# RedTeam Agent — Architecture

## Overview

A defensive security scanner that runs SAST-lite (npm audit + secret detection) and optional DAST-lite (HTTP scan) against a repository, normalizes findings into a common schema, deduplicates them, and files/updates GitHub Issues.

---

## Directory Layout

```
redteam-agent/
├── src/
│   ├── index.ts                  # CLI entrypoint
│   ├── config.ts                 # Config loader + validation
│   ├── types.ts                  # All shared TypeScript interfaces
│   ├── scanners/
│   │   ├── scanner.ts            # Scanner interface
│   │   ├── npm-audit.ts          # npm audit wrapper
│   │   ├── secret-detection.ts   # Regex-based secret finder
│   │   └── http-scan.ts          # DAST-lite HTTP scanner
│   ├── normalizer.ts             # Raw scanner output → Finding[]
│   ├── dedup.ts                  # Deduplicate by fingerprint
│   ├── github/
│   │   ├── issues.ts             # Create/update GitHub Issues
│   │   └── labels.ts             # Ensure labels exist
│   └── utils/
│       ├── fingerprint.ts        # SHA-256 fingerprint generator
│       └── logger.ts             # Minimal structured logger
├── .github/
│   └── workflows/
│       └── redteam.yml           # GitHub Actions workflow
├── redteam.config.json           # Default config file
├── package.json
├── tsconfig.json
└── README.md
```

---

## TypeScript Interfaces (`src/types.ts`)

```typescript
// ─── Severity & Confidence ───────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "high" | "medium" | "low";
export type Category = "dependency" | "secret" | "http";

// ─── Core Finding Schema ─────────────────────────────────────────────

export interface Finding {
  /** Deterministic ID: SHA-256 of fingerprint fields */
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  /** Which scanner produced this */
  tool: "npm-audit" | "secret-detection" | "http-scan";
  category: Category;
  /** Where in the repo or URL the issue was found */
  location: Location;
  /** Raw evidence string (truncated to 1 KB) */
  evidence: string;
  /** Human-readable fix suggestion */
  remediation: string;
  /** Advisory URLs, CVE links, etc. */
  references: string[];
  /** Stable dedup key: hash of (tool + category + location.path + title) */
  fingerprint: string;
}

export interface Location {
  /** File path relative to repo root, or URL for DAST */
  path: string;
  /** Start line (1-based), undefined for DAST / dependency findings */
  startLine?: number;
  /** End line (1-based) */
  endLine?: number;
}

// ─── Scanner Interface ───────────────────────────────────────────────

/** Raw output from a scanner before normalization */
export interface RawFinding {
  /** Scanner-specific identifier (e.g. GHSA ID, regex pattern name) */
  rawId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  tool: Finding["tool"];
  category: Category;
  location: Location;
  evidence: string;
  remediation: string;
  references: string[];
}

export interface Scanner {
  /** Human-readable name */
  name: string;
  /** Returns true if this scanner can run in the current environment */
  isAvailable(config: RedTeamConfig): boolean;
  /** Execute the scan and return raw findings */
  scan(config: RedTeamConfig): Promise<RawFinding[]>;
}

// ─── Configuration ───────────────────────────────────────────────────

export interface RedTeamConfig {
  /** Path to the repository root to scan (default: ".") */
  repoRoot: string;

  /** GitHub owner/repo (e.g. "octocat/hello-world"). Auto-detected in Actions. */
  github: {
    owner: string;
    repo: string;
    /** GITHUB_TOKEN — read from env, never stored in config file */
    token: string;
  };

  scanners: {
    npmAudit: {
      enabled: boolean;
      /** Minimum severity to report */
      minSeverity: Severity;
    };
    secretDetection: {
      enabled: boolean;
      /** Glob patterns to scan (default: ["**/*"]) */
      include: string[];
      /** Glob patterns to skip (default: ["node_modules/**", ".git/**"]) */
      exclude: string[];
      /** Extra regex patterns beyond built-ins: { name: regexString } */
      customPatterns: Record<string, string>;
    };
    httpScan: {
      enabled: boolean;
      /** Base URL to scan (must be localhost/127.0.0.1) */
      target: string;
      /** Paths to probe */
      paths: string[];
    };
  };

  /** Issue creation settings */
  issues: {
    /** Create issues? If false, just output JSON. */
    enabled: boolean;
    /** Labels to apply beyond severity label */
    extraLabels: string[];
    /** Max issues to create per run (prevents spam) */
    maxPerRun: number;
    /** Assign issues to these GitHub usernames */
    assignees: string[];
  };
}

// ─── Dedup Result ────────────────────────────────────────────────────

export interface DedupResult {
  /** New findings that need issues created */
  newFindings: Finding[];
  /** Existing findings whose issues should be updated */
  existingFindings: Array<{ finding: Finding; issueNumber: number }>;
  /** Total findings before dedup */
  totalRaw: number;
}

// ─── Issue Output ────────────────────────────────────────────────────

export interface IssueResult {
  issueNumber: number;
  issueUrl: string;
  action: "created" | "updated" | "skipped";
  finding: Finding;
}
```

---

## Module Interfaces

### Scanner (`src/scanners/scanner.ts`)

```typescript
import { Scanner } from "../types";

// Re-export the interface; each scanner file exports a default instance.
export type { Scanner };
```

### npm-audit scanner (`src/scanners/npm-audit.ts`)

```typescript
import { Scanner, RawFinding, RedTeamConfig, Severity } from "../types";
import { execFile } from "node:child_process";

const SEVERITY_MAP: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
  info: "low",
};

export const npmAuditScanner: Scanner = {
  name: "npm-audit",

  isAvailable(config: RedTeamConfig): boolean {
    return config.scanners.npmAudit.enabled;
  },

  async scan(config: RedTeamConfig): Promise<RawFinding[]> {
    // Runs: npm audit --json in config.repoRoot
    // Parses JSON output → maps advisories to RawFinding[]
    // Filters by minSeverity
  },
};
```

### Secret Detection (`src/scanners/secret-detection.ts`)

```typescript
import { Scanner, RawFinding, RedTeamConfig } from "../types";

/** Built-in patterns */
const BUILTIN_PATTERNS: Record<string, RegExp> = {
  "aws-access-key":    /AKIA[0-9A-Z]{16}/g,
  "aws-secret-key":    /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
  "github-token":      /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
  "generic-api-key":   /(?:api[_-]?key|apikey|secret)["\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi,
  "private-key":       /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
  "generic-password":  /(?:password|passwd|pwd)["\s:=]+["']([^"'\s]{8,})["']/gi,
};

export const secretDetectionScanner: Scanner = {
  name: "secret-detection",

  isAvailable(config: RedTeamConfig): boolean {
    return config.scanners.secretDetection.enabled;
  },

  async scan(config: RedTeamConfig): Promise<RawFinding[]> {
    // 1. Glob files matching include/exclude
    // 2. Read each file, test all patterns (builtin + custom)
    // 3. On match → emit RawFinding with file path + line number
  },
};
```

### HTTP Scan (`src/scanners/http-scan.ts`)

```typescript
import { Scanner, RawFinding, RedTeamConfig } from "../types";

export const httpScanScanner: Scanner = {
  name: "http-scan",

  isAvailable(config: RedTeamConfig): boolean {
    if (!config.scanners.httpScan.enabled) return false;
    const url = new URL(config.scanners.httpScan.target);
    // SAFETY: only allow localhost targets
    return ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  },

  async scan(config: RedTeamConfig): Promise<RawFinding[]> {
    // For each path in config.scanners.httpScan.paths:
    //   1. Check security headers (X-Frame-Options, CSP, etc.)
    //   2. Check for directory listing
    //   3. Check for exposed sensitive paths (/env, /.git, /debug)
    // Emit RawFinding for each issue found
  },
};
```

---

## Data Flow

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  npm-audit   │   │   secret     │   │  http-scan   │
│  scanner     │   │  detection   │   │  (optional)  │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       │ RawFinding[]     │ RawFinding[]     │ RawFinding[]
       └──────────────────┼──────────────────┘
                          ▼
                 ┌────────────────┐
                 │  normalizer.ts │  RawFinding → Finding
                 │  (+ fingerprint│  (adds deterministic id
                 │    generation) │   and fingerprint hash)
                 └────────┬───────┘
                          │ Finding[]
                          ▼
                 ┌────────────────┐
                 │   dedup.ts     │  Fetches open issues with
                 │                │  "security" label, matches
                 │                │  fingerprint in issue body
                 └────────┬───────┘
                          │ DedupResult
                          ▼
                 ┌────────────────┐
                 │  issues.ts     │  Creates new issues,
                 │  + labels.ts   │  updates existing ones,
                 │                │  applies severity labels
                 └────────┬───────┘
                          │ IssueResult[]
                          ▼
                   CLI output / JSON
```

### Step-by-step (`src/index.ts`)

```typescript
import { loadConfig } from "./config";
import { npmAuditScanner } from "./scanners/npm-audit";
import { secretDetectionScanner } from "./scanners/secret-detection";
import { httpScanScanner } from "./scanners/http-scan";
import { normalize } from "./normalizer";
import { deduplicate } from "./dedup";
import { processIssues } from "./github/issues";
import { ensureLabels } from "./github/labels";
import { Scanner, Finding, IssueResult } from "./types";

async function main(): Promise<void> {
  const config = loadConfig();

  // 1. Run scanners
  const scanners: Scanner[] = [
    npmAuditScanner,
    secretDetectionScanner,
    httpScanScanner,
  ];

  const allRaw = [];
  for (const scanner of scanners) {
    if (scanner.isAvailable(config)) {
      const findings = await scanner.scan(config);
      allRaw.push(...findings);
    }
  }

  // 2. Normalize → Finding[] with fingerprints
  const findings: Finding[] = normalize(allRaw);

  // 3. Deduplicate against existing GitHub Issues
  const dedup = await deduplicate(findings, config);

  // 4. Create/update issues
  if (config.issues.enabled) {
    await ensureLabels(config);
    const results: IssueResult[] = await processIssues(dedup, config);
    console.log(JSON.stringify(results, null, 2));
  } else {
    console.log(JSON.stringify(findings, null, 2));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

---

## Normalizer (`src/normalizer.ts`)

```typescript
import { RawFinding, Finding } from "./types";
import { generateFingerprint, generateId } from "./utils/fingerprint";

export function normalize(raw: RawFinding[]): Finding[] {
  return raw.map((r) => {
    const fingerprint = generateFingerprint(r.tool, r.category, r.location.path, r.title);
    const id = generateId(fingerprint);
    return {
      ...r,
      id,
      fingerprint,
      evidence: r.evidence.slice(0, 1024), // Truncate to 1024 characters
    };
  });
}
```

## Fingerprint Utility (`src/utils/fingerprint.ts`)

```typescript
import { createHash } from "node:crypto";

/** Deterministic fingerprint: hash of stable fields */
export function generateFingerprint(...fields: string[]): string {
  return createHash("sha256").update(fields.join("|")).digest("hex");
}

/** Short ID derived from fingerprint */
export function generateId(fingerprint: string): string {
  return fingerprint.slice(0, 12);
}
```

## Deduplicator (`src/dedup.ts`)

```typescript
import { Finding, DedupResult, RedTeamConfig } from "./types";

/**
 * Fetches all open issues with label "security",
 * extracts fingerprint from issue body (stored as HTML comment),
 * and partitions findings into new vs. existing.
 */
export async function deduplicate(
  findings: Finding[],
  config: RedTeamConfig,
): Promise<DedupResult> {
  // 1. GET /repos/{owner}/{repo}/issues?labels=security&state=open
  // 2. For each issue, extract: <!-- fingerprint:abc123 -->
  // 3. Build Map<fingerprint, issueNumber>
  // 4. Partition findings into new vs. existing
}
```

## GitHub Issues (`src/github/issues.ts`)

Issue body template (the `<!-- fingerprint:... -->` comment enables dedup):

```markdown
<!-- fingerprint:${finding.fingerprint} -->

## ${finding.title}

| Field | Value |
|-------|-------|
| **Severity** | ${finding.severity} |
| **Confidence** | ${finding.confidence} |
| **Tool** | ${finding.tool} |
| **Category** | ${finding.category} |
| **Location** | \`${finding.location.path}:${finding.location.startLine ?? '-'}\` |

### Evidence

\`\`\`
${finding.evidence}
\`\`\`

### Remediation

${finding.remediation}

### References

${finding.references.map(r => `- ${r}`).join('\n')}

---
*Filed by RedTeam Agent • Finding ID: \`${finding.id}\`*
```

## Labels (`src/github/labels.ts`)

```typescript
import { RedTeamConfig } from "../types";

const REQUIRED_LABELS = [
  { name: "security",          color: "d73a4a", description: "Security finding" },
  { name: "severity:critical", color: "b60205", description: "Critical severity" },
  { name: "severity:high",     color: "d93f0b", description: "High severity" },
  { name: "severity:medium",   color: "fbca04", description: "Medium severity" },
  { name: "severity:low",      color: "0e8a16", description: "Low severity" },
];

/**
 * Ensures all required labels exist in the repo.
 * Uses GET then POST (idempotent).
 */
export async function ensureLabels(config: RedTeamConfig): Promise<void> {
  // For each label: try GET /repos/{owner}/{repo}/labels/{name}
  // If 404 → POST /repos/{owner}/{repo}/labels
}
```

---

## Config File (`redteam.config.json`)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "repoRoot": ".",
  "github": {
    "owner": "",
    "repo": ""
  },
  "scanners": {
    "npmAudit": {
      "enabled": true,
      "minSeverity": "medium"
    },
    "secretDetection": {
      "enabled": true,
      "include": ["**/*"],
      "exclude": [
        "node_modules/**",
        ".git/**",
        "*.lock",
        "dist/**",
        "*.png",
        "*.jpg",
        "*.gif",
        "*.woff",
        "*.woff2"
      ],
      "customPatterns": {}
    },
    "httpScan": {
      "enabled": false,
      "target": "http://localhost:3000",
      "paths": ["/", "/.env", "/.git/config", "/debug", "/api"]
    }
  },
  "issues": {
    "enabled": true,
    "extraLabels": [],
    "maxPerRun": 10,
    "assignees": []
  }
}
```

### Config Resolution Order

1. `redteam.config.json` in repo root (file defaults)
2. Environment variables override specifics:
   - `GITHUB_REPOSITORY` → splits into `github.owner` + `github.repo`
   - `GITHUB_TOKEN` → `github.token`
   - `REDTEAM_REPO_ROOT` → `repoRoot`
3. CLI flags override everything:
   - `--config <path>` — alternate config file
   - `--no-issues` — disable issue creation (local dry-run)
   - `--json` — output findings as JSON to stdout

```typescript
// src/config.ts
import { RedTeamConfig } from "./types";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_CONFIG_PATH = "redteam.config.json";

export function loadConfig(overridePath?: string): RedTeamConfig {
  const configPath = resolve(overridePath ?? DEFAULT_CONFIG_PATH);
  const fileConfig = existsSync(configPath)
    ? JSON.parse(readFileSync(configPath, "utf-8"))
    : {};

  // Merge: defaults ← file ← env ← CLI args
  const [owner, repo] = (process.env.GITHUB_REPOSITORY ?? "/").split("/");

  return {
    repoRoot: process.env.REDTEAM_REPO_ROOT ?? fileConfig.repoRoot ?? ".",
    github: {
      owner: fileConfig.github?.owner || owner,
      repo: fileConfig.github?.repo || repo,
      token: process.env.GITHUB_TOKEN ?? "",
    },
    scanners: { /* deep merge defaults + file */ },
    issues: { /* deep merge defaults + file */ },
  } as RedTeamConfig;
}
```

---

## GitHub Actions Workflow (`.github/workflows/redteam.yml`)

```yaml
name: RedTeam Security Scan

on:
  schedule:
    - cron: "0 6 * * 1"       # Weekly Monday 6 AM UTC
  push:
    branches: [main]
  workflow_dispatch:            # Manual trigger

permissions:
  issues: write                 # Create/update issues
  contents: read                # Read repo for scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install RedTeam Agent
        run: |
          cd redteam-agent
          npm ci

      - name: Run Security Scan
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          cd redteam-agent
          npx tsx src/index.ts
```

---

## `package.json`

```json
{
  "name": "redteam-agent",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "scan": "tsx src/index.ts",
    "scan:dry": "tsx src/index.ts --no-issues --json",
    "build": "tsc",
    "lint": "eslint src/"
  },
  "dependencies": {
    "glob": "^10.0.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "tsx": "^4.0.0",
    "typescript": "^5.4.0"
  }
}
```

**Key design decision**: No runtime dependencies beyond `glob` for file matching. The GitHub API is called via `node:https` (native) to keep the dependency surface minimal — fitting for a security tool.

---

## `tsconfig.json`

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "Node16",
    "moduleResolution": "Node16",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "declaration": true,
    "sourceMap": true
  },
  "include": ["src"]
}
```

---

## Security Design Notes

1. **No secrets in config**: `GITHUB_TOKEN` is read only from `process.env`, never from `redteam.config.json`.
2. **DAST safety**: HTTP scanner validates target is `localhost/127.0.0.1/::1` before running. Rejects all external targets.
3. **Evidence truncation**: All evidence strings are capped at 1024 characters to prevent leaking large secrets into issue bodies.
4. **Secret masking**: When filing issues for secret findings, the evidence field shows the pattern name and masked value (first 4 + last 4 chars), never the full secret.
5. **Rate limiting**: `maxPerRun` caps issue creation to prevent accidental spam.
6. **Fingerprint stability**: Fingerprint is `SHA-256(tool|category|path|title)` — survives line-number shifts, evidence changes, and re-runs without creating duplicate issues.
