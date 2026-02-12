# RedTeam Agent 🛡️

A defensive security scanner that scans your repository for vulnerabilities and automatically files GitHub Issues with actionable writeups.

**Defensive use only** — scans only targets you explicitly configure (your own repo code, localhost test environments). Never scans arbitrary external hosts.

## Features

- **Dependency Scanning** — Runs `npm audit` and reports known vulnerabilities in your dependencies
- **Secret Detection** — Regex-based scanning for leaked credentials (AWS keys, GitHub tokens, API keys, private keys, passwords)
- **HTTP Scanning (optional)** — Probes localhost endpoints for missing security headers and exposed sensitive paths
- **GitHub Issue Integration** — Automatically creates, deduplicates, and (optionally) auto-closes issues
- **Fingerprint-based Dedup** — Stable SHA-256 fingerprints prevent duplicate issues across runs
- **Severity Labels** — Issues are labeled with `severity:critical`, `severity:high`, `severity:medium`, or `severity:low`
- **CI/CD Ready** — GitHub Actions workflow for scheduled and push-triggered scans

## Quick Start

### Local Usage

```bash
# 1. Install dependencies
npm install

# 2. Copy .env.example and set your GitHub token
cp .env.example .env
# Edit .env and add your GITHUB_TOKEN

# 3. Configure scanning (optional — defaults work for most repos)
# Edit redteam.config.json to customize

# 4. Run a dry-run scan (no issues created, JSON output)
npm run scan:dry

# 5. Run a full scan (creates GitHub issues)
npm run scan
```

### GitHub Actions (CI)

The included workflow (`.github/workflows/redteam.yml`) runs automatically:
- **Weekly** — Every Monday at 6 AM UTC
- **On push** — To the `main` branch
- **Manual** — Via `workflow_dispatch`

No configuration needed — it uses the built-in `GITHUB_TOKEN` and auto-detects `owner/repo`.

## Configuration

### `redteam.config.json`

```json
{
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
      "exclude": ["node_modules/**", ".git/**", "*.lock", "dist/**"],
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
    "assignees": [],
    "autoClose": false
  },
  "persona": "default"
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GITHUB_TOKEN` | GitHub token for issue creation | _(required for issue creation)_ |
| `GITHUB_REPOSITORY` | `owner/repo` format (auto-set in Actions) | _(auto-detected)_ |
| `REDTEAM_REPO_ROOT` | Path to repo to scan | `.` |
| `DEMO_ISSUE_LABEL` | Label to apply in demo mode (e.g. `demo:redteam-example`) | _(none)_ |
| `REDTEAM_PERSONA` | Issue writing style: `default` or `chuck_norris` | `default` |
| `LOG_LEVEL` | Logging verbosity: `debug`, `info`, `warn`, `error` | `info` |

### CLI Flags

```bash
node dist/index.js [options]

Options:
  --no-issues    Skip issue creation (scan only)
  --json         Output results as JSON
  --config PATH  Path to config file (default: redteam.config.json)
  --demo         Apply demo:redteam-example label to all created issues
```

## Finding Schema

All scanner output is normalized to this common schema:

```typescript
interface Finding {
  id: string;           // Short ID (first 12 hex chars of fingerprint)
  title: string;        // Human-readable title
  severity: "critical" | "high" | "medium" | "low";
  confidence: "high" | "medium" | "low";
  tool: "npm-audit" | "secret-detection" | "http-scan";
  category: "dependency" | "secret" | "http";
  location: {
    path: string;       // File path or URL
    startLine?: number; // Line number (1-based)
    endLine?: number;
  };
  evidence: string;     // Truncated to 1 KB; secrets are masked
  remediation: string;  // Actionable fix suggestion
  references: string[]; // CVE/advisory URLs
  fingerprint: string;  // SHA-256 dedup key
}
```

## Scanners

### npm audit (Dependency Scanner)

Runs `npm audit --json` and parses vulnerabilities. Filters by `minSeverity` setting.

### Secret Detection

Scans all text files for common secret patterns:

| Pattern | Example | Severity |
|---------|---------|----------|
| AWS Access Key | `AKIA...` | Critical |
| AWS Secret Key | `aws_secret_access_key=...` | Critical |
| GitHub Token | `ghp_...`, `gho_...`, `ghs_...` | Critical |
| Generic API Key | `api_key=...` | High |
| Private Key | `-----BEGIN RSA PRIVATE KEY-----` | Critical |
| Generic Password | `password='...'` | High |

Secrets are **always masked** in findings and issue bodies (first 4 + last 4 chars shown).

### HTTP Scan (DAST-lite)

⚠️ **Localhost only** — will refuse to scan any non-localhost target.

Checks for:
- Missing security headers (X-Frame-Options, CSP, HSTS, etc.)
- Exposed sensitive paths (/.env, /.git/config, /debug, /actuator)

## Issue Deduplication

Issues are deduplicated using a fingerprint-based strategy:

1. Each finding gets a **stable fingerprint** = `SHA-256(tool | category | location | title)`
2. The fingerprint is embedded as an HTML comment in the issue body: `<!-- redteam-fingerprint:abc123... -->`
3. On subsequent runs, existing open issues are matched by fingerprint
4. New findings get new issues; existing findings are skipped
5. If `autoClose` is enabled, issues whose findings disappear are auto-closed

## 🎬 Chuck Norris Mode (Optional)

A high-confidence, no-nonsense persona for GitHub issue writeups. Designed for demos, presentations, and engagement — Chuck Norris mode adds cinematic attitude to your security findings.

**Why it exists:** Fun, demos, and making security findings impossible to ignore.

**How to enable it:**

```bash
# Via environment variable
export REDTEAM_PERSONA=chuck_norris

# Or in redteam.config.json
{ "persona": "chuck_norris" }
```

**What changes:**
- Issue titles, opening paragraphs, section headers, and closing lines adopt a confident, declarative tone
- Tone scales with severity (playful for LOW, urgent for CRITICAL)

**What does NOT change:**
- Scan results, severity values, fingerprints, and evidence remain identical
- No insults, profanity, or disrespect toward individuals — the attitude targets the vulnerability, not the developer

## 🧠 LLM Attack Planner (Optional)

An **optional** AI-powered stage that uses a large language model to review your codebase and generate structured security test hypotheses. This is **defensive use only** — no exploitation, no external targeting.

### What It Does

1. **Reads** your repo structure and security-relevant source files (routes, controllers, auth, config, database)
2. **Generates** structured `AttackHypothesis` objects: what might be vulnerable, why, and how to safely verify
3. **Validates** each hypothesis using deterministic static checks (regex/AST patterns, config inspection)
4. **Creates issues** only when evidence is confirmed — no speculation, no false alarms

### Safety Guardrails

| Guardrail | Enforcement |
|-----------|-------------|
| **Disabled by default** | Requires `REDTEAM_LLM_ENABLED=true` explicitly |
| **No external targets** | Dynamic probes only run against `REDTEAM_TARGET_ALLOWLIST` (default: localhost) |
| **No exploit payloads** | LLM system prompt prohibits weaponized output |
| **Output validation** | All LLM responses are validated against a strict JSON schema |
| **Evidence required** | No evidence → no issue created (deterministic confirmation) |
| **Rate limited** | Max hypotheses per run, max files analyzed, request timeouts |
| **CI safety** | Only runs via `workflow_dispatch` with explicit opt-in and secrets present |

### How to Enable Locally

```bash
# 1. Set your LLM API key
export REDTEAM_LLM_KEY="sk-..."

# 2. Enable the planner
export REDTEAM_LLM_ENABLED=true

# 3. (Optional) Set model and endpoint
export REDTEAM_LLM_MODEL=gpt-4o-mini
export REDTEAM_LLM_ENDPOINT=https://api.openai.com/v1

# 4. Run a dry-run scan
npm run scan:dry
```

### How to Run in CI

The LLM planner only runs in CI when **all** of these conditions are met:
1. Triggered via `workflow_dispatch` (manual trigger)
2. `enable_llm_planner` input is set to `"true"`
3. `REDTEAM_LLM_KEY` secret is configured in the repository

This prevents accidental LLM usage on push or schedule triggers.

### Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `REDTEAM_LLM_ENABLED` | Enable/disable the LLM planner | `false` |
| `REDTEAM_LLM_MODEL` | LLM model name | `gpt-4o-mini` |
| `REDTEAM_LLM_ENDPOINT` | API endpoint URL | OpenAI default |
| `REDTEAM_LLM_KEY` | API key (env var only, never in config) | _(none)_ |
| `REDTEAM_LLM_MAX_FILES` | Max files to analyze | `20` |
| `REDTEAM_LLM_MAX_TOKENS` | Max response tokens | `4096` |
| `REDTEAM_TARGET_ALLOWLIST` | Allowed hostnames for dynamic probes | `localhost,127.0.0.1,::1` |

### AttackHypothesis Schema

```typescript
interface AttackHypothesis {
  id: string;                   // e.g., "HYPO-001"
  title: string;                // Short descriptive title
  category: string;             // e.g., "injection", "auth-bypass"
  risk: "critical" | "high" | "medium" | "low";
  confidence: "high" | "medium" | "low";
  rationale: string;            // Why the code suggests this
  evidence_to_collect: string;  // What would prove it
  safe_test_plan: string;       // Non-destructive verification steps
  likely_locations: string[];   // Files/functions/routes
  references: string[];         // OWASP/CWE IDs
}
```

### Issue Quality

Issues created from LLM hypotheses include:
- Hypothesis summary and category
- Code-grounded rationale (specific files/functions)
- Evidence collected by deterministic tooling
- Safe reproduction steps for demo environments
- Remediation guidance with OWASP/CWE references
- Labels: `security`, `severity:<level>`, `category:<type>`, `tool:llm-planner`

## Development

```bash
# Install dependencies
npm install

# Type-check
npx tsc --noEmit

# Run tests
npm test

# Build
npm run build
```

## Example App + Demo Workflow

The `example/` directory contains an **intentionally vulnerable** demo app
that exercises all scanners (secret detection + HTTP scan). Issues created
during demo runs are tagged with the label **`demo:redteam-example`** so
they can be bulk-identified and cleaned up.

### Run the demo locally

```bash
# Scan secrets only (no server needed)
REDTEAM_REPO_ROOT=example npx tsx src/index.ts --demo --no-issues --json

# Full scan with HTTP server
node example/server.cjs &
npx tsx src/index.ts --demo --no-issues --json --config example/redteam.example.json
kill %1
```

### Run the demo in CI

Trigger the **RedTeam Example Demo** workflow manually from the Actions tab
(`workflow_dispatch`). It will create issues labeled `demo:redteam-example`.

### Clean up demo issues

To close all demo issues, re-run the workflow with the **cleanup** input
set to `true`, or use the GitHub CLI:

```bash
gh issue list --label "demo:redteam-example" --state open --json number \
  | jq -r '.[].number' \
  | xargs -I{} gh issue close {} --reason "not planned"
```

## License

MIT
