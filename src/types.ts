// ─── Severity & Confidence ───────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low";
export type Confidence = "high" | "medium" | "low";
export type Category = "dependency" | "secret" | "http";
export type PersonaName = "default" | "chuck_norris";

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
      /** Glob patterns to scan (default: all files) */
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
    /** Close issues whose findings are no longer present */
    autoClose: boolean;
  };

  /** Persona for issue writing style: "default" | "chuck_norris" */
  persona: PersonaName;
}

// ─── Dedup Result ────────────────────────────────────────────────────

export interface DedupResult {
  /** New findings that need issues created */
  newFindings: Finding[];
  /** Existing findings whose issues should be updated */
  existingFindings: Array<{ finding: Finding; issueNumber: number }>;
  /** Fingerprints of open issues that no longer have matching findings */
  resolvedIssueNumbers: number[];
  /** Total findings before dedup */
  totalRaw: number;
}

// ─── Issue Output ────────────────────────────────────────────────────

export interface IssueResult {
  issueNumber: number;
  issueUrl: string;
  action: "created" | "updated" | "skipped" | "closed";
  finding?: Finding;
}
