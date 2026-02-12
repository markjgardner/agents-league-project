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
| `REDTEAM_PERSONA` | Issue writing style: `default` or `chuck_norris` | `default` |
| `LOG_LEVEL` | Logging verbosity: `debug`, `info`, `warn`, `error` | `info` |

### CLI Flags

```bash
node dist/index.js [options]

Options:
  --no-issues    Skip issue creation (scan only)
  --json         Output results as JSON
  --config PATH  Path to config file (default: redteam.config.json)
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

## License

MIT
