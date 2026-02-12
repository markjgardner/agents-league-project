import type { Scanner, RawFinding, RedTeamConfig, Severity } from "../types.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { logger } from "../utils/logger.js";

const execFileAsync = promisify(execFile);

const SEVERITY_MAP: Record<string, Severity> = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
  info: "low",
};

/** npm audit JSON shape (v7+) */
interface NpmAuditOutput {
  vulnerabilities?: Record<
    string,
    {
      name: string;
      severity: string;
      via: Array<
        | { title?: string; url?: string; source?: number }
        | string
      >;
      fixAvailable: boolean | { name: string; version: string };
    }
  >;
}

export const npmAuditScanner: Scanner = {
  name: "npm-audit",

  isAvailable(config: RedTeamConfig): boolean {
    return config.scanners.npmAudit.enabled;
  },

  async scan(config: RedTeamConfig): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    let stdout = "";

    try {
      const result = await execFileAsync("npm", ["audit", "--json"], {
        cwd: config.repoRoot,
        maxBuffer: 10 * 1024 * 1024,
      });
      stdout = result.stdout;
    } catch (err: unknown) {
      // npm audit exits non-zero when vulnerabilities exist; capture stdout
      if (isExecError(err) && err.stdout) {
        stdout = err.stdout;
      } else {
        logger.error("npm audit failed", {
          error: err instanceof Error ? err.message : String(err),
        });
        return findings;
      }
    }

    let audit: NpmAuditOutput;
    try {
      audit = JSON.parse(stdout) as NpmAuditOutput;
    } catch {
      logger.error("Failed to parse npm audit JSON output");
      return findings;
    }

    const minOrder = SEVERITY_ORDER[config.scanners.npmAudit.minSeverity];

    for (const [name, vuln] of Object.entries(audit.vulnerabilities ?? {})) {
      const severity = SEVERITY_MAP[vuln.severity] ?? "low";
      if (SEVERITY_ORDER[severity] < minOrder) continue;

      // via can contain strings (transitive dep names) or advisory objects
      const advisory = vuln.via.find(
        (v): v is { title?: string; url?: string; source?: number } =>
          typeof v === "object" && typeof v.title === "string",
      );
      const title = advisory?.title ?? `Vulnerability in ${name}`;
      const url = advisory?.url ?? "";

      findings.push({
        rawId: `npm-${name}-${advisory?.source ?? 0}`,
        title,
        severity,
        confidence: "high",
        tool: "npm-audit",
        category: "dependency",
        location: { path: `package.json (${name})` },
        evidence: `Package: ${name}, Severity: ${vuln.severity}`,
        remediation:
          typeof vuln.fixAvailable === "object"
            ? `Update to ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`
            : "Run npm audit fix or update manually",
        references: url ? [url] : [],
      });
    }

    return findings;
  },
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Type guard for child_process exec errors that include stdout/stderr */
function isExecError(err: unknown): err is Error & { stdout: string; stderr: string } {
  return err instanceof Error && "stdout" in err;
}
