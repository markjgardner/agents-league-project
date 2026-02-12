import type { Scanner, RawFinding, RedTeamConfig, Severity } from "../types.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

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
    const findings: RawFinding[] = [];
    try {
      const { stdout } = await execFileAsync("npm", ["audit", "--json"], {
        cwd: config.repoRoot,
      });
      const audit = JSON.parse(stdout) as {
        vulnerabilities?: Record<
          string,
          {
            name: string;
            severity: string;
            via: Array<{
              title?: string;
              url?: string;
              source?: number;
            }>;
            fixAvailable: boolean | { name: string; version: string };
          }
        >;
      };

      const minOrder = SEVERITY_ORDER[config.scanners.npmAudit.minSeverity];
      for (const [name, vuln] of Object.entries(audit.vulnerabilities ?? {})) {
        const severity = SEVERITY_MAP[vuln.severity] ?? "low";
        if (SEVERITY_ORDER[severity] > minOrder) continue;

        const advisory = vuln.via.find((v) => typeof v.title === "string");
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
    } catch {
      // npm audit exits non-zero when vulnerabilities exist; parse stdout anyway
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
