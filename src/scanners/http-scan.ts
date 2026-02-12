import type { Scanner, RawFinding, RedTeamConfig } from "../types.js";

const SECURITY_HEADERS = [
  "x-frame-options",
  "x-content-type-options",
  "strict-transport-security",
  "content-security-policy",
  "x-xss-protection",
];

const SENSITIVE_PATHS = ["/.env", "/.git/config", "/debug", "/actuator"];

export const httpScanScanner: Scanner = {
  name: "http-scan",

  isAvailable(config: RedTeamConfig): boolean {
    if (!config.scanners.httpScan.enabled) return false;
    try {
      const url = new URL(config.scanners.httpScan.target);
      return ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
    } catch {
      return false;
    }
  },

  async scan(config: RedTeamConfig): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const { target, paths } = config.scanners.httpScan;

    for (const path of paths) {
      const url = `${target.replace(/\/$/, "")}${path}`;
      try {
        const response = await fetch(url, {
          redirect: "manual",
          signal: AbortSignal.timeout(5000),
        });

        // Check for missing security headers on successful responses
        if (response.ok) {
          for (const header of SECURITY_HEADERS) {
            if (!response.headers.has(header)) {
              findings.push({
                rawId: `http-header-${header}-${path}`,
                title: `Missing security header: ${header}`,
                severity: "medium",
                confidence: "high",
                tool: "http-scan",
                category: "http",
                location: { path: url },
                evidence: `Response to ${path} is missing the ${header} header`,
                remediation: `Add the ${header} header to your server responses.`,
                references: [
                  "https://owasp.org/www-project-secure-headers/",
                ],
              });
            }
          }

          // Check for exposed sensitive paths
          if (SENSITIVE_PATHS.includes(path)) {
            findings.push({
              rawId: `http-exposed-${path}`,
              title: `Sensitive path exposed: ${path}`,
              severity: "high",
              confidence: "high",
              tool: "http-scan",
              category: "http",
              location: { path: url },
              evidence: `${path} returned HTTP ${response.status}`,
              remediation: `Block access to ${path} in your web server configuration.`,
              references: [],
            });
          }
        }
      } catch {
        // Connection refused or timeout — path not reachable, skip
      }
    }

    return findings;
  },
};
