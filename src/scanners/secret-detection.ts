import type { Scanner, RawFinding, RedTeamConfig } from "../types.js";
import { readFileSync } from "node:fs";
import { glob } from "glob";
import { resolve, relative } from "node:path";

/** Built-in secret detection patterns */
const BUILTIN_PATTERNS: Record<string, RegExp> = {
  "aws-access-key": /AKIA[0-9A-Z]{16}/g,
  "github-token": /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
  "generic-api-key":
    /(?:api[_-]?key|apikey|secret)["'\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi,
  "private-key": /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
  "generic-password":
    /(?:password|passwd|pwd)["'\s:=]+["']([^"'\s]{8,})["']/gi,
};

export const secretDetectionScanner: Scanner = {
  name: "secret-detection",

  isAvailable(config: RedTeamConfig): boolean {
    return config.scanners.secretDetection.enabled;
  },

  async scan(config: RedTeamConfig): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const scanConfig = config.scanners.secretDetection;

    const files = await glob(scanConfig.include, {
      cwd: resolve(config.repoRoot),
      ignore: scanConfig.exclude,
      nodir: true,
      absolute: true,
    });

    // Combine builtin + custom patterns
    const patterns: Record<string, RegExp> = { ...BUILTIN_PATTERNS };
    for (const [name, pattern] of Object.entries(scanConfig.customPatterns)) {
      patterns[name] = new RegExp(pattern, "g");
    }

    for (const file of files) {
      let content: string;
      try {
        content = readFileSync(file, "utf-8");
      } catch {
        continue; // Skip binary or unreadable files
      }

      const lines = content.split("\n");
      const relPath = relative(resolve(config.repoRoot), file);

      for (const [patternName, regex] of Object.entries(patterns)) {
        for (let i = 0; i < lines.length; i++) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(lines[i])) !== null) {
            findings.push({
              rawId: `secret-${patternName}-${relPath}-${i + 1}-${match.index}`,
              title: `Potential secret detected: ${patternName}`,
              severity: "high",
              confidence: "medium",
              tool: "secret-detection",
              category: "secret",
              location: { path: relPath, startLine: i + 1, endLine: i + 1 },
              evidence: match[0].slice(0, 1024),
              remediation:
                "Remove the secret from source code and rotate the credential. " +
                "Use environment variables or a secrets manager instead.",
              references: [],
            });
          }
        }
      }
    }

    return findings;
  },
};
