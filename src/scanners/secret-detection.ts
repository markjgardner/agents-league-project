import type { Scanner, RawFinding, RedTeamConfig, Severity } from "../types.js";
import { readFileSync } from "node:fs";
import { glob } from "glob";
import { resolve, relative } from "node:path";
import { logger } from "../utils/logger.js";

/** Severity mapping for each built-in pattern */
const PATTERN_SEVERITY: Record<string, Severity> = {
  "aws-access-key": "critical",
  "aws-secret-key": "critical",
  "github-token": "critical",
  "generic-api-key": "high",
  "private-key": "critical",
  "generic-password": "high",
};

/** Built-in secret detection patterns */
const BUILTIN_PATTERNS: Record<string, RegExp> = {
  "aws-access-key": /AKIA[0-9A-Z]{16}/g,
  "aws-secret-key":
    /(?:aws_secret_access_key|aws_secret_key)[\s]*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
  "github-token": /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
  "generic-api-key":
    /(?:api[_-]?key|apikey|api[_-]?secret)["'\s:=]+["']?([A-Za-z0-9_\-]{20,})["']?/gi,
  "private-key": /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
  "generic-password":
    /(?:password|passwd|pwd)["'\s:=]+["']([^"'\s]{8,})["']/gi,
};

/** File extensions that are definitely binary and should be skipped */
const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
  ".woff", ".woff2", ".ttf", ".eot", ".otf",
  ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx",
  ".exe", ".dll", ".so", ".dylib", ".o",
  ".mp3", ".mp4", ".avi", ".mov", ".webm",
  ".wasm", ".pyc", ".class",
]);

/** Returns true if the buffer looks like it contains binary data */
function isBinaryContent(buf: Buffer): boolean {
  // Check first 512 bytes for null bytes (common binary indicator)
  const checkLength = Math.min(buf.length, 512);
  for (let i = 0; i < checkLength; i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

export const secretDetectionScanner: Scanner = {
  name: "secret-detection",

  isAvailable(config: RedTeamConfig): boolean {
    return config.scanners.secretDetection.enabled;
  },

  async scan(config: RedTeamConfig): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const scanConfig = config.scanners.secretDetection;
    const repoRoot = resolve(config.repoRoot);

    const files = await glob(scanConfig.include, {
      cwd: repoRoot,
      ignore: scanConfig.exclude,
      nodir: true,
      absolute: true,
      dot: true,
    });

    // Combine builtin + custom patterns
    const patterns: Record<string, RegExp> = { ...BUILTIN_PATTERNS };
    for (const [name, pattern] of Object.entries(scanConfig.customPatterns)) {
      patterns[name] = new RegExp(pattern, "gi");
    }

    for (const file of files) {
      // Skip known binary extensions
      const ext = file.substring(file.lastIndexOf(".")).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext)) continue;

      let buf: Buffer;
      try {
        buf = readFileSync(file);
      } catch {
        continue;
      }

      // Skip binary files
      if (isBinaryContent(buf)) continue;

      const content = buf.toString("utf-8");
      const lines = content.split("\n");
      const relPath = relative(repoRoot, file);

      for (const [patternName, regex] of Object.entries(patterns)) {
        for (let i = 0; i < lines.length; i++) {
          // Reset lastIndex for each line since regex has /g flag
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(lines[i])) !== null) {
            const severity = PATTERN_SEVERITY[patternName] ?? "high";

            findings.push({
              rawId: `secret-${patternName}-${relPath}-${i + 1}-${match.index}`,
              title: `Potential secret detected: ${patternName}`,
              severity,
              confidence: "medium",
              tool: "secret-detection",
              category: "secret",
              location: { path: relPath, startLine: i + 1, endLine: i + 1 },
              evidence: maskEvidence(match[0]),
              remediation:
                "Remove the secret from source code and rotate the credential. " +
                "Use environment variables or a secrets manager instead.",
              references: [
                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
              ],
            });
          }
        }
      }
    }

    logger.info("Secret scan complete", {
      filesScanned: files.length,
      findings: findings.length,
    });

    return findings;
  },
};

/**
 * Mask evidence so raw secrets are never stored in findings.
 * Shows first 4 and last 4 characters; masks the rest.
 */
function maskEvidence(raw: string): string {
  const truncated = raw.slice(0, 1024);
  if (truncated.length <= 8) return "*".repeat(truncated.length);
  return (
    truncated.slice(0, 4) +
    "*".repeat(truncated.length - 8) +
    truncated.slice(-4)
  );
}
