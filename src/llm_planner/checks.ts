// ─── Hypothesis → Safe Checks Mapper ─────────────────────────────────

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { AttackHypothesis, HypothesisCheckResult } from "./models.js";
import { isTargetAllowed } from "./guardrails.js";
import { logger } from "../utils/logger.js";

/**
 * Static check patterns mapped to hypothesis categories.
 * Each pattern is a regex to grep for in relevant files.
 */
const STATIC_CHECK_PATTERNS: Record<string, Array<{ name: string; pattern: RegExp }>> = {
  injection: [
    { name: "string-concatenated-query", pattern: /['"].*(?:SELECT|INSERT|UPDATE|DELETE)\b.*['\"]\s*\+|\+\s*['"].*(?:SELECT|INSERT|UPDATE|DELETE)/gi },
    { name: "unsanitized-input", pattern: /req\.(?:body|query|params)\s*\[/gi },
    { name: "eval-usage", pattern: /\beval\s*\(/gi },
  ],
  "auth-bypass": [
    { name: "missing-auth-middleware", pattern: /app\.(?:get|post|put|delete|patch)\s*\([^,]+,\s*(?:async\s+)?\(/gi },
    { name: "jwt-none-algorithm", pattern: /algorithm.*none|none.*algorithm/gi },
    { name: "hardcoded-token-check", pattern: /===?\s*['"][a-zA-Z0-9]{20,}['"]/gi },
  ],
  "info-disclosure": [
    { name: "stack-trace-exposure", pattern: /(?:err|error)\.(?:stack|message)\s*[,)}\]]/gi },
    { name: "verbose-error", pattern: /res\.(?:json|send)\s*\(\s*(?:err|error)/gi },
    { name: "console-log-sensitive", pattern: /console\.log\s*\(.*(?:password|secret|token|key|credential)/gi },
  ],
  misconfiguration: [
    { name: "cors-wildcard", pattern: /cors\s*\(\s*\)|\*.*origin|origin.*\*/gi },
    { name: "debug-enabled", pattern: /debug\s*[:=]\s*true|NODE_ENV.*development/gi },
    { name: "missing-helmet", pattern: /app\.use\s*\(\s*(?:express\.static|morgan|bodyParser)/gi },
  ],
  "secret-leak": [
    { name: "hardcoded-credential", pattern: /(?:password|secret|api_key|apikey|token)\s*[:=]\s*['"][^'"]{8,}['"]/gi },
    { name: "dotenv-in-source", pattern: /\.env.*committed|process\.env\.\w+\s*\|\|\s*['"][^'"]{8,}['"]/gi },
  ],
  dependency: [
    { name: "outdated-package", pattern: /\"version\"\s*:\s*\"[01]\./gi },
    { name: "no-lockfile-integrity", pattern: /integrity/gi },
  ],
};

/**
 * Run safe static checks for a hypothesis against the repository.
 * Returns check results with evidence details.
 */
export function runStaticChecks(
  hypothesis: AttackHypothesis,
  repoRoot: string,
): HypothesisCheckResult {
  const locations: string[] = [];
  const evidenceDetails: string[] = [];

  // Get relevant patterns for this category
  const categoryPatterns = STATIC_CHECK_PATTERNS[hypothesis.category] ?? [];

  // Check each likely location
  for (const loc of hypothesis.likely_locations) {
    const filePath = loc.split(":")[0]; // Strip function/line info
    const fullPath = join(repoRoot, filePath);

    if (!existsSync(fullPath)) continue;

    try {
      const content = readFileSync(fullPath, "utf-8");

      // Run category-specific patterns
      for (const { name, pattern } of categoryPatterns) {
        // Reset regex state
        pattern.lastIndex = 0;
        const matches = content.match(pattern);
        if (matches) {
          locations.push(filePath);
          evidenceDetails.push(
            `Pattern '${name}' matched ${matches.length} time(s) in ${filePath}`,
          );
        }
      }

      // Also search for keywords mentioned in the hypothesis rationale
      const keywords = extractKeywords(hypothesis.rationale);
      for (const keyword of keywords) {
        if (content.toLowerCase().includes(keyword.toLowerCase())) {
          if (!locations.includes(filePath)) {
            locations.push(filePath);
          }
        }
      }
    } catch {
      // Cannot read file — skip
    }
  }

  const evidenceFound = evidenceDetails.length > 0;
  const details = evidenceFound
    ? `Static analysis found supporting evidence:\n${evidenceDetails.join("\n")}`
    : "No supporting evidence found via static analysis.";

  return {
    hypothesisId: hypothesis.id,
    evidenceFound,
    details,
    locations: [...new Set(locations)],
  };
}

/**
 * Run safe dynamic checks against a localhost target.
 * Only executes if the target is on the allowlist.
 */
export async function runDynamicChecks(
  hypothesis: AttackHypothesis,
  targetUrl: string,
  allowlist: string[],
): Promise<HypothesisCheckResult> {
  if (!isTargetAllowed(targetUrl, allowlist)) {
    logger.warn("Dynamic check blocked: target not on allowlist", {
      target: targetUrl,
      hypothesisId: hypothesis.id,
    });
    return {
      hypothesisId: hypothesis.id,
      evidenceFound: false,
      details: `Dynamic check skipped: target '${targetUrl}' is not on the allowlist.`,
      locations: [],
    };
  }

  const evidenceDetails: string[] = [];
  const locations: string[] = [];

  // Safe dynamic checks: header inspection and path probing only
  if (hypothesis.category === "misconfiguration" || hypothesis.category === "info-disclosure") {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {
        const response = await fetch(targetUrl, {
          method: "GET",
          signal: controller.signal,
        });

        // Check for missing security headers
        const securityHeaders = [
          "x-frame-options",
          "x-content-type-options",
          "strict-transport-security",
          "content-security-policy",
          "x-xss-protection",
        ];

        for (const header of securityHeaders) {
          if (!response.headers.get(header)) {
            evidenceDetails.push(`Missing security header: ${header}`);
            locations.push(targetUrl);
          }
        }
      } finally {
        clearTimeout(timeout);
      }
    } catch {
      evidenceDetails.push(`Could not reach target: ${targetUrl}`);
    }
  }

  const evidenceFound = evidenceDetails.length > 0 && !evidenceDetails[0].startsWith("Could not");

  return {
    hypothesisId: hypothesis.id,
    evidenceFound,
    details: evidenceDetails.length > 0
      ? evidenceDetails.join("\n")
      : "No issues found via safe dynamic probes.",
    locations,
  };
}

/**
 * Extract simple keywords from a rationale string for evidence searching.
 */
function extractKeywords(rationale: string): string[] {
  // Extract function names, variable names, and key terms
  const codeRefs = rationale.match(/`[^`]+`/g) ?? [];
  return codeRefs.map((r) => r.replace(/`/g, "")).filter((r) => r.length >= 3);
}
