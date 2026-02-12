// ─── Safety Guardrails for LLM Planner ───────────────────────────────

import type { LLMPlannerConfig } from "./config.js";
import type { AttackHypothesis } from "./models.js";

/**
 * Check if the LLM planner stage is enabled.
 * Requires explicit opt-in via REDTEAM_LLM_ENABLED=true.
 */
export function isLLMPlannerEnabled(config: LLMPlannerConfig): boolean {
  return config.enabled === true;
}

/**
 * Validate that a target URL is on the allowlist.
 * Default allowlist is localhost only.
 */
export function isTargetAllowed(target: string, allowlist: string[]): boolean {
  try {
    const url = new URL(target);
    const hostname = url.hostname.toLowerCase();
    return allowlist.some((allowed) => {
      const normalizedAllowed = allowed.toLowerCase().trim();
      return hostname === normalizedAllowed;
    });
  } catch {
    return false;
  }
}

/** Default target allowlist — localhost only */
export const DEFAULT_TARGET_ALLOWLIST: string[] = [
  "localhost",
  "127.0.0.1",
  "::1",
];

/**
 * Sanitize LLM output by removing potentially dangerous content.
 * Returns the sanitized string.
 */
export function sanitizeLLMOutput(raw: string): string {
  // Remove any shell command patterns that look like exploitation
  let sanitized = raw;

  // Strip bash/shell command blocks that aren't safe inspection commands
  const dangerousPatterns = [
    /```bash\s*\n.*?(curl|wget|nc|netcat|nmap|sqlmap|nikto|burp)\s+(?!localhost|127\.0\.0\.1).*?```/gis,
    /rm\s+-rf\s+\S*/gi,
    /;\s*(drop|delete|truncate)\s+/gi,
  ];

  for (const pattern of dangerousPatterns) {
    sanitized = sanitized.replace(pattern, "[REDACTED: unsafe command]");
  }

  return sanitized;
}

/**
 * Filter hypotheses to remove any that suggest targeting external systems.
 */
export function filterSafeHypotheses(
  hypotheses: AttackHypothesis[],
  allowlist: string[],
): AttackHypothesis[] {
  return hypotheses.filter((h) => {
    // Check safe_test_plan doesn't reference external URLs
    const urlPattern = /https?:\/\/([^/\s]+)/gi;
    let match: RegExpExecArray | null;
    while ((match = urlPattern.exec(h.safe_test_plan)) !== null) {
      const hostname = match[1].split(":")[0].toLowerCase();
      if (!allowlist.some((a) => hostname === a.toLowerCase().trim())) {
        return false;
      }
    }
    return true;
  });
}

/**
 * Enforce a maximum number of hypotheses to prevent unbounded output.
 */
export function limitHypotheses(
  hypotheses: AttackHypothesis[],
  maxCount: number,
): AttackHypothesis[] {
  return hypotheses.slice(0, maxCount);
}
