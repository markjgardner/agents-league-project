// ─── LLM Planner Configuration ───────────────────────────────────────

import { DEFAULT_TARGET_ALLOWLIST } from "./guardrails.js";

export interface LLMPlannerConfig {
  /** Master toggle — must be explicitly true to run the LLM stage */
  enabled: boolean;
  /** LLM model name / deployment */
  model: string;
  /** API endpoint URL (optional) */
  endpoint?: string;
  /** API key (from env var, never in config file) */
  apiKey?: string;
  /** Maximum number of files to send to the LLM */
  maxFiles: number;
  /** Maximum tokens for LLM response */
  maxTokens: number;
  /** Request timeout in milliseconds */
  timeoutMs: number;
  /** Allowed dynamic test targets (hostnames only) */
  targetAllowlist: string[];
  /** Maximum hypotheses to process per run */
  maxHypotheses: number;
}

/** Default LLM planner configuration (disabled by default) */
export const DEFAULT_LLM_PLANNER_CONFIG: LLMPlannerConfig = {
  enabled: false,
  model: "gpt-4o-mini",
  maxFiles: 20,
  maxTokens: 4096,
  timeoutMs: 60_000,
  targetAllowlist: [...DEFAULT_TARGET_ALLOWLIST],
  maxHypotheses: 10,
};

/**
 * Load LLM planner config from environment variables and optional file config.
 */
export function loadLLMPlannerConfig(
  fileConfig?: Partial<LLMPlannerConfig>,
): LLMPlannerConfig {
  const base = { ...DEFAULT_LLM_PLANNER_CONFIG, ...fileConfig };

  // Environment variable overrides (highest precedence)
  if (process.env.REDTEAM_LLM_ENABLED !== undefined) {
    base.enabled = process.env.REDTEAM_LLM_ENABLED === "true";
  }
  if (process.env.REDTEAM_LLM_MODEL) {
    base.model = process.env.REDTEAM_LLM_MODEL;
  }
  if (process.env.REDTEAM_LLM_ENDPOINT) {
    base.endpoint = process.env.REDTEAM_LLM_ENDPOINT;
  }
  if (process.env.REDTEAM_LLM_KEY) {
    base.apiKey = process.env.REDTEAM_LLM_KEY;
  }
  if (process.env.REDTEAM_LLM_MAX_FILES) {
    const n = parseInt(process.env.REDTEAM_LLM_MAX_FILES, 10);
    if (!isNaN(n) && n > 0) base.maxFiles = n;
  }
  if (process.env.REDTEAM_LLM_MAX_TOKENS) {
    const n = parseInt(process.env.REDTEAM_LLM_MAX_TOKENS, 10);
    if (!isNaN(n) && n > 0) base.maxTokens = n;
  }
  if (process.env.REDTEAM_TARGET_ALLOWLIST) {
    base.targetAllowlist = process.env.REDTEAM_TARGET_ALLOWLIST.split(",").map((s) => s.trim()).filter(Boolean);
  }

  return base;
}
