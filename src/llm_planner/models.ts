// ─── LLM Attack Planner Schema ───────────────────────────────────────

export interface AttackHypothesis {
  /** Unique hypothesis identifier (e.g., "HYPO-001") */
  id: string;
  /** Short descriptive title */
  title: string;
  /** Vulnerability category (e.g., "injection", "auth-bypass", "info-disclosure") */
  category: string;
  /** Estimated risk: critical | high | medium | low */
  risk: "critical" | "high" | "medium" | "low";
  /** LLM confidence in the hypothesis: high | medium | low */
  confidence: "high" | "medium" | "low";
  /** Why the code suggests this vulnerability may exist */
  rationale: string;
  /** What evidence would prove or disprove the hypothesis */
  evidence_to_collect: string;
  /** Non-destructive steps to verify the hypothesis */
  safe_test_plan: string;
  /** Files, functions, or routes where the issue is likely located */
  likely_locations: string[];
  /** OWASP / CWE identifiers if known */
  references: string[];
}

/** Result of running a safe check against a hypothesis */
export interface HypothesisCheckResult {
  hypothesisId: string;
  /** Did the check find supporting evidence? */
  evidenceFound: boolean;
  /** Description of what was found (or not found) */
  details: string;
  /** Files/lines where evidence was found */
  locations: string[];
}

/** Validated planner response containing one or more hypotheses */
export interface PlannerResponse {
  hypotheses: AttackHypothesis[];
}

// ─── Validation ──────────────────────────────────────────────────────

const VALID_RISK = new Set(["critical", "high", "medium", "low"]);
const VALID_CONFIDENCE = new Set(["high", "medium", "low"]);

/**
 * Validate that an object conforms to the AttackHypothesis schema.
 * Returns an array of error messages (empty = valid).
 */
export function validateHypothesis(obj: unknown): string[] {
  const errors: string[] = [];
  if (typeof obj !== "object" || obj === null) {
    return ["Hypothesis must be a non-null object"];
  }
  const h = obj as Record<string, unknown>;

  if (typeof h.id !== "string" || h.id.length === 0) {
    errors.push("id must be a non-empty string");
  }
  if (typeof h.title !== "string" || h.title.length === 0) {
    errors.push("title must be a non-empty string");
  }
  if (typeof h.category !== "string" || h.category.length === 0) {
    errors.push("category must be a non-empty string");
  }
  if (!VALID_RISK.has(h.risk as string)) {
    errors.push(`risk must be one of: ${[...VALID_RISK].join(", ")}`);
  }
  if (!VALID_CONFIDENCE.has(h.confidence as string)) {
    errors.push(`confidence must be one of: ${[...VALID_CONFIDENCE].join(", ")}`);
  }
  if (typeof h.rationale !== "string" || h.rationale.length === 0) {
    errors.push("rationale must be a non-empty string");
  }
  if (typeof h.evidence_to_collect !== "string" || h.evidence_to_collect.length === 0) {
    errors.push("evidence_to_collect must be a non-empty string");
  }
  if (typeof h.safe_test_plan !== "string" || h.safe_test_plan.length === 0) {
    errors.push("safe_test_plan must be a non-empty string");
  }
  if (!Array.isArray(h.likely_locations) || h.likely_locations.length === 0) {
    errors.push("likely_locations must be a non-empty array of strings");
  } else if (!h.likely_locations.every((l: unknown) => typeof l === "string")) {
    errors.push("likely_locations must contain only strings");
  }
  if (!Array.isArray(h.references)) {
    errors.push("references must be an array");
  } else if (!h.references.every((r: unknown) => typeof r === "string")) {
    errors.push("references must contain only strings");
  }

  return errors;
}

/**
 * Validate a full PlannerResponse. Returns errors for each hypothesis.
 */
export function validatePlannerResponse(obj: unknown): string[] {
  const errors: string[] = [];
  if (typeof obj !== "object" || obj === null) {
    return ["Response must be a non-null object"];
  }
  const resp = obj as Record<string, unknown>;
  if (!Array.isArray(resp.hypotheses)) {
    return ["Response must contain a 'hypotheses' array"];
  }
  for (let i = 0; i < resp.hypotheses.length; i++) {
    const hErrors = validateHypothesis(resp.hypotheses[i]);
    for (const e of hErrors) {
      errors.push(`hypotheses[${i}]: ${e}`);
    }
  }
  return errors;
}
