// ─── LLM Planner Issue Builder ───────────────────────────────────────

import type { AttackHypothesis, HypothesisCheckResult } from "./models.js";
import type { RawFinding, Severity, Confidence } from "../types.js";

/**
 * Convert a confirmed hypothesis (with evidence) into a RawFinding
 * that can be processed by the existing issue pipeline.
 *
 * Only creates a finding if evidence was actually collected.
 */
export function hypothesisToFinding(
  hypothesis: AttackHypothesis,
  checkResult: HypothesisCheckResult,
  demoLabel?: string,
): RawFinding | null {
  // NO EVIDENCE → NO FINDING → NO ISSUE
  if (!checkResult.evidenceFound) {
    return null;
  }

  const locationPath = checkResult.locations[0] ?? hypothesis.likely_locations[0] ?? "unknown";

  return {
    rawId: `llm-planner-${hypothesis.id}`,
    title: hypothesis.title,
    severity: hypothesis.risk as Severity,
    confidence: hypothesis.confidence as Confidence,
    tool: "llm-planner" as RawFinding["tool"],
    category: mapCategory(hypothesis.category),
    location: { path: locationPath },
    evidence: buildEvidenceBlock(hypothesis, checkResult),
    remediation: buildRemediationBlock(hypothesis),
    references: hypothesis.references,
  };
}

/**
 * Build a rich issue body for an LLM-derived finding.
 * Includes hypothesis summary, rationale, evidence, and safe reproduction steps.
 */
function buildEvidenceBlock(
  hypothesis: AttackHypothesis,
  checkResult: HypothesisCheckResult,
): string {
  return [
    `**Hypothesis:** ${hypothesis.title}`,
    `**Category:** ${hypothesis.category}`,
    `**Confidence:** ${hypothesis.confidence}`,
    "",
    "**Why the code suggests this:**",
    hypothesis.rationale,
    "",
    "**Evidence collected:**",
    checkResult.details,
    "",
    `**Files inspected:** ${checkResult.locations.join(", ") || "N/A"}`,
    "",
    "**Safe reproduction steps:**",
    hypothesis.safe_test_plan,
  ].join("\n");
}

/**
 * Build remediation guidance from the hypothesis.
 */
function buildRemediationBlock(hypothesis: AttackHypothesis): string {
  const refs = hypothesis.references.length > 0
    ? `\n\nReferences: ${hypothesis.references.join(", ")}`
    : "";
  return `Review the identified code locations and apply appropriate security controls.${refs}`;
}

/**
 * Map hypothesis categories to the existing Finding category type.
 */
function mapCategory(category: string): RawFinding["category"] {
  const mapping: Record<string, RawFinding["category"]> = {
    injection: "secret",
    "auth-bypass": "http",
    "info-disclosure": "http",
    misconfiguration: "http",
    "secret-leak": "secret",
    dependency: "dependency",
  };
  return mapping[category] ?? "http";
}

/**
 * Get the labels for an LLM-derived issue.
 */
export function getLLMPlannerLabels(
  hypothesis: AttackHypothesis,
  demoLabel?: string,
): string[] {
  const labels = [
    "security",
    `severity:${hypothesis.risk}`,
    `category:${hypothesis.category}`,
    "tool:llm-planner",
  ];
  if (demoLabel) {
    labels.push(demoLabel);
  }
  return labels;
}
