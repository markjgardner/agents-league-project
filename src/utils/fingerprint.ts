import { createHash } from "node:crypto";

/**
 * Generate a stable fingerprint from the canonical fields of a finding.
 * fingerprint = SHA-256(tool | ruleId/category | normalizedLocation | normalizedEvidence/title)
 */
export function generateFingerprint(...fields: string[]): string {
  const normalized = fields.map((f) => f.toLowerCase().trim());
  return createHash("sha256").update(normalized.join("|")).digest("hex");
}

/** Short ID derived from fingerprint (first 12 hex chars) */
export function generateId(fingerprint: string): string {
  return fingerprint.slice(0, 12);
}
