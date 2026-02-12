import { RawFinding, Finding } from "./types.js";
import { generateFingerprint, generateId } from "./utils/fingerprint.js";

/**
 * Normalize raw scanner output into the canonical Finding schema.
 * Adds deterministic fingerprint and ID, truncates evidence.
 */
export function normalize(raw: RawFinding[]): Finding[] {
  return raw.map((r) => {
    const fingerprint = generateFingerprint(
      r.tool,
      r.category,
      r.location.path,
      r.title,
    );
    const id = generateId(fingerprint);
    return {
      ...r,
      id,
      fingerprint,
      evidence: r.evidence.slice(0, 1024),
    };
  });
}
