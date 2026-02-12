import { normalize } from "./normalizer.js";
import type { RawFinding } from "./types.js";

describe("normalize", () => {
  const rawFinding: RawFinding = {
    rawId: "npm-lodash-1234",
    title: "Prototype Pollution in lodash",
    severity: "high",
    confidence: "high",
    tool: "npm-audit",
    category: "dependency",
    location: { path: "package.json (lodash)" },
    evidence: "Package: lodash, Severity: high",
    remediation: "Update to lodash@4.17.21",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
  };

  it("adds fingerprint and id to raw findings", () => {
    const [finding] = normalize([rawFinding]);
    expect(finding.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(finding.id).toHaveLength(12);
    expect(finding.id).toBe(finding.fingerprint.slice(0, 12));
  });

  it("preserves all raw fields", () => {
    const [finding] = normalize([rawFinding]);
    expect(finding.title).toBe(rawFinding.title);
    expect(finding.severity).toBe(rawFinding.severity);
    expect(finding.tool).toBe(rawFinding.tool);
    expect(finding.category).toBe(rawFinding.category);
    expect(finding.location).toEqual(rawFinding.location);
    expect(finding.remediation).toBe(rawFinding.remediation);
    expect(finding.references).toEqual(rawFinding.references);
  });

  it("truncates evidence to 1024 characters", () => {
    const longEvidence = "x".repeat(2000);
    const [finding] = normalize([{ ...rawFinding, evidence: longEvidence }]);
    expect(finding.evidence).toHaveLength(1024);
  });

  it("produces deterministic fingerprints for same inputs", () => {
    const [a] = normalize([rawFinding]);
    const [b] = normalize([rawFinding]);
    expect(a.fingerprint).toBe(b.fingerprint);
  });

  it("handles empty array", () => {
    const result = normalize([]);
    expect(result).toEqual([]);
  });
});
