import { buildIssueBody, maskSecret, FINGERPRINT_REGEX } from "./issues.js";
import type { Finding } from "../types.js";

describe("buildIssueBody", () => {
  const finding: Finding = {
    id: "abcdef123456",
    title: "Prototype Pollution in lodash",
    severity: "high",
    confidence: "high",
    tool: "npm-audit",
    category: "dependency",
    location: { path: "package.json (lodash)" },
    evidence: "Package: lodash, Severity: high",
    remediation: "Update to lodash@4.17.21",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
    fingerprint: "a".repeat(64),
  };

  it("includes the fingerprint marker in the body", () => {
    const body = buildIssueBody(finding);
    expect(body).toContain(`<!-- redteam-fingerprint:${"a".repeat(64)} -->`);
  });

  it("fingerprint marker is extractable with FINGERPRINT_REGEX", () => {
    const body = buildIssueBody(finding);
    const match = FINGERPRINT_REGEX.exec(body);
    expect(match).not.toBeNull();
    expect(match![1]).toBe("a".repeat(64));
  });

  it("includes title, severity, and tool in the body", () => {
    const body = buildIssueBody(finding);
    expect(body).toContain(finding.title);
    expect(body).toContain(finding.severity);
    expect(body).toContain(finding.tool);
  });

  it("includes location with line number when present", () => {
    const findingWithLine = {
      ...finding,
      location: { path: "src/app.ts", startLine: 42, endLine: 42 },
    };
    const body = buildIssueBody(findingWithLine);
    expect(body).toContain("`src/app.ts:42`");
  });

  it("masks evidence for secret findings", () => {
    const secretFinding: Finding = {
      ...finding,
      category: "secret",
      evidence: "AKIA1234567890ABCDEF",
    };
    const body = buildIssueBody(secretFinding);
    // Should not contain the raw secret
    expect(body).not.toContain("AKIA1234567890ABCDEF");
  });

  it("includes references", () => {
    const body = buildIssueBody(finding);
    expect(body).toContain("https://nvd.nist.gov/vuln/detail/CVE-2021-23337");
  });

  it("shows _None_ when no references", () => {
    const noRefFinding = { ...finding, references: [] };
    const body = buildIssueBody(noRefFinding);
    expect(body).toContain("_None_");
  });
});

describe("maskSecret", () => {
  it("masks the middle of a long string", () => {
    const result = maskSecret("AKIA1234567890ABCDEF");
    expect(result).toBe("AKIA************CDEF");
  });

  it("fully masks short strings (≤8 chars)", () => {
    const result = maskSecret("short");
    expect(result).toBe("*****");
  });

  it("handles exactly 8 chars", () => {
    const result = maskSecret("12345678");
    expect(result).toBe("********");
  });

  it("handles 9 chars (minimum partial mask)", () => {
    const result = maskSecret("123456789");
    expect(result).toBe("1234*6789");
  });
});
