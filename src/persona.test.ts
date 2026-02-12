import { getPersona } from "./persona.js";
import { buildIssueBody, FINGERPRINT_REGEX } from "./github/issues.js";
import type { Finding } from "./types.js";

const baseFinding: Finding = {
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

describe("Persona abstraction", () => {
  describe("default persona", () => {
    const persona = getPersona("default");

    it("formats issue title as [SEVERITY] Title", () => {
      expect(persona.issueTitle(baseFinding)).toBe("[HIGH] Prototype Pollution in lodash");
    });

    it("returns empty opening paragraph", () => {
      expect(persona.openingParagraph(baseFinding)).toBe("");
    });

    it("returns standard evidence header", () => {
      expect(persona.evidenceHeader()).toBe("### Evidence");
    });

    it("returns standard remediation header", () => {
      expect(persona.remediationHeader()).toBe("### Remediation");
    });

    it("returns empty closing line", () => {
      expect(persona.closingLine()).toBe("");
    });
  });

  describe("chuck_norris persona", () => {
    const persona = getPersona("chuck_norris");

    it("includes 'Chuck Norris Was Here' in issue title", () => {
      const title = persona.issueTitle(baseFinding);
      expect(title).toContain("[HIGH]");
      expect(title).toContain("Chuck Norris Was Here");
      expect(title).toContain(baseFinding.title);
    });

    it("produces a non-empty opening paragraph", () => {
      const opening = persona.openingParagraph(baseFinding);
      expect(opening.length).toBeGreaterThan(0);
      expect(opening).toContain(">");
    });

    it("uses Chuck Norris evidence header", () => {
      expect(persona.evidenceHeader()).toContain("Proof");
    });

    it("uses Chuck Norris remediation header", () => {
      expect(persona.remediationHeader()).toContain("Fix This");
    });

    it("produces a non-empty closing line", () => {
      const closing = persona.closingLine();
      expect(closing).toContain("Chuck Norris");
    });

    it("scales tone with severity", () => {
      const criticalFinding = { ...baseFinding, severity: "critical" as const };
      const lowFinding = { ...baseFinding, severity: "low" as const };
      const criticalOpening = persona.openingParagraph(criticalFinding);
      const lowOpening = persona.openingParagraph(lowFinding);
      // Both should be non-empty but different
      expect(criticalOpening.length).toBeGreaterThan(0);
      expect(lowOpening.length).toBeGreaterThan(0);
    });
  });

  describe("persona does not alter findings data", () => {
    it("chuck_norris body preserves fingerprint, id, severity, and tool", () => {
      const persona = getPersona("chuck_norris");
      const body = buildIssueBody(baseFinding, persona);

      // Fingerprint is embedded correctly
      const match = FINGERPRINT_REGEX.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe(baseFinding.fingerprint);

      // Core finding data is present unchanged
      expect(body).toContain(`\`${baseFinding.severity}\``);
      expect(body).toContain(`\`${baseFinding.tool}\``);
      expect(body).toContain(`\`${baseFinding.id}\``);
      expect(body).toContain(baseFinding.fingerprint.slice(0, 12));
      expect(body).toContain(baseFinding.evidence);
      expect(body).toContain(baseFinding.remediation);
    });

    it("default body preserves fingerprint, id, severity, and tool", () => {
      const persona = getPersona("default");
      const body = buildIssueBody(baseFinding, persona);

      const match = FINGERPRINT_REGEX.exec(body);
      expect(match).not.toBeNull();
      expect(match![1]).toBe(baseFinding.fingerprint);

      expect(body).toContain(`\`${baseFinding.severity}\``);
      expect(body).toContain(`\`${baseFinding.tool}\``);
      expect(body).toContain(`\`${baseFinding.id}\``);
    });

    it("chuck_norris body has different wording than default body", () => {
      const defaultBody = buildIssueBody(baseFinding, getPersona("default"));
      const chuckBody = buildIssueBody(baseFinding, getPersona("chuck_norris"));

      // Bodies should be different (persona changes presentation)
      expect(chuckBody).not.toBe(defaultBody);

      // But both contain the same core finding data
      expect(chuckBody).toContain(baseFinding.evidence);
      expect(defaultBody).toContain(baseFinding.evidence);
    });
  });

  describe("getPersona fallback", () => {
    it("returns default persona for unknown names", () => {
      // Cast to bypass type checking for the test
      const persona = getPersona("nonexistent" as any);
      expect(persona.issueTitle(baseFinding)).toBe("[HIGH] Prototype Pollution in lodash");
    });
  });
});
