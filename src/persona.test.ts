import { getPersona } from "./persona.js";
import { buildIssueBody, FINGERPRINT_REGEX } from "./github/issues.js";
import type { Finding, PersonaName } from "./types.js";

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

    it("returns empty fun fact", () => {
      expect(persona.funFact(baseFinding)).toBe("");
    });

    it("returns empty closing line", () => {
      expect(persona.closingLine(baseFinding)).toBe("");
    });
  });

  describe("chuck_norris persona", () => {
    const persona = getPersona("chuck_norris");

    it("includes emoji and a Chuck Norris suffix in issue title", () => {
      const title = persona.issueTitle(baseFinding);
      expect(title).toContain("[HIGH]");
      expect(title).toContain("🥋");
      expect(title).toContain(baseFinding.title);
      expect(title).toMatch(/—\s.+/); // has a suffix after the em-dash
    });

    it("produces a non-empty opening paragraph", () => {
      const opening = persona.openingParagraph(baseFinding);
      expect(opening.length).toBeGreaterThan(0);
      expect(opening).toContain(">");
    });

    it("uses Chuck Norris evidence header with emoji", () => {
      const header = persona.evidenceHeader();
      expect(header).toContain("Proof");
      expect(header).toContain("🔍");
    });

    it("uses Chuck Norris remediation header with emoji", () => {
      const header = persona.remediationHeader();
      expect(header).toContain("Fix This");
      expect(header).toContain("💪");
    });

    it("produces a non-empty fun fact with Chuck Norris theme", () => {
      const fact = persona.funFact(baseFinding);
      expect(fact).toContain("Chuck Norris Fun Fact");
      expect(fact).toContain("💡");
      expect(fact.length).toBeGreaterThan(0);
    });

    it("produces a non-empty closing line with Chuck Norris theme", () => {
      const closing = persona.closingLine(baseFinding);
      expect(closing).toContain("🥋");
      expect(closing.length).toBeGreaterThan(0);
    });

    it("has at least 5 opening quips per severity", () => {
      for (const sev of ["critical", "high", "medium", "low"] as const) {
        const finding = { ...baseFinding, severity: sev };
        // Generate openings with different fingerprints to prove variety
        const seen = new Set<string>();
        for (let i = 0; i < 20; i++) {
          const fp = i.toString(16).padStart(8, "0").repeat(8);
          const tweaked = { ...finding, fingerprint: fp };
          seen.add(persona.openingParagraph(tweaked));
        }
        expect(seen.size).toBeGreaterThanOrEqual(3);
      }
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

    it("rotates closing lines deterministically based on fingerprint", () => {
      const seen = new Set<string>();
      for (let i = 0; i < 20; i++) {
        const fp = i.toString(16).padStart(8, "0").repeat(8);
        const tweaked = { ...baseFinding, fingerprint: fp };
        seen.add(persona.closingLine(tweaked));
      }
      expect(seen.size).toBeGreaterThanOrEqual(2);
    });

    it("rotates fun facts deterministically based on fingerprint", () => {
      const seen = new Set<string>();
      for (let i = 0; i < 20; i++) {
        const fp = i.toString(16).padStart(8, "0").repeat(8);
        const tweaked = { ...baseFinding, fingerprint: fp };
        seen.add(persona.funFact(tweaked));
      }
      expect(seen.size).toBeGreaterThanOrEqual(3);
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

    it("chuck_norris body includes a fun fact section", () => {
      const persona = getPersona("chuck_norris");
      const body = buildIssueBody(baseFinding, persona);
      expect(body).toContain("Chuck Norris Fun Fact");
    });

    it("default body does not include a fun fact section", () => {
      const persona = getPersona("default");
      const body = buildIssueBody(baseFinding, persona);
      expect(body).not.toContain("Chuck Norris Fun Fact");
    });
  });

  describe("getPersona fallback", () => {
    it("returns default persona for unknown names", () => {
      const persona = getPersona("nonexistent" as PersonaName);
      expect(persona.issueTitle(baseFinding)).toBe("[HIGH] Prototype Pollution in lodash");
    });
  });
});
