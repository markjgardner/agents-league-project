import type { Finding, PersonaName, Severity } from "./types.js";

// ─── Persona Interface ──────────────────────────────────────────────

export interface Persona {
  /** Format the issue title for a finding */
  issueTitle(finding: Finding): string;
  /** Opening paragraph for the issue body */
  openingParagraph(finding: Finding): string;
  /** Section header for evidence */
  evidenceHeader(): string;
  /** Section header for remediation */
  remediationHeader(): string;
  /** Closing line for the issue body */
  closingLine(): string;
}

// ─── Default Persona ────────────────────────────────────────────────

const defaultPersona: Persona = {
  issueTitle(finding) {
    return `[${finding.severity.toUpperCase()}] ${finding.title}`;
  },
  openingParagraph(_finding) {
    return "";
  },
  evidenceHeader() {
    return "### Evidence";
  },
  remediationHeader() {
    return "### Remediation";
  },
  closingLine() {
    return "";
  },
};

// ─── Chuck Norris Persona ───────────────────────────────────────────

const CHUCK_OPENINGS: Record<Severity, string[]> = {
  critical: [
    "This vulnerability was found cowering in the codebase. It never had a chance.",
    "Chuck Norris mode does not negotiate with insecure code. This one is critical.",
  ],
  high: [
    "A serious vulnerability was discovered. It immediately regretted existing.",
    "This finding is significant. Chuck Norris mode has zero tolerance for it.",
  ],
  medium: [
    "This vulnerability thought it could hide. It was wrong.",
    "A moderate issue was found. Chuck Norris mode does not do \"moderate\" — fix it.",
  ],
  low: [
    "Even low-severity findings get noticed. Nothing escapes a Chuck Norris scan.",
    "A minor issue was detected. Chuck Norris mode rounds low up to \"handle it now.\"",
  ],
};

const chuckNorrisPersona: Persona = {
  issueTitle(finding) {
    const sev = finding.severity.toUpperCase();
    return `[${sev}] ${finding.title} — Chuck Norris Was Here`;
  },
  openingParagraph(finding) {
    const options = CHUCK_OPENINGS[finding.severity];
    // Deterministic pick based on fingerprint to keep it stable across runs
    const index = parseInt(finding.fingerprint.slice(0, 8), 16) % options.length;
    return `> ${options[index]}\n`;
  },
  evidenceHeader() {
    return "### Proof (Because Doubt Is Not an Option)";
  },
  remediationHeader() {
    return "### How to Fix This So It Never Happens Again";
  },
  closingLine() {
    return "\n🥋 *Fix this. Re-run the scan. Chuck Norris will be watching.*";
  },
};

// ─── Persona Registry ───────────────────────────────────────────────

const PERSONAS: Record<PersonaName, Persona> = {
  default: defaultPersona,
  chuck_norris: chuckNorrisPersona,
};

export function getPersona(name: PersonaName): Persona {
  return PERSONAS[name] ?? PERSONAS.default;
}
