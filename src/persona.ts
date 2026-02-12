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
  /** Optional fun-fact or motivational blurb inserted before the closing */
  funFact(finding: Finding): string;
  /** Closing line for the issue body */
  closingLine(finding: Finding): string;
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
  funFact(_finding) {
    return "";
  },
  closingLine(_finding) {
    return "";
  },
};

// ─── Chuck Norris Persona ───────────────────────────────────────────

const CHUCK_OPENINGS: Record<Severity, string[]> = {
  critical: [
    "This vulnerability was found cowering in the codebase. It never had a chance.",
    "Chuck Norris mode does not negotiate with insecure code. This one is critical.",
    "Chuck Norris once roundhouse-kicked a vulnerability so hard it patched itself. This one wasn't so lucky.",
    "This critical finding tried to run. Chuck Norris doesn't chase — the code just surrenders.",
    "When Chuck Norris scans for critical vulnerabilities, they turn themselves in.",
  ],
  high: [
    "A serious vulnerability was discovered. It immediately regretted existing.",
    "This finding is significant. Chuck Norris mode has zero tolerance for it.",
    "Chuck Norris counted to infinity — twice — before this vulnerability even loaded.",
    "This high-severity bug thought it was tough. Then it met Chuck Norris mode.",
    "Chuck Norris doesn't read stack traces. Stack traces read themselves to him.",
  ],
  medium: [
    "This vulnerability thought it could hide. It was wrong.",
    "A moderate issue was found. Chuck Norris mode does not do \"moderate\" — fix it.",
    "Chuck Norris doesn't triage medium findings. He promotes them to \"fix immediately.\"",
    "Medium severity? Chuck Norris's beard has already written the patch.",
    "This bug was medium. Chuck Norris rounded it up to \"unacceptable.\"",
  ],
  low: [
    "Even low-severity findings get noticed. Nothing escapes a Chuck Norris scan.",
    "A minor issue was detected. Chuck Norris mode rounds low up to \"handle it now.\"",
    "Chuck Norris doesn't ignore low findings. He stares at them until they fix themselves.",
    "Low severity is just Chuck Norris giving you a head start.",
    "This bug thought being low severity would save it. Chuck Norris disagrees.",
  ],
};

const CHUCK_TITLE_SUFFIXES: string[] = [
  "Chuck Norris Was Here",
  "Detected by Roundhouse Scan",
  "You Can't Hide from Chuck",
  "Fear the Scan",
  "Chuck Norris Approved Fix Required",
];

const CHUCK_CLOSINGS: string[] = [
  "🥋 *Fix this. Re-run the scan. Chuck Norris will be watching.*",
  "🥋 *Chuck Norris doesn't file bugs — he files warnings. You've been warned.*",
  "🥋 *The code has been judged. Chuck Norris expects a fix by yesterday.*",
  "🥋 *Remember: Chuck Norris can unit-test an entire codebase with a single glare.*",
  "🥋 *Patch it before Chuck Norris patches you.*",
];

const CHUCK_FUN_FACTS: string[] = [
  "Chuck Norris can delete the root node of a binary tree in O(0) time.",
  "Chuck Norris's keyboard has no Ctrl key. Chuck Norris is always in control.",
  "Chuck Norris can compile syntax errors.",
  "When Chuck Norris pushes code, the repo pulls itself together.",
  "Chuck Norris doesn't use version control. The code is too afraid to change without his permission.",
  "Chuck Norris doesn't deploy to production. Production deploys to Chuck Norris.",
  "Chuck Norris's code doesn't have bugs. Bugs have Chuck Norris, and they regret it.",
  "Chuck Norris can access private methods. They volunteer their values.",
  "Chuck Norris's pull requests merge themselves out of respect.",
  "Chuck Norris once mass-assigned every variable in a codebase. They all said thank you.",
];

/** Deterministic index picker based on a hex fingerprint string */
function pickIndex(fingerprint: string, offset: number, count: number): number {
  return (
    (parseInt(fingerprint.slice(offset, offset + 8), 16) || 0) % count
  );
}

const chuckNorrisPersona: Persona = {
  issueTitle(finding) {
    const sev = finding.severity.toUpperCase();
    const suffix =
      CHUCK_TITLE_SUFFIXES[pickIndex(finding.fingerprint, 0, CHUCK_TITLE_SUFFIXES.length)];
    return `🥋 [${sev}] ${finding.title} — ${suffix}`;
  },
  openingParagraph(finding) {
    const options = CHUCK_OPENINGS[finding.severity];
    const index = pickIndex(finding.fingerprint, 0, options.length);
    return `> ${options[index]}\n`;
  },
  evidenceHeader() {
    return "### 🔍 Proof (Because Doubt Is Not an Option)";
  },
  remediationHeader() {
    return "### 💪 How to Fix This So It Never Happens Again";
  },
  funFact(finding) {
    const fact =
      CHUCK_FUN_FACTS[pickIndex(finding.fingerprint, 8, CHUCK_FUN_FACTS.length)];
    return `\n> 💡 **Chuck Norris Fun Fact:** ${fact}\n`;
  },
  closingLine(finding) {
    const closing =
      CHUCK_CLOSINGS[pickIndex(finding.fingerprint, 16, CHUCK_CLOSINGS.length)];
    return `\n${closing}`;
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
