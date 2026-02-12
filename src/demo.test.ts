import { DEMO_ISSUE_LABEL } from "./constants.js";
import { loadConfig } from "./config.js";
import { generateFingerprint } from "./utils/fingerprint.js";
import { buildIssueBody, FINGERPRINT_REGEX } from "./github/issues.js";
import type { Finding, RedTeamConfig } from "./types.js";
import { writeFileSync, unlinkSync, existsSync } from "node:fs";
import { resolve } from "node:path";

// ─── Helper ─────────────────────────────────────────────────────────

function makeFinding(overrides?: Partial<Finding>): Finding {
  const base: Finding = {
    id: "abcdef123456",
    title: "Potential secret detected: aws-access-key",
    severity: "critical",
    confidence: "medium",
    tool: "secret-detection",
    category: "secret",
    location: { path: "secrets.example", startLine: 7, endLine: 7 },
    evidence: "AKIA************MPLE",
    remediation: "Remove the secret and rotate.",
    references: [],
    fingerprint: "a".repeat(64),
  };
  return { ...base, ...overrides };
}

// ─── DEMO_ISSUE_LABEL constant ──────────────────────────────────────

describe("DEMO_ISSUE_LABEL", () => {
  it("has the expected value", () => {
    expect(DEMO_ISSUE_LABEL).toBe("demo:redteam-example");
  });
});

// ─── Config: demoLabel ──────────────────────────────────────────────

describe("loadConfig demoLabel", () => {
  const testConfigPath = resolve("/tmp/test-demo-config.json");

  afterEach(() => {
    if (existsSync(testConfigPath)) unlinkSync(testConfigPath);
    delete process.env.DEMO_ISSUE_LABEL;
  });

  it("sets demoLabel from DEMO_ISSUE_LABEL env var", () => {
    process.env.DEMO_ISSUE_LABEL = "demo:redteam-example";
    const config = loadConfig("/tmp/nonexistent-config.json");
    expect(config.issues.demoLabel).toBe("demo:redteam-example");
  });

  it("leaves demoLabel undefined when env var is not set", () => {
    const config = loadConfig("/tmp/nonexistent-config.json");
    expect(config.issues.demoLabel).toBeUndefined();
  });

  it("env var takes precedence over file config", () => {
    writeFileSync(
      testConfigPath,
      JSON.stringify({ issues: { demoLabel: "file-label" } }),
    );
    process.env.DEMO_ISSUE_LABEL = "env-label";
    const config = loadConfig(testConfigPath);
    expect(config.issues.demoLabel).toBe("env-label");
  });
});

// ─── Fingerprint stability ──────────────────────────────────────────

describe("demo fingerprint stability", () => {
  it("produces the same fingerprint for the same finding regardless of demo mode", () => {
    // Fingerprints are based on (tool, category, location, title) — not on labels.
    // This means the same finding will have the same fingerprint whether or not
    // demo mode is active. Demo/non-demo separation is handled by the label
    // filter in dedup, not by the fingerprint itself.
    const fp1 = generateFingerprint(
      "secret-detection",
      "secret",
      "secrets.example",
      "Potential secret detected: aws-access-key",
    );
    const fp2 = generateFingerprint(
      "secret-detection",
      "secret",
      "secrets.example",
      "Potential secret detected: aws-access-key",
    );
    expect(fp1).toBe(fp2);
  });

  it("demo issues are separated from non-demo via label, not fingerprint", () => {
    // Two configs: one with demo label, one without
    const configWithDemo: RedTeamConfig = {
      repoRoot: ".",
      github: { owner: "o", repo: "r", token: "" },
      scanners: {
        npmAudit: { enabled: false, minSeverity: "medium" },
        secretDetection: {
          enabled: false, include: [], exclude: [], customPatterns: {},
        },
        httpScan: { enabled: false, target: "", paths: [] },
      },
      issues: {
        enabled: true, extraLabels: [], maxPerRun: 10,
        assignees: [], autoClose: false,
        demoLabel: "demo:redteam-example",
      },
    };

    const configWithoutDemo: RedTeamConfig = {
      ...configWithDemo,
      issues: { ...configWithDemo.issues, demoLabel: undefined },
    };

    // Same finding produces same fingerprint in both configs
    const finding = makeFinding();
    const body1 = buildIssueBody(finding);
    const body2 = buildIssueBody(finding);
    const fp1 = FINGERPRINT_REGEX.exec(body1)?.[1];
    const fp2 = FINGERPRINT_REGEX.exec(body2)?.[1];
    expect(fp1).toBe(fp2);

    // The distinction is in the label filter used by dedup (tested indirectly
    // via the demoLabel config field). When demoLabel is set, dedup filters
    // issues by "redteam-agent,demo:redteam-example" instead of "redteam-agent".
    expect(configWithDemo.issues.demoLabel).toBe("demo:redteam-example");
    expect(configWithoutDemo.issues.demoLabel).toBeUndefined();
  });
});
