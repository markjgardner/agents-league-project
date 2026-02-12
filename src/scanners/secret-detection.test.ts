import { secretDetectionScanner } from "./secret-detection.js";
import type { RedTeamConfig } from "../types.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";

const TEST_DIR = resolve("/tmp/redteam-secret-test");

function makeConfig(overrides?: Partial<RedTeamConfig["scanners"]["secretDetection"]>): RedTeamConfig {
  return {
    repoRoot: TEST_DIR,
    github: { owner: "test", repo: "test", token: "" },
    scanners: {
      npmAudit: { enabled: false, minSeverity: "medium" },
      secretDetection: {
        enabled: true,
        include: ["**/*"],
        exclude: [],
        customPatterns: {},
        ...overrides,
      },
      httpScan: { enabled: false, target: "http://localhost:3000", paths: [] },
    },
    issues: { enabled: false, extraLabels: [], maxPerRun: 10, assignees: [], autoClose: false },
  };
}

describe("secretDetectionScanner", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  it("detects AWS access keys", async () => {
    writeFileSync(resolve(TEST_DIR, "config.js"), 'const key = "AKIAIOSFODNN7EXAMPLE";\n');
    const findings = await secretDetectionScanner.scan(makeConfig());
    const awsFindings = findings.filter((f) => f.rawId.startsWith("secret-aws-access-key"));
    expect(awsFindings.length).toBeGreaterThan(0);
    expect(awsFindings[0].severity).toBe("critical");
    expect(awsFindings[0].location.startLine).toBe(1);
  });

  it("detects GitHub tokens", async () => {
    writeFileSync(
      resolve(TEST_DIR, "env.sh"),
      'export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n',
    );
    const findings = await secretDetectionScanner.scan(makeConfig());
    const ghFindings = findings.filter((f) => f.rawId.startsWith("secret-github-token"));
    expect(ghFindings.length).toBeGreaterThan(0);
    expect(ghFindings[0].severity).toBe("critical");
  });

  it("detects private keys", async () => {
    writeFileSync(
      resolve(TEST_DIR, "key.pem"),
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
    );
    const findings = await secretDetectionScanner.scan(makeConfig());
    const keyFindings = findings.filter((f) => f.rawId.startsWith("secret-private-key"));
    expect(keyFindings.length).toBeGreaterThan(0);
    expect(keyFindings[0].severity).toBe("critical");
  });

  it("detects generic passwords", async () => {
    writeFileSync(
      resolve(TEST_DIR, "app.py"),
      "password='super_secret_password_123'\n",
    );
    const findings = await secretDetectionScanner.scan(makeConfig());
    const pwFindings = findings.filter((f) => f.rawId.startsWith("secret-generic-password"));
    expect(pwFindings.length).toBeGreaterThan(0);
    expect(pwFindings[0].severity).toBe("high");
  });

  it("masks evidence in findings", async () => {
    writeFileSync(resolve(TEST_DIR, "config.js"), 'const key = "AKIAIOSFODNN7EXAMPLE";\n');
    const findings = await secretDetectionScanner.scan(makeConfig());
    const awsFindings = findings.filter((f) => f.rawId.startsWith("secret-aws-access-key"));
    expect(awsFindings[0].evidence).not.toBe("AKIAIOSFODNN7EXAMPLE");
    expect(awsFindings[0].evidence).toContain("****");
  });

  it("skips binary files", async () => {
    const buf = Buffer.alloc(100);
    buf[0] = 0; // null byte
    writeFileSync(resolve(TEST_DIR, "binary.dat"), buf);
    const findings = await secretDetectionScanner.scan(makeConfig());
    expect(findings).toHaveLength(0);
  });

  it("returns empty when no secrets found", async () => {
    writeFileSync(resolve(TEST_DIR, "clean.js"), 'const x = 42;\n');
    const findings = await secretDetectionScanner.scan(makeConfig());
    expect(findings).toHaveLength(0);
  });

  it("includes correct location info", async () => {
    writeFileSync(
      resolve(TEST_DIR, "multi.js"),
      'const a = 1;\nconst b = 2;\nconst key = "AKIAIOSFODNN7EXAMPLE";\n',
    );
    const findings = await secretDetectionScanner.scan(makeConfig());
    const awsFindings = findings.filter((f) => f.rawId.startsWith("secret-aws-access-key"));
    expect(awsFindings[0].location.startLine).toBe(3);
    expect(awsFindings[0].location.path).toBe("multi.js");
  });

  it("reports correct category and tool", async () => {
    writeFileSync(resolve(TEST_DIR, "config.js"), 'const key = "AKIAIOSFODNN7EXAMPLE";\n');
    const findings = await secretDetectionScanner.scan(makeConfig());
    expect(findings[0].tool).toBe("secret-detection");
    expect(findings[0].category).toBe("secret");
  });
});
