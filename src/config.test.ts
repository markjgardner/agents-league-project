import { loadConfig } from "./config.js";
import { existsSync, writeFileSync, unlinkSync } from "node:fs";
import { resolve } from "node:path";

describe("loadConfig", () => {
  const testConfigPath = resolve("/tmp/test-redteam-config.json");

  afterEach(() => {
    // Clean up test config file
    if (existsSync(testConfigPath)) {
      unlinkSync(testConfigPath);
    }
    // Clean up env vars
    delete process.env.GITHUB_REPOSITORY;
    delete process.env.GITHUB_TOKEN;
    delete process.env.REDTEAM_REPO_ROOT;
  });

  it("returns defaults when no config file exists", () => {
    const config = loadConfig("/tmp/nonexistent-config.json");
    expect(config.repoRoot).toBe(".");
    expect(config.scanners.npmAudit.enabled).toBe(true);
    expect(config.scanners.secretDetection.enabled).toBe(true);
    expect(config.scanners.httpScan.enabled).toBe(false);
    expect(config.issues.maxPerRun).toBe(10);
  });

  it("reads github owner/repo from GITHUB_REPOSITORY env var", () => {
    process.env.GITHUB_REPOSITORY = "octocat/hello-world";
    const config = loadConfig("/tmp/nonexistent-config.json");
    expect(config.github.owner).toBe("octocat");
    expect(config.github.repo).toBe("hello-world");
  });

  it("reads GITHUB_TOKEN from env", () => {
    process.env.GITHUB_TOKEN = "ghp_test123";
    const config = loadConfig("/tmp/nonexistent-config.json");
    expect(config.github.token).toBe("ghp_test123");
    delete process.env.GITHUB_TOKEN;
  });

  it("merges file config with defaults", () => {
    writeFileSync(
      testConfigPath,
      JSON.stringify({
        scanners: {
          httpScan: {
            enabled: true,
            target: "http://localhost:8080",
          },
        },
        issues: { maxPerRun: 5 },
      }),
    );
    const config = loadConfig(testConfigPath);
    expect(config.scanners.httpScan.enabled).toBe(true);
    expect(config.scanners.httpScan.target).toBe("http://localhost:8080");
    expect(config.issues.maxPerRun).toBe(5);
    // Defaults preserved
    expect(config.scanners.npmAudit.enabled).toBe(true);
  });

  it("file config owner/repo overrides env", () => {
    process.env.GITHUB_REPOSITORY = "env-owner/env-repo";
    writeFileSync(
      testConfigPath,
      JSON.stringify({
        github: { owner: "file-owner", repo: "file-repo" },
      }),
    );
    const config = loadConfig(testConfigPath);
    expect(config.github.owner).toBe("file-owner");
    expect(config.github.repo).toBe("file-repo");
  });
});
