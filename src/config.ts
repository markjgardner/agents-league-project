import { RedTeamConfig, Severity } from "./types.js";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_CONFIG_PATH = "redteam.config.json";

const DEFAULT_CONFIG: RedTeamConfig = {
  repoRoot: ".",
  github: { owner: "", repo: "", token: "" },
  scanners: {
    npmAudit: { enabled: true, minSeverity: "medium" as Severity },
    secretDetection: {
      enabled: true,
      include: ["**/*"],
      exclude: ["node_modules/**", ".git/**", "*.lock", "dist/**"],
      customPatterns: {},
    },
    httpScan: {
      enabled: false,
      target: "http://localhost:3000",
      paths: ["/", "/.env", "/.git/config", "/debug", "/api"],
    },
  },
  issues: {
    enabled: true,
    extraLabels: [],
    maxPerRun: 10,
    assignees: [],
    autoClose: false,
  },
};

export function loadConfig(overridePath?: string): RedTeamConfig {
  const configPath = resolve(overridePath ?? DEFAULT_CONFIG_PATH);
  let fileConfig: Record<string, unknown> = {};

  if (existsSync(configPath)) {
    fileConfig = JSON.parse(readFileSync(configPath, "utf-8")) as Record<string, unknown>;
  }

  // Auto-detect owner/repo from GITHUB_REPOSITORY env var
  const [envOwner = "", envRepo = ""] = (
    process.env.GITHUB_REPOSITORY ?? "/"
  ).split("/");

  const github = (fileConfig.github ?? {}) as Record<string, string>;
  const issues = (fileConfig.issues ?? {}) as Record<string, unknown>;

  return {
    repoRoot:
      (process.env.REDTEAM_REPO_ROOT as string) ??
      (fileConfig.repoRoot as string) ??
      DEFAULT_CONFIG.repoRoot,
    github: {
      owner: github.owner || envOwner,
      repo: github.repo || envRepo,
      token: process.env.GITHUB_TOKEN ?? "",
    },
    scanners: deepMerge(
      DEFAULT_CONFIG.scanners,
      (fileConfig.scanners as Record<string, unknown>) ?? {},
    ) as RedTeamConfig["scanners"],
    issues: {
      enabled: (issues.enabled as boolean) ?? DEFAULT_CONFIG.issues.enabled,
      extraLabels:
        (issues.extraLabels as string[]) ?? DEFAULT_CONFIG.issues.extraLabels,
      maxPerRun:
        (issues.maxPerRun as number) ?? DEFAULT_CONFIG.issues.maxPerRun,
      assignees:
        (issues.assignees as string[]) ?? DEFAULT_CONFIG.issues.assignees,
      autoClose:
        (issues.autoClose as boolean) ?? DEFAULT_CONFIG.issues.autoClose,
      demoLabel:
        process.env.DEMO_ISSUE_LABEL ||
        (issues.demoLabel as string | undefined) ||
        undefined,
    },
  };
}

function deepMerge(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
): Record<string, unknown> {
  const result: Record<string, unknown> = { ...target };
  for (const key of Object.keys(source)) {
    if (
      typeof source[key] === "object" &&
      source[key] !== null &&
      !Array.isArray(source[key]) &&
      typeof target[key] === "object" &&
      target[key] !== null &&
      !Array.isArray(target[key])
    ) {
      result[key] = deepMerge(
        target[key] as Record<string, unknown>,
        source[key] as Record<string, unknown>,
      );
    } else {
      result[key] = source[key];
    }
  }
  return result;
}
