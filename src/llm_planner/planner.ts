// ─── LLM Attack Planner ──────────────────────────────────────────────

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { LLMProvider, LLMProviderConfig } from "./provider.js";
import type { LLMPlannerConfig } from "./config.js";
import type { AttackHypothesis, PlannerResponse } from "./models.js";
import { validatePlannerResponse } from "./models.js";
import { isLLMPlannerEnabled, filterSafeHypotheses, limitHypotheses, sanitizeLLMOutput } from "./guardrails.js";
import { PLANNER_SYSTEM_PROMPT, buildUserPrompt } from "./prompt.js";
import { logger } from "../utils/logger.js";

/** File extensions likely to contain security-relevant code */
const SECURITY_RELEVANT_EXTENSIONS = new Set([
  ".ts", ".js", ".cjs", ".mjs",
  ".py", ".rb", ".go", ".java",
  ".json", ".yaml", ".yml", ".toml",
  ".env", ".cfg", ".conf", ".ini",
]);

/** Directory names commonly containing security-relevant code */
const PRIORITY_DIRS = new Set([
  "routes", "controllers", "auth", "middleware",
  "api", "db", "database", "config", "src",
  "lib", "server", "handlers", "services",
]);

/** Files/dirs to always exclude from scanning */
const EXCLUDE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "coverage",
  ".next", "__pycache__", "vendor", ".venv",
]);

/**
 * LLMAttackPlanner reads the repository structure and selected files,
 * sends them to an LLM provider, and returns structured hypotheses.
 */
export class LLMAttackPlanner {
  private provider: LLMProvider;
  private config: LLMPlannerConfig;

  constructor(provider: LLMProvider, config: LLMPlannerConfig) {
    this.provider = provider;
    this.config = config;
  }

  /**
   * Generate attack hypotheses for the given repository.
   * Returns an empty array if the LLM planner is disabled.
   */
  async generateHypotheses(repoRoot: string): Promise<AttackHypothesis[]> {
    if (!isLLMPlannerEnabled(this.config)) {
      logger.info("LLM planner is disabled, skipping hypothesis generation");
      return [];
    }

    logger.info("LLM planner: collecting repo structure", { repoRoot });

    // 1. Collect repo structure
    const repoStructure = this.collectRepoStructure(repoRoot);

    // 2. Select security-relevant files
    const files = this.selectFiles(repoRoot);
    logger.info("LLM planner: selected files for analysis", {
      count: files.length,
      files: files.map((f) => f.path),
    });

    // 3. Build prompts
    const userPrompt = buildUserPrompt(repoStructure, files);

    // 4. Call LLM provider
    const providerConfig: LLMProviderConfig = {
      model: this.config.model,
      endpoint: this.config.endpoint,
      apiKey: this.config.apiKey,
      maxTokens: this.config.maxTokens,
      timeoutMs: this.config.timeoutMs,
    };

    logger.info("LLM planner: calling provider", {
      provider: this.provider.name,
      model: this.config.model,
    });

    const result = await this.provider.complete(
      [
        { role: "system", content: PLANNER_SYSTEM_PROMPT },
        { role: "user", content: userPrompt },
      ],
      providerConfig,
    );

    if (result.usage) {
      logger.info("LLM planner: token usage", result.usage);
    }

    // 5. Parse and validate response
    const sanitized = sanitizeLLMOutput(result.content);
    let parsed: PlannerResponse;
    try {
      parsed = JSON.parse(sanitized) as PlannerResponse;
    } catch {
      logger.error("LLM planner: failed to parse response as JSON");
      return [];
    }

    const errors = validatePlannerResponse(parsed);
    if (errors.length > 0) {
      logger.warn("LLM planner: validation errors in response", { errors });
      // Filter out invalid hypotheses but keep valid ones
      parsed.hypotheses = (parsed.hypotheses ?? []).filter(
        (h) => validatePlannerResponse({ hypotheses: [h] }).length === 0,
      );
    }

    // 6. Apply safety filters
    let hypotheses = filterSafeHypotheses(
      parsed.hypotheses,
      this.config.targetAllowlist,
    );
    hypotheses = limitHypotheses(hypotheses, this.config.maxHypotheses);

    logger.info("LLM planner: generated hypotheses", {
      total: parsed.hypotheses.length,
      afterFilters: hypotheses.length,
    });

    return hypotheses;
  }

  /**
   * Collect a tree-style listing of the repository structure.
   */
  collectRepoStructure(rootDir: string, prefix = "", depth = 3): string {
    if (depth <= 0) return "";
    const lines: string[] = [];

    try {
      const entries = readdirSync(rootDir, { withFileTypes: true })
        .filter((e) => !e.name.startsWith(".") && !EXCLUDE_DIRS.has(e.name))
        .sort((a, b) => {
          // Directories first
          if (a.isDirectory() && !b.isDirectory()) return -1;
          if (!a.isDirectory() && b.isDirectory()) return 1;
          return a.name.localeCompare(b.name);
        });

      for (const entry of entries) {
        lines.push(`${prefix}${entry.name}${entry.isDirectory() ? "/" : ""}`);
        if (entry.isDirectory()) {
          const sub = this.collectRepoStructure(
            join(rootDir, entry.name),
            prefix + "  ",
            depth - 1,
          );
          if (sub) lines.push(sub);
        }
      }
    } catch {
      // Permission or access error — skip
    }

    return lines.join("\n");
  }

  /**
   * Select the most security-relevant files to send to the LLM.
   * Prioritizes routes, controllers, auth, config, and database files.
   */
  selectFiles(rootDir: string): Array<{ path: string; content: string }> {
    const files: Array<{ path: string; size: number }> = [];
    this.walkDir(rootDir, rootDir, files);

    // Sort: priority directories first, then by size (smaller first for more variety)
    files.sort((a, b) => {
      const aPriority = this.isInPriorityDir(a.path) ? 0 : 1;
      const bPriority = this.isInPriorityDir(b.path) ? 0 : 1;
      if (aPriority !== bPriority) return aPriority - bPriority;
      return a.size - b.size;
    });

    // Take top N files
    const selected = files.slice(0, this.config.maxFiles);

    // Read file contents
    return selected.map((f) => {
      try {
        const fullPath = join(rootDir, f.path);
        const content = readFileSync(fullPath, "utf-8");
        // Truncate very large files to avoid token limits
        return { path: f.path, content: content.slice(0, 8192) };
      } catch {
        return { path: f.path, content: "[Could not read file]" };
      }
    });
  }

  private walkDir(
    dir: string,
    rootDir: string,
    result: Array<{ path: string; size: number }>,
  ): void {
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name.startsWith(".") || EXCLUDE_DIRS.has(entry.name)) continue;
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          this.walkDir(fullPath, rootDir, result);
        } else if (entry.isFile()) {
          const dotIndex = entry.name.lastIndexOf(".");
          const ext = dotIndex > 0 ? entry.name.slice(dotIndex) : "";
          if (ext && SECURITY_RELEVANT_EXTENSIONS.has(ext)) {
            const stat = statSync(fullPath);
            if (stat.size < 100_000) {
              // Skip very large files
              result.push({
                path: relative(rootDir, fullPath),
                size: stat.size,
              });
            }
          }
        }
      }
    } catch {
      // Permission error — skip
    }
  }

  private isInPriorityDir(filePath: string): boolean {
    const parts = filePath.split("/");
    return parts.some((p) => PRIORITY_DIRS.has(p.toLowerCase()));
  }
}
