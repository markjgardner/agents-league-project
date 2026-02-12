import { validateHypothesis, validatePlannerResponse } from "./models.js";
import type { AttackHypothesis, PlannerResponse } from "./models.js";
import {
  isLLMPlannerEnabled,
  isTargetAllowed,
  DEFAULT_TARGET_ALLOWLIST,
  filterSafeHypotheses,
  limitHypotheses,
  sanitizeLLMOutput,
} from "./guardrails.js";
import { loadLLMPlannerConfig, DEFAULT_LLM_PLANNER_CONFIG } from "./config.js";
import type { LLMPlannerConfig } from "./config.js";
import { StubProvider } from "./provider.js";
import { LLMAttackPlanner } from "./planner.js";
import { hypothesisToFinding } from "./issues.js";
import { runStaticChecks } from "./checks.js";
import type { HypothesisCheckResult } from "./models.js";
import { writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";

// ─── Test Fixtures ───────────────────────────────────────────────────

function makeValidHypothesis(overrides?: Partial<AttackHypothesis>): AttackHypothesis {
  return {
    id: "HYPO-001",
    title: "SQL Injection in user query",
    category: "injection",
    risk: "high",
    confidence: "medium",
    rationale: "The function `queryUser` in `src/db.ts` concatenates user input directly into a SQL string.",
    evidence_to_collect: "Check if parameterized queries are used in src/db.ts",
    safe_test_plan: "Grep for string concatenation patterns in SQL query builders",
    likely_locations: ["src/db.ts:queryUser"],
    references: ["CWE-89", "OWASP A03:2021"],
    ...overrides,
  };
}

const GOLDEN_PLANNER_RESPONSE: PlannerResponse = {
  hypotheses: [
    makeValidHypothesis(),
    makeValidHypothesis({
      id: "HYPO-002",
      title: "Missing authentication on admin route",
      category: "auth-bypass",
      risk: "critical",
      confidence: "high",
      rationale: "The route `/admin` in `src/routes.ts` does not use auth middleware.",
      evidence_to_collect: "Check if auth middleware is applied to /admin route",
      safe_test_plan: "Inspect route definitions for middleware usage",
      likely_locations: ["src/routes.ts:/admin"],
      references: ["CWE-306"],
    }),
  ],
};

// ─── Schema Validation Tests ─────────────────────────────────────────

describe("validateHypothesis", () => {
  it("accepts a valid hypothesis", () => {
    const errors = validateHypothesis(makeValidHypothesis());
    expect(errors).toEqual([]);
  });

  it("rejects null input", () => {
    const errors = validateHypothesis(null);
    expect(errors).toEqual(["Hypothesis must be a non-null object"]);
  });

  it("rejects non-object input", () => {
    const errors = validateHypothesis("not an object");
    expect(errors).toEqual(["Hypothesis must be a non-null object"]);
  });

  it("rejects empty id", () => {
    const errors = validateHypothesis(makeValidHypothesis({ id: "" }));
    expect(errors).toContain("id must be a non-empty string");
  });

  it("rejects invalid risk value", () => {
    const errors = validateHypothesis(
      makeValidHypothesis({ risk: "extreme" as AttackHypothesis["risk"] }),
    );
    expect(errors).toContain("risk must be one of: critical, high, medium, low");
  });

  it("rejects invalid confidence value", () => {
    const errors = validateHypothesis(
      makeValidHypothesis({ confidence: "very-high" as AttackHypothesis["confidence"] }),
    );
    expect(errors).toContain("confidence must be one of: high, medium, low");
  });

  it("rejects empty likely_locations", () => {
    const errors = validateHypothesis(makeValidHypothesis({ likely_locations: [] }));
    expect(errors).toContain("likely_locations must be a non-empty array of strings");
  });

  it("rejects non-string items in references", () => {
    const h = makeValidHypothesis();
    (h as unknown as Record<string, unknown>).references = [123];
    const errors = validateHypothesis(h);
    expect(errors).toContain("references must contain only strings");
  });

  it("rejects missing required fields", () => {
    const errors = validateHypothesis({});
    expect(errors.length).toBeGreaterThan(0);
    expect(errors).toContain("id must be a non-empty string");
    expect(errors).toContain("title must be a non-empty string");
    expect(errors).toContain("rationale must be a non-empty string");
  });
});

describe("validatePlannerResponse", () => {
  it("accepts a valid response", () => {
    const errors = validatePlannerResponse(GOLDEN_PLANNER_RESPONSE);
    expect(errors).toEqual([]);
  });

  it("rejects missing hypotheses array", () => {
    const errors = validatePlannerResponse({});
    expect(errors).toEqual(["Response must contain a 'hypotheses' array"]);
  });

  it("rejects null response", () => {
    const errors = validatePlannerResponse(null);
    expect(errors).toEqual(["Response must be a non-null object"]);
  });

  it("reports per-hypothesis errors with index", () => {
    const response = {
      hypotheses: [makeValidHypothesis(), { id: "" }],
    };
    const errors = validatePlannerResponse(response);
    expect(errors.some((e) => e.startsWith("hypotheses[1]:"))).toBe(true);
    expect(errors.some((e) => e.startsWith("hypotheses[0]:"))).toBe(false);
  });
});

// ─── Guardrails Tests ────────────────────────────────────────────────

describe("isLLMPlannerEnabled", () => {
  it("returns false when disabled (default)", () => {
    expect(isLLMPlannerEnabled({ ...DEFAULT_LLM_PLANNER_CONFIG })).toBe(false);
  });

  it("returns true when explicitly enabled", () => {
    expect(isLLMPlannerEnabled({ ...DEFAULT_LLM_PLANNER_CONFIG, enabled: true })).toBe(true);
  });
});

describe("isTargetAllowed", () => {
  it("allows localhost targets", () => {
    expect(isTargetAllowed("http://localhost:3000", DEFAULT_TARGET_ALLOWLIST)).toBe(true);
    expect(isTargetAllowed("http://127.0.0.1:8080/path", DEFAULT_TARGET_ALLOWLIST)).toBe(true);
  });

  it("blocks external targets", () => {
    expect(isTargetAllowed("https://example.com", DEFAULT_TARGET_ALLOWLIST)).toBe(false);
    expect(isTargetAllowed("https://evil.org/admin", DEFAULT_TARGET_ALLOWLIST)).toBe(false);
  });

  it("blocks invalid URLs", () => {
    expect(isTargetAllowed("not-a-url", DEFAULT_TARGET_ALLOWLIST)).toBe(false);
  });

  it("respects custom allowlists", () => {
    expect(isTargetAllowed("http://staging.internal:8080", ["staging.internal"])).toBe(true);
  });
});

describe("filterSafeHypotheses", () => {
  it("removes hypotheses targeting external systems", () => {
    const hypotheses = [
      makeValidHypothesis({
        id: "SAFE",
        safe_test_plan: "Check localhost:3000 for missing headers",
      }),
      makeValidHypothesis({
        id: "UNSAFE",
        safe_test_plan: "Probe https://example.com/admin for auth bypass",
      }),
    ];
    const filtered = filterSafeHypotheses(hypotheses, DEFAULT_TARGET_ALLOWLIST);
    expect(filtered).toHaveLength(1);
    expect(filtered[0].id).toBe("SAFE");
  });

  it("keeps hypotheses with no URLs in test plan", () => {
    const hypotheses = [
      makeValidHypothesis({ safe_test_plan: "Grep for eval() usage in codebase" }),
    ];
    const filtered = filterSafeHypotheses(hypotheses, DEFAULT_TARGET_ALLOWLIST);
    expect(filtered).toHaveLength(1);
  });
});

describe("limitHypotheses", () => {
  it("limits to maxCount", () => {
    const hypotheses = Array.from({ length: 20 }, (_, i) =>
      makeValidHypothesis({ id: `HYPO-${i}` }),
    );
    const limited = limitHypotheses(hypotheses, 5);
    expect(limited).toHaveLength(5);
    expect(limited[0].id).toBe("HYPO-0");
  });

  it("returns all if under limit", () => {
    const hypotheses = [makeValidHypothesis()];
    const limited = limitHypotheses(hypotheses, 10);
    expect(limited).toHaveLength(1);
  });
});

describe("sanitizeLLMOutput", () => {
  it("passes through valid JSON", () => {
    const json = JSON.stringify(GOLDEN_PLANNER_RESPONSE);
    expect(sanitizeLLMOutput(json)).toBe(json);
  });

  it("redacts rm -rf commands", () => {
    const malicious = "rm -rf /important";
    expect(sanitizeLLMOutput(malicious)).toBe("[REDACTED: unsafe command]");
  });
});

// ─── Config Tests ────────────────────────────────────────────────────

describe("loadLLMPlannerConfig", () => {
  afterEach(() => {
    delete process.env.REDTEAM_LLM_ENABLED;
    delete process.env.REDTEAM_LLM_MODEL;
    delete process.env.REDTEAM_LLM_ENDPOINT;
    delete process.env.REDTEAM_LLM_KEY;
    delete process.env.REDTEAM_LLM_MAX_FILES;
    delete process.env.REDTEAM_LLM_MAX_TOKENS;
    delete process.env.REDTEAM_TARGET_ALLOWLIST;
  });

  it("returns defaults when no config or env vars", () => {
    const config = loadLLMPlannerConfig();
    expect(config.enabled).toBe(false);
    expect(config.model).toBe("gpt-4o-mini");
    expect(config.maxFiles).toBe(20);
    expect(config.targetAllowlist).toEqual(DEFAULT_TARGET_ALLOWLIST);
  });

  it("respects REDTEAM_LLM_ENABLED env var", () => {
    process.env.REDTEAM_LLM_ENABLED = "true";
    const config = loadLLMPlannerConfig();
    expect(config.enabled).toBe(true);
  });

  it("REDTEAM_LLM_ENABLED=false overrides file config", () => {
    process.env.REDTEAM_LLM_ENABLED = "false";
    const config = loadLLMPlannerConfig({ enabled: true });
    expect(config.enabled).toBe(false);
  });

  it("reads model from env var", () => {
    process.env.REDTEAM_LLM_MODEL = "gpt-4o";
    const config = loadLLMPlannerConfig();
    expect(config.model).toBe("gpt-4o");
  });

  it("reads endpoint from env var", () => {
    process.env.REDTEAM_LLM_ENDPOINT = "https://my-llm.example.com/v1";
    const config = loadLLMPlannerConfig();
    expect(config.endpoint).toBe("https://my-llm.example.com/v1");
  });

  it("reads API key from env var", () => {
    process.env.REDTEAM_LLM_KEY = "sk-test123";
    const config = loadLLMPlannerConfig();
    expect(config.apiKey).toBe("sk-test123");
  });

  it("reads target allowlist from env var", () => {
    process.env.REDTEAM_TARGET_ALLOWLIST = "localhost,staging.internal";
    const config = loadLLMPlannerConfig();
    expect(config.targetAllowlist).toEqual(["localhost", "staging.internal"]);
  });

  it("merges file config with defaults", () => {
    const config = loadLLMPlannerConfig({ maxFiles: 5, model: "custom-model" });
    expect(config.maxFiles).toBe(5);
    expect(config.model).toBe("custom-model");
    expect(config.maxTokens).toBe(4096); // default preserved
  });
});

// ─── Planner Tests ───────────────────────────────────────────────────

describe("LLMAttackPlanner", () => {
  it("returns empty when disabled", async () => {
    const provider = new StubProvider(JSON.stringify(GOLDEN_PLANNER_RESPONSE));
    const planner = new LLMAttackPlanner(provider, {
      ...DEFAULT_LLM_PLANNER_CONFIG,
      enabled: false,
    });
    const result = await planner.generateHypotheses("/tmp");
    expect(result).toEqual([]);
  });

  it("parses valid LLM response", async () => {
    const provider = new StubProvider(JSON.stringify(GOLDEN_PLANNER_RESPONSE));
    const planner = new LLMAttackPlanner(provider, {
      ...DEFAULT_LLM_PLANNER_CONFIG,
      enabled: true,
    });
    const result = await planner.generateHypotheses("/tmp");
    expect(result).toHaveLength(2);
    expect(result[0].id).toBe("HYPO-001");
    expect(result[1].id).toBe("HYPO-002");
  });

  it("handles invalid JSON from LLM gracefully", async () => {
    const provider = new StubProvider("not valid json at all");
    const planner = new LLMAttackPlanner(provider, {
      ...DEFAULT_LLM_PLANNER_CONFIG,
      enabled: true,
    });
    const result = await planner.generateHypotheses("/tmp");
    expect(result).toEqual([]);
  });

  it("handles empty hypotheses array", async () => {
    const provider = new StubProvider(JSON.stringify({ hypotheses: [] }));
    const planner = new LLMAttackPlanner(provider, {
      ...DEFAULT_LLM_PLANNER_CONFIG,
      enabled: true,
    });
    const result = await planner.generateHypotheses("/tmp");
    expect(result).toEqual([]);
  });

  it("filters out invalid hypotheses from response", async () => {
    const response = {
      hypotheses: [
        makeValidHypothesis({ id: "VALID" }),
        { id: "", title: "" }, // invalid
      ],
    };
    const provider = new StubProvider(JSON.stringify(response));
    const planner = new LLMAttackPlanner(provider, {
      ...DEFAULT_LLM_PLANNER_CONFIG,
      enabled: true,
    });
    const result = await planner.generateHypotheses("/tmp");
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("VALID");
  });

  it("respects maxHypotheses limit", async () => {
    const response = {
      hypotheses: Array.from({ length: 20 }, (_, i) =>
        makeValidHypothesis({ id: `HYPO-${i}` }),
      ),
    };
    const provider = new StubProvider(JSON.stringify(response));
    const planner = new LLMAttackPlanner(provider, {
      ...DEFAULT_LLM_PLANNER_CONFIG,
      enabled: true,
      maxHypotheses: 3,
    });
    const result = await planner.generateHypotheses("/tmp");
    expect(result).toHaveLength(3);
  });
});

// ─── "No Evidence → No Issue" Tests ──────────────────────────────────

describe("hypothesisToFinding", () => {
  it("returns null when no evidence found", () => {
    const hypothesis = makeValidHypothesis();
    const checkResult: HypothesisCheckResult = {
      hypothesisId: "HYPO-001",
      evidenceFound: false,
      details: "No evidence found",
      locations: [],
    };
    const finding = hypothesisToFinding(hypothesis, checkResult);
    expect(finding).toBeNull();
  });

  it("creates a finding when evidence is confirmed", () => {
    const hypothesis = makeValidHypothesis();
    const checkResult: HypothesisCheckResult = {
      hypothesisId: "HYPO-001",
      evidenceFound: true,
      details: "Found string concatenation in SQL query",
      locations: ["src/db.ts"],
    };
    const finding = hypothesisToFinding(hypothesis, checkResult);
    expect(finding).not.toBeNull();
    expect(finding!.title).toBe(hypothesis.title);
    expect(finding!.severity).toBe(hypothesis.risk);
    expect(finding!.tool).toBe("llm-planner");
    expect(finding!.rawId).toBe("llm-planner-HYPO-001");
  });

  it("uses first check location as finding location", () => {
    const hypothesis = makeValidHypothesis();
    const checkResult: HypothesisCheckResult = {
      hypothesisId: "HYPO-001",
      evidenceFound: true,
      details: "Evidence found",
      locations: ["src/db.ts", "src/routes.ts"],
    };
    const finding = hypothesisToFinding(hypothesis, checkResult);
    expect(finding!.location.path).toBe("src/db.ts");
  });
});

// ─── Static Checks Tests ────────────────────────────────────────────

describe("runStaticChecks", () => {
  const tmpDir = "/tmp/redteam-test-static-checks";

  beforeAll(() => {
    mkdirSync(join(tmpDir, "src"), { recursive: true });
  });

  afterAll(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("finds evidence when pattern matches in file", () => {
    writeFileSync(
      join(tmpDir, "src/db.ts"),
      `function queryUser(name: string) {
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  return db.query(sql);
}`,
    );
    const hypothesis = makeValidHypothesis({
      likely_locations: ["src/db.ts:queryUser"],
    });
    const result = runStaticChecks(hypothesis, tmpDir);
    expect(result.evidenceFound).toBe(true);
    expect(result.locations).toContain("src/db.ts");
  });

  it("returns no evidence when file does not exist", () => {
    const hypothesis = makeValidHypothesis({
      likely_locations: ["src/nonexistent.ts"],
    });
    const result = runStaticChecks(hypothesis, tmpDir);
    expect(result.evidenceFound).toBe(false);
    expect(result.locations).toHaveLength(0);
  });

  it("returns no evidence when patterns do not match", () => {
    writeFileSync(
      join(tmpDir, "src/safe.ts"),
      `function safeQuery(name: string) {
  return db.query("SELECT * FROM users WHERE name = ?", [name]);
}`,
    );
    const hypothesis = makeValidHypothesis({
      likely_locations: ["src/safe.ts"],
    });
    const result = runStaticChecks(hypothesis, tmpDir);
    expect(result.evidenceFound).toBe(false);
  });
});

// ─── Snapshot / Golden Test ──────────────────────────────────────────

describe("Golden planner response (snapshot)", () => {
  it("produces deterministic output from mocked response", async () => {
    const provider = new StubProvider(JSON.stringify(GOLDEN_PLANNER_RESPONSE));
    const planner = new LLMAttackPlanner(provider, {
      ...DEFAULT_LLM_PLANNER_CONFIG,
      enabled: true,
    });
    const hypotheses = await planner.generateHypotheses("/tmp");

    // Snapshot the structure (not deep content, just shape)
    expect(hypotheses).toMatchSnapshot();
  });

  it("golden response passes validation", () => {
    const errors = validatePlannerResponse(GOLDEN_PLANNER_RESPONSE);
    expect(errors).toEqual([]);
  });

  it("golden response hypotheses have correct IDs", () => {
    expect(GOLDEN_PLANNER_RESPONSE.hypotheses[0].id).toBe("HYPO-001");
    expect(GOLDEN_PLANNER_RESPONSE.hypotheses[1].id).toBe("HYPO-002");
  });
});
