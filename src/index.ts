import { loadConfig } from "./config.js";
import { normalize } from "./normalizer.js";
import { deduplicate } from "./dedup.js";
import { processIssues } from "./github/issues.js";
import { ensureLabels } from "./github/labels.js";
import { logger } from "./utils/logger.js";
import { DEMO_ISSUE_LABEL } from "./constants.js";
import type { Scanner, Finding, RawFinding, IssueResult } from "./types.js";
import {
  LLMAttackPlanner,
  StubProvider,
  OpenAICompatibleProvider,
  isLLMPlannerEnabled,
  runStaticChecks,
  hypothesisToFinding,
} from "./llm_planner/index.js";
import type { LLMPlannerConfig } from "./llm_planner/index.js";

async function main(): Promise<void> {
  const noIssues = process.argv.includes("--no-issues");
  const jsonOutput = process.argv.includes("--json");
  const demoMode = process.argv.includes("--demo");
  const configPath = getArgValue("--config");

  const config = loadConfig(configPath);

  // --demo flag activates demo mode: applies DEMO_ISSUE_LABEL to all created issues
  if (demoMode && !config.issues.demoLabel) {
    config.issues.demoLabel = DEMO_ISSUE_LABEL;
  }

  if (noIssues) {
    config.issues.enabled = false;
  }

  // 1. Dynamically import scanners (they're optional modules)
  const scanners: Scanner[] = [];

  try {
    const { npmAuditScanner } = await import("./scanners/npm-audit.js");
    scanners.push(npmAuditScanner);
  } catch { /* scanner not implemented yet */ }

  try {
    const { secretDetectionScanner } = await import("./scanners/secret-detection.js");
    scanners.push(secretDetectionScanner);
  } catch { /* scanner not implemented yet */ }

  try {
    const { httpScanScanner } = await import("./scanners/http-scan.js");
    scanners.push(httpScanScanner);
  } catch { /* scanner not implemented yet */ }

  // 2. Run available scanners
  const allRaw: RawFinding[] = [];
  for (const scanner of scanners) {
    if (scanner.isAvailable(config)) {
      logger.info("Running scanner", { scanner: scanner.name });
      const findings = await scanner.scan(config);
      allRaw.push(...findings);
    }
  }

  // 2b. Run LLM planner stage (optional — behind feature flag)
  if (config.llmPlanner && isLLMPlannerEnabled(config.llmPlanner)) {
    logger.info("LLM planner stage enabled, generating hypotheses");
    const plannerConfig = config.llmPlanner as LLMPlannerConfig;
    const provider = plannerConfig.apiKey
      ? new OpenAICompatibleProvider()
      : new StubProvider("{}");
    const planner = new LLMAttackPlanner(provider, plannerConfig);

    try {
      const hypotheses = await planner.generateHypotheses(config.repoRoot);
      logger.info("LLM planner: checking hypotheses", { count: hypotheses.length });

      for (const hypothesis of hypotheses) {
        const checkResult = runStaticChecks(hypothesis, config.repoRoot);
        const finding = hypothesisToFinding(
          hypothesis,
          checkResult,
          config.issues.demoLabel,
        );
        if (finding) {
          allRaw.push(finding);
          logger.info("LLM planner: evidence confirmed for hypothesis", {
            id: hypothesis.id,
            title: hypothesis.title,
          });
        } else {
          logger.info("LLM planner: no evidence for hypothesis, skipping", {
            id: hypothesis.id,
          });
        }
      }
    } catch (err: unknown) {
      logger.error("LLM planner stage failed", {
        error: err instanceof Error ? err.message : String(err),
      });
      // Continue with deterministic scanner results
    }
  }

  // 3. Normalize → Finding[] with fingerprints
  const findings: Finding[] = normalize(allRaw);
  logger.info("Normalized findings", { count: findings.length });

  // 4. If issues disabled, output JSON and exit
  if (!config.issues.enabled) {
    if (jsonOutput) {
      process.stdout.write(JSON.stringify(findings, null, 2) + "\n");
    } else {
      logger.info("Issue creation disabled", { findings: findings.length });
    }
    return;
  }

  // 5. Deduplicate against existing GitHub Issues
  const dedup = await deduplicate(findings, config);

  // 6. Ensure labels exist, then create/update/close issues
  await ensureLabels(config);
  const results: IssueResult[] = await processIssues(dedup, config);

  if (jsonOutput) {
    process.stdout.write(JSON.stringify(results, null, 2) + "\n");
  } else {
    for (const r of results) {
      logger.info(`Issue ${r.action}`, {
        issueNumber: r.issueNumber,
        url: r.issueUrl,
      });
    }
  }
}

function getArgValue(flag: string): string | undefined {
  const idx = process.argv.indexOf(flag);
  if (idx !== -1 && idx + 1 < process.argv.length) {
    return process.argv[idx + 1];
  }
  return undefined;
}

main().catch((err) => {
  logger.error("Fatal error", { error: err instanceof Error ? err.message : String(err) });
  process.exit(1);
});
