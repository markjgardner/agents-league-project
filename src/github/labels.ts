import { Octokit } from "@octokit/rest";
import { RedTeamConfig } from "../types.js";
import { logger } from "../utils/logger.js";

/**
 * Labels the RedTeam agent requires. Created idempotently on each run.
 * "redteam-agent" label is always applied so issues can be filtered.
 */
const REQUIRED_LABELS: Array<{
  name: string;
  color: string;
  description: string;
}> = [
  { name: "security", color: "d73a4a", description: "Security finding" },
  { name: "redteam-agent", color: "5319e7", description: "Filed by RedTeam Agent" },
  { name: "severity:critical", color: "b60205", description: "Critical severity" },
  { name: "severity:high", color: "d93f0b", description: "High severity" },
  { name: "severity:medium", color: "fbca04", description: "Medium severity" },
  { name: "severity:low", color: "0e8a16", description: "Low severity" },
];

/**
 * Creates an authenticated Octokit instance from config.
 * Throws if GITHUB_TOKEN is missing.
 */
export function createOctokit(config: RedTeamConfig): Octokit {
  if (!config.github.token) {
    throw new Error(
      "GITHUB_TOKEN is required. Set it via environment variable or .env file.",
    );
  }
  return new Octokit({ auth: config.github.token });
}

/**
 * Ensure all required labels exist in the target repository.
 * Uses GET-then-POST pattern: tries to fetch each label, creates if 404.
 */
export async function ensureLabels(config: RedTeamConfig): Promise<void> {
  const octokit = createOctokit(config);
  const { owner, repo } = config.github;

  for (const label of REQUIRED_LABELS) {
    try {
      await octokit.issues.getLabel({ owner, repo, name: label.name });
      logger.debug("Label already exists", { label: label.name });
    } catch (err: unknown) {
      if (isOctokitError(err) && err.status === 404) {
        await octokit.issues.createLabel({
          owner,
          repo,
          name: label.name,
          color: label.color,
          description: label.description,
        });
        logger.info("Created label", { label: label.name });
      } else {
        // Re-throw unexpected errors (403, 500, etc.)
        throw err;
      }
    }
  }

  // Also ensure any user-configured extra labels exist
  for (const extra of config.issues.extraLabels) {
    try {
      await octokit.issues.getLabel({ owner, repo, name: extra });
    } catch (err: unknown) {
      if (isOctokitError(err) && err.status === 404) {
        await octokit.issues.createLabel({
          owner,
          repo,
          name: extra,
          color: "c5def5",
          description: "Custom RedTeam label",
        });
        logger.info("Created extra label", { label: extra });
      } else {
        throw err;
      }
    }
  }

  // Ensure the demo label exists when in demo mode
  if (config.issues.demoLabel) {
    const demoLabel = config.issues.demoLabel;
    try {
      await octokit.issues.getLabel({ owner, repo, name: demoLabel });
    } catch (err: unknown) {
      if (isOctokitError(err) && err.status === 404) {
        await octokit.issues.createLabel({
          owner,
          repo,
          name: demoLabel,
          color: "e4e669",
          description: "Demo/example run — safe to bulk-close",
        });
        logger.info("Created demo label", { label: demoLabel });
      } else {
        throw err;
      }
    }
  }
}

/** Type guard for Octokit HTTP errors */
function isOctokitError(err: unknown): err is { status: number; message: string } {
  return typeof err === "object" && err !== null && "status" in err;
}

export { REQUIRED_LABELS };
