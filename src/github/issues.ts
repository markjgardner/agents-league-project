import { Octokit } from "@octokit/rest";
import { Finding, DedupResult, IssueResult, RedTeamConfig, Severity } from "../types.js";
import { createOctokit } from "./labels.js";
import { logger } from "../utils/logger.js";
import { getPersona, Persona } from "../persona.js";

// ─── Fingerprint marker embedded in issue body ───────────────────────

const FINGERPRINT_PREFIX = "<!-- redteam-fingerprint:";
const FINGERPRINT_SUFFIX = " -->";
const FINGERPRINT_REGEX = /<!-- redteam-fingerprint:([a-f0-9]{64}) -->/;

// ─── Issue Body Template ─────────────────────────────────────────────

function buildIssueBody(finding: Finding, persona?: Persona): string {
  const tone = persona ?? getPersona("default");
  const locationStr = finding.location.startLine
    ? `\`${finding.location.path}:${finding.location.startLine}\``
    : `\`${finding.location.path}\``;

  // Mask evidence for secret findings to avoid leaking sensitive data
  const safeEvidence =
    finding.category === "secret"
      ? maskSecret(finding.evidence)
      : finding.evidence;

  const refs =
    finding.references.length > 0
      ? finding.references.map((r) => `- ${r}`).join("\n")
      : "_None_";

  const opening = tone.openingParagraph(finding);
  const openingBlock = opening ? `\n${opening}\n` : "";
  const funFact = tone.funFact(finding);
  const funFactBlock = funFact ? `\n${funFact}` : "";
  const closing = tone.closingLine(finding);

  return `${FINGERPRINT_PREFIX}${finding.fingerprint}${FINGERPRINT_SUFFIX}
${openingBlock}
## ${finding.title}

| Field | Value |
|-------|-------|
| **Severity** | \`${finding.severity}\` |
| **Confidence** | \`${finding.confidence}\` |
| **Tool** | \`${finding.tool}\` |
| **Category** | \`${finding.category}\` |
| **Location** | ${locationStr} |

${tone.evidenceHeader()}

\`\`\`
${safeEvidence}
\`\`\`

${tone.remediationHeader()}

${finding.remediation}

### References

${refs}
${funFactBlock}
---
*Filed by RedTeam Agent • Finding ID: \`${finding.id}\` • Fingerprint: \`${finding.fingerprint.slice(0, 12)}\`*
${closing}
`;
}

/**
 * Mask a secret value, showing only first 4 and last 4 characters.
 * If the value is ≤ 8 chars, mask everything.
 */
function maskSecret(evidence: string): string {
  if (evidence.length <= 8) {
    return "*".repeat(evidence.length);
  }
  return evidence.slice(0, 4) + "*".repeat(evidence.length - 8) + evidence.slice(-4);
}

// ─── Search existing issues by fingerprint ───────────────────────────

/**
 * Fetch all open issues with "redteam-agent" label and extract fingerprints.
 * Returns a Map of fingerprint → issue number.
 *
 * Uses pagination to handle repos with many security issues.
 */
export async function fetchExistingIssuesByFingerprint(
  config: RedTeamConfig,
): Promise<Map<string, number>> {
  const octokit = createOctokit(config);
  const { owner, repo } = config.github;
  const fingerprints = new Map<string, number>();

  // Paginate through all open issues with our label
  // When a demoLabel is set, also filter by that label so demo issues
  // don't collide with real issues (and vice versa).
  const labelFilter = config.issues.demoLabel
    ? `redteam-agent,${config.issues.demoLabel}`
    : "redteam-agent";
  const iterator = octokit.paginate.iterator(octokit.issues.listForRepo, {
    owner,
    repo,
    labels: labelFilter,
    state: "open",
    per_page: 100,
  });

  for await (const response of iterator) {
    for (const issue of response.data) {
      // Skip pull requests (the issues endpoint includes them)
      if (issue.pull_request) continue;

      const body = issue.body ?? "";
      const match = FINGERPRINT_REGEX.exec(body);
      if (match) {
        fingerprints.set(match[1], issue.number);
      }
    }
  }

  logger.info("Fetched existing issues", { count: fingerprints.size });
  return fingerprints;
}

// ─── Create a new issue ──────────────────────────────────────────────

/**
 * Create a single GitHub Issue for a finding.
 * Applies labels: security, redteam-agent, severity:<level>, + any extras.
 */
export async function createIssueForFinding(
  finding: Finding,
  config: RedTeamConfig,
): Promise<IssueResult> {
  const octokit = createOctokit(config);
  const { owner, repo } = config.github;
  const persona = getPersona(config.persona);

  const labels = [
    "security",
    "redteam-agent",
    `severity:${finding.severity}`,
    ...config.issues.extraLabels,
    ...(config.issues.demoLabel ? [config.issues.demoLabel] : []),
  ];

  const response = await octokit.issues.create({
    owner,
    repo,
    title: persona.issueTitle(finding),
    body: buildIssueBody(finding, persona),
    labels,
    assignees: config.issues.assignees,
  });

  logger.info("Created issue", {
    issueNumber: response.data.number,
    fingerprint: finding.fingerprint.slice(0, 12),
  });

  return {
    issueNumber: response.data.number,
    issueUrl: response.data.html_url,
    action: "created",
    finding,
  };
}

// ─── Close a resolved issue ─────────────────────────────────────────

/**
 * Close an issue that is no longer backed by an active finding.
 * Adds a comment explaining why it was auto-closed.
 */
export async function closeResolvedIssue(
  issueNumber: number,
  config: RedTeamConfig,
): Promise<IssueResult> {
  const octokit = createOctokit(config);
  const { owner, repo } = config.github;

  await octokit.issues.createComment({
    owner,
    repo,
    issue_number: issueNumber,
    body:
      "✅ **Auto-closed by RedTeam Agent**\n\n" +
      "This finding is no longer detected in the latest scan. " +
      "If this was closed in error, please reopen.",
  });

  await octokit.issues.update({
    owner,
    repo,
    issue_number: issueNumber,
    state: "closed",
    state_reason: "completed",
  });

  logger.info("Closed resolved issue", { issueNumber });

  return {
    issueNumber,
    issueUrl: `https://github.com/${owner}/${repo}/issues/${issueNumber}`,
    action: "closed",
  };
}

// ─── Orchestrator: process all dedup results ─────────────────────────

/**
 * Process a DedupResult: create new issues, skip existing ones,
 * and optionally close resolved ones.
 *
 * Respects `config.issues.maxPerRun` to prevent spam.
 */
export async function processIssues(
  dedupResult: DedupResult,
  config: RedTeamConfig,
): Promise<IssueResult[]> {
  const results: IssueResult[] = [];
  let created = 0;

  // 1. Create issues for new findings (respecting rate limit)
  const sortedNew = sortBySeverity(dedupResult.newFindings);
  for (const finding of sortedNew) {
    if (created >= config.issues.maxPerRun) {
      logger.warn("Reached maxPerRun limit, skipping remaining findings", {
        maxPerRun: config.issues.maxPerRun,
        remaining: sortedNew.length - created,
      });
      break;
    }

    try {
      const result = await createIssueForFinding(finding, config);
      results.push(result);
      created++;
    } catch (err: unknown) {
      logger.error("Failed to create issue", {
        fingerprint: finding.fingerprint.slice(0, 12),
        error: err instanceof Error ? err.message : String(err),
      });
      // Continue with remaining findings instead of aborting
    }
  }

  // 2. Log skipped (existing) findings
  for (const { finding, issueNumber } of dedupResult.existingFindings) {
    results.push({
      issueNumber,
      issueUrl: `https://github.com/${config.github.owner}/${config.github.repo}/issues/${issueNumber}`,
      action: "skipped",
      finding,
    });
  }

  // 3. Close resolved issues if auto-close is enabled
  if (config.issues.autoClose) {
    for (const issueNumber of dedupResult.resolvedIssueNumbers) {
      try {
        const result = await closeResolvedIssue(issueNumber, config);
        results.push(result);
      } catch (err: unknown) {
        logger.error("Failed to close issue", {
          issueNumber,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  return results;
}

// ─── Helpers ─────────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Sort findings by severity (critical first) for issue creation priority */
function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
}

export { buildIssueBody, maskSecret, FINGERPRINT_REGEX };
