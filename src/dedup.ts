import { Finding, DedupResult, RedTeamConfig } from "./types.js";
import { fetchExistingIssuesByFingerprint } from "./github/issues.js";
import { logger } from "./utils/logger.js";

/**
 * Deduplicate findings against open GitHub Issues.
 *
 * Strategy:
 * 1. Fetch all open issues with "redteam-agent" label
 * 2. Extract fingerprint from each issue body (HTML comment)
 * 3. Partition current findings into:
 *    - newFindings: no matching open issue
 *    - existingFindings: matched by fingerprint to an open issue
 * 4. Identify resolvedIssueNumbers: open issues whose fingerprints
 *    are NOT in the current scan results (finding resolved)
 */
export async function deduplicate(
  findings: Finding[],
  config: RedTeamConfig,
): Promise<DedupResult> {
  // Build a set of current fingerprints for O(1) lookup
  const currentFingerprints = new Set(findings.map((f) => f.fingerprint));

  // Fetch existing issue fingerprints from GitHub
  const existingIssues = await fetchExistingIssuesByFingerprint(config);

  const newFindings: Finding[] = [];
  const existingFindings: Array<{ finding: Finding; issueNumber: number }> = [];

  for (const finding of findings) {
    const issueNumber = existingIssues.get(finding.fingerprint);
    if (issueNumber !== undefined) {
      existingFindings.push({ finding, issueNumber });
    } else {
      newFindings.push(finding);
    }
  }

  // Issues whose fingerprints are no longer in the current scan
  const resolvedIssueNumbers: number[] = [];
  for (const [fingerprint, issueNumber] of existingIssues) {
    if (!currentFingerprints.has(fingerprint)) {
      resolvedIssueNumbers.push(issueNumber);
    }
  }

  logger.info("Dedup complete", {
    totalRaw: findings.length,
    new: newFindings.length,
    existing: existingFindings.length,
    resolved: resolvedIssueNumbers.length,
  });

  return {
    newFindings,
    existingFindings,
    resolvedIssueNumbers,
    totalRaw: findings.length,
  };
}
