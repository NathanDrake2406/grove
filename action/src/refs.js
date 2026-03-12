import * as core from "@actions/core";
import * as exec from "@actions/exec";
import { withRetry } from "./retry.js";

export async function fetchPrRefs(octokit, repo, baseBranch, maxBranches) {
  core.info(`Listing open PRs targeting '${baseBranch}'`);

  const prs = await withRetry(() =>
    octokit.paginate(octokit.rest.pulls.list, {
      ...repo,
      base: baseBranch,
      state: "open",
      sort: "updated",
      direction: "desc",
      per_page: 100,
    }),
  );

  const selected = prs.slice(0, maxBranches);
  core.info(`Found ${prs.length} open PRs, analyzing ${selected.length}`);

  core.info(`Fetching base branch '${baseBranch}'`);
  await exec.exec("git", ["fetch", "origin", `refs/heads/${baseBranch}:refs/heads/${baseBranch}`]);

  const fetched = [];
  for (const pr of selected) {
    const localRef = `refs/remotes/origin/pr/${pr.number}`;
    const remoteRef = `refs/pull/${pr.number}/head`;
    core.info(`Fetching ${remoteRef} → ${localRef}`);
    const exitCode = await exec.exec("git", ["fetch", "origin", `${remoteRef}:${localRef}`], {
      ignoreReturnCode: true,
    });
    if (exitCode !== 0) {
      core.warning(`Failed to fetch PR #${pr.number} — skipping`);
      continue;
    }
    fetched.push(pr);
  }

  return fetched;
}

export function buildRefSpecs(prs) {
  return prs.map((pr) => {
    const ref = `refs/remotes/origin/pr/${pr.number}`;
    const label = `PR #${pr.number} (${pr.head.ref})`;
    return `${ref}=${label}`;
  });
}
