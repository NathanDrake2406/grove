import * as core from "@actions/core";
import { MARKER, formatPrComment } from "./format.js";
import { withRetry } from "./retry.js";

export async function postPrComment(octokit, repo, prNumber, prs, result, commentOnClean) {
  const { body, hasConflicts } = formatPrComment(prNumber, prs, result);

  if (!hasConflicts && !commentOnClean) {
    core.info(`No conflicts for PR #${prNumber} and comment-on-clean is false — skipping comment`);
    await deleteExistingComment(octokit, repo, prNumber);
    return;
  }

  const existing = await findExistingComment(octokit, repo, prNumber);

  if (existing) {
    core.info(`Updating existing comment ${existing.id} on PR #${prNumber}`);
    await withRetry(() =>
      octokit.rest.issues.updateComment({
        ...repo,
        comment_id: existing.id,
        body,
      }),
    );
  } else {
    core.info(`Posting new comment on PR #${prNumber}`);
    await withRetry(() =>
      octokit.rest.issues.createComment({
        ...repo,
        issue_number: prNumber,
        body,
      }),
    );
  }
}

async function findExistingComment(octokit, repo, prNumber) {
  const comments = await withRetry(() =>
    octokit.paginate(octokit.rest.issues.listComments, {
      ...repo,
      issue_number: prNumber,
      per_page: 100,
    }),
  );

  return comments.find((c) => c.body?.includes(MARKER));
}

async function deleteExistingComment(octokit, repo, prNumber) {
  const existing = await findExistingComment(octokit, repo, prNumber);
  if (existing) {
    core.info(`Deleting stale grove comment ${existing.id} on PR #${prNumber}`);
    await withRetry(() =>
      octokit.rest.issues.deleteComment({
        ...repo,
        comment_id: existing.id,
      }),
    );
  }
}
