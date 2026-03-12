import * as core from "@actions/core";
import { formatMatrixBody } from "./format.js";

const MATRIX_LABEL = "grove-ci-matrix";

export async function updateMatrixIssue(octokit, repo, result, baseBranch) {
  const body = formatMatrixBody(result, baseBranch);
  const existing = await findMatrixIssue(octokit, repo);

  if (existing) {
    core.info(`Updating matrix issue #${existing.number}`);
    await octokit.rest.issues.update({
      ...repo,
      issue_number: existing.number,
      body,
    });
  } else {
    core.info("Creating matrix tracking issue");
    await ensureLabelExists(octokit, repo);
    const { data: issue } = await octokit.rest.issues.create({
      ...repo,
      title: `Grove Conflict Matrix — ${baseBranch}`,
      body,
      labels: [MATRIX_LABEL],
    });
    core.info(`Created matrix issue #${issue.number}`);
  }
}

async function findMatrixIssue(octokit, repo) {
  const { data: issues } = await octokit.rest.issues.listForRepo({
    ...repo,
    labels: MATRIX_LABEL,
    state: "open",
    per_page: 1,
    sort: "created",
    direction: "desc",
  });
  return issues[0] ?? null;
}

async function ensureLabelExists(octokit, repo) {
  try {
    await octokit.rest.issues.getLabel({ ...repo, name: MATRIX_LABEL });
  } catch (error) {
    if (error.status === 404) {
      await octokit.rest.issues.createLabel({
        ...repo,
        name: MATRIX_LABEL,
        color: "0e8a16",
        description: "Grove CI conflict matrix tracking issue",
      });
    }
  }
}
