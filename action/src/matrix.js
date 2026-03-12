import * as core from "@actions/core";
import { formatMatrixBody } from "./format.js";
import { withRetry } from "./retry.js";

const MATRIX_LABEL = "grove-ci-matrix";

export async function updateMatrixIssue(octokit, repo, result, baseBranch) {
  const body = formatMatrixBody(result, baseBranch);
  const existing = await findMatrixIssue(octokit, repo, baseBranch);

  if (existing) {
    core.info(`Updating matrix issue #${existing.number}`);
    await withRetry(() =>
      octokit.rest.issues.update({
        ...repo,
        issue_number: existing.number,
        body,
      }),
    );
  } else {
    core.info("Creating matrix tracking issue");
    await ensureLabelExists(octokit, repo);
    const { data: issue } = await withRetry(() =>
      octokit.rest.issues.create({
        ...repo,
        title: `Grove Conflict Matrix — ${baseBranch}`,
        body,
        labels: [MATRIX_LABEL],
      }),
    );
    core.info(`Created matrix issue #${issue.number}`);
  }
}

async function findMatrixIssue(octokit, repo, baseBranch) {
  const { data: issues } = await withRetry(() =>
    octokit.rest.issues.listForRepo({
      ...repo,
      labels: MATRIX_LABEL,
      state: "open",
      per_page: 100,
      sort: "created",
      direction: "desc",
    }),
  );
  const title = `Grove Conflict Matrix — ${baseBranch}`;
  return issues.find((issue) => issue.title === title) ?? null;
}

async function ensureLabelExists(octokit, repo) {
  try {
    await withRetry(() => octokit.rest.issues.getLabel({ ...repo, name: MATRIX_LABEL }));
  } catch (error) {
    if (error.status === 404) {
      await withRetry(() =>
        octokit.rest.issues.createLabel({
          ...repo,
          name: MATRIX_LABEL,
          color: "0e8a16",
          description: "Grove CI conflict matrix tracking issue",
        }),
      );
    } else {
      throw error;
    }
  }
}
