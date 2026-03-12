import * as core from "@actions/core";
import * as github from "@actions/github";
import { installGrove } from "./install.js";
import { fetchPrRefs, buildRefSpecs } from "./refs.js";
import { runAnalysis } from "./analyze.js";
import { postPrComment } from "./comment.js";
import { updateMatrixIssue } from "./matrix.js";

async function run() {
  const token = core.getInput("github-token", { required: true });
  const octokit = github.getOctokit(token);
  const { context } = github;

  const maxBranches = parseInt(core.getInput("max-branches"), 10);
  if (Number.isNaN(maxBranches) || maxBranches < 1) {
    core.setFailed("'max-branches' must be a positive integer");
    return;
  }

  const timeout = parseInt(core.getInput("timeout"), 10);
  if (Number.isNaN(timeout) || timeout < 1) {
    core.setFailed("'timeout' must be a positive integer");
    return;
  }

  const inputs = {
    baseBranch: core.getInput("base-branch"),
    disableLayers: core.getInput("disable-layers"),
    commentOnClean: core.getInput("comment-on-clean") === "true",
    groveVersion: core.getInput("grove-version"),
    maxBranches,
    timeout,
  };

  const grovePath = await installGrove(inputs.groveVersion);

  const prs = await fetchPrRefs(octokit, context.repo, inputs.baseBranch, inputs.maxBranches);
  if (prs.length < 2) {
    core.info("Fewer than 2 open PRs targeting the base branch — nothing to analyze");
    return;
  }

  const refSpecs = buildRefSpecs(prs);
  const result = await runAnalysis(grovePath, inputs, refSpecs);

  const eventName = context.eventName;
  if (eventName === "pull_request") {
    const prNumber = context.payload.pull_request?.number;
    if (!prNumber) {
      core.setFailed("Could not determine triggering PR number");
      return;
    }
    await postPrComment(octokit, context.repo, prNumber, prs, result, inputs.commentOnClean);
  } else if (eventName === "schedule" || eventName === "workflow_dispatch") {
    await updateMatrixIssue(octokit, context.repo, result, inputs.baseBranch);
  } else {
    core.warning(`Unsupported event '${eventName}' — skipping comment/issue posting`);
  }

  core.setOutput("result", JSON.stringify(result));
}

run().catch((error) => {
  core.setFailed(error.message);
});
