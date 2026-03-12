import * as core from "@actions/core";
import * as exec from "@actions/exec";

export async function runAnalysis(grovePath, inputs, refSpecs) {
  const args = ["ci", "analyze", "--base", inputs.baseBranch, "--refs-from-stdin"];

  args.push("--timeout", String(inputs.timeout));

  if (inputs.disableLayers) {
    for (const layer of inputs.disableLayers.split(",")) {
      const trimmed = layer.trim();
      if (trimmed) {
        args.push("--disable-layer", trimmed);
      }
    }
  }

  const stdin = refSpecs.join("\n") + "\n";
  let stdout = "";
  let stderr = "";

  core.info(`Running: ${grovePath} ${args.join(" ")}`);
  core.info(`Stdin refs:\n${stdin.trimEnd()}`);

  const exitCode = await exec.exec(grovePath, args, {
    input: Buffer.from(stdin),
    listeners: {
      stdout: (data) => { stdout += data.toString(); },
      stderr: (data) => { stderr += data.toString(); },
    },
    silent: true,
  });

  if (exitCode !== 0) {
    core.error(`grove stderr:\n${stderr}`);
    throw new Error(`grove ci analyze failed with exit code ${exitCode}`);
  }

  if (stderr) {
    core.warning(`grove stderr:\n${stderr}`);
  }

  const result = JSON.parse(stdout);
  core.info(`Analysis complete: ${result.pairs?.length ?? 0} pairs, ${result.refs?.length ?? 0} refs`);
  return result;
}
