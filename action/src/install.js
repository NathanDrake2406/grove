import * as core from "@actions/core";
import * as tc from "@actions/tool-cache";
import * as http from "@actions/http-client";
import path from "path";
import fs from "fs";

const REPO_OWNER = "NathanDrake2406";
const REPO_NAME = "grove";

export async function installGrove(version) {
  const tag = await resolveVersion(version);
  core.info(`Installing grove ${tag}`);

  const target = resolveTarget();
  const archiveName = `grove-${tag}-${target}.tar.gz`;
  const url = `https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download/${tag}/${archiveName}`;

  core.info(`Downloading ${url}`);
  const archivePath = await tc.downloadTool(url);
  const extracted = await tc.extractTar(archivePath);

  const stem = `grove-${tag}-${target}`;
  const binaryPath = path.join(extracted, stem, "grove");

  if (!fs.existsSync(binaryPath)) {
    throw new Error(`Binary not found at expected path: ${binaryPath}`);
  }

  fs.chmodSync(binaryPath, 0o755);
  const cachedDir = await tc.cacheDir(path.dirname(binaryPath), "grove", tag.replace(/^v/, ""));
  const cachedBinary = path.join(cachedDir, "grove");
  core.addPath(cachedDir);
  core.info(`grove ${tag} installed to ${cachedBinary}`);
  return cachedBinary;
}

async function resolveVersion(version) {
  if (version !== "latest") {
    return version.startsWith("v") ? version : `v${version}`;
  }

  const client = new http.HttpClient("grove-action");
  const url = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest`;
  const response = await client.getJson(url);

  if (response.statusCode !== 200 || !response.result?.tag_name) {
    throw new Error(`Failed to resolve latest grove version (status ${response.statusCode})`);
  }

  core.info(`Resolved 'latest' to ${response.result.tag_name}`);
  return response.result.tag_name;
}

function resolveTarget() {
  const platform = process.platform;
  const arch = process.arch;

  const targets = {
    "linux-x64": "x86_64-unknown-linux-gnu",
    "linux-arm64": "aarch64-unknown-linux-gnu",
    "darwin-x64": "x86_64-apple-darwin",
    "darwin-arm64": "aarch64-apple-darwin",
  };

  const key = `${platform}-${arch}`;
  const target = targets[key];
  if (!target) {
    throw new Error(`Unsupported platform: ${key}`);
  }
  return target;
}
