#!/usr/bin/env node

"use strict";

const { spawnSync } = require("child_process");
const path = require("path");

const PLATFORM_PACKAGES = {
  "darwin-arm64": "@nathan2406/grove-darwin-arm64",
  "darwin-x64": "@nathan2406/grove-darwin-x64",
  "linux-arm64": "@nathan2406/grove-linux-arm64",
  "linux-x64": "@nathan2406/grove-linux-x64",
};

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORM_PACKAGES[key];

if (!pkg) {
  console.error(
    `Unsupported platform: ${process.platform}-${process.arch}\n` +
      `Grove supports: ${Object.keys(PLATFORM_PACKAGES).join(", ")}`,
  );
  process.exit(1);
}

let binaryPath;
try {
  const pkgDir = path.dirname(require.resolve(`${pkg}/package.json`));
  binaryPath = path.join(pkgDir, "bin", "grove");
} catch {
  console.error(
    `Could not find the Grove binary package for your platform (${key}).\n\n` +
      `Expected package: ${pkg}\n\n` +
      `This usually means the optional dependency was not installed.\n` +
      `Try reinstalling: npm install -g @nathan2406/grove`,
  );
  process.exit(1);
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
});

if (result.error) {
  if (result.error.code === "EACCES") {
    console.error(
      `Permission denied when trying to run Grove binary.\n` +
        `Try: chmod +x "${binaryPath}"`,
    );
  } else {
    console.error(`Failed to run Grove: ${result.error.message}`);
  }
  process.exit(1);
}

if (result.status === null && result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status ?? 1);
