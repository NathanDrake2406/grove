const MARKER = "<!-- grove-ci -->";

const SCORE_EMOJI = {
  green: "\u{1F7E2}",
  yellow: "\u{1F7E1}",
  red: "\u{1F534}",
  black: "\u{26AB}",
};

const SCORE_LABEL = {
  green: "Clean",
  yellow: "Caution",
  red: "Conflict",
  black: "Critical",
};

export { MARKER };

function sanitize(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function formatPrComment(prNumber, prs, result) {
  const prLabel = labelForPr(prs, prNumber);
  const relevantPairs = result.pairs.filter(
    (p) => p.a === prLabel || p.b === prLabel,
  );

  const conflictPairs = relevantPairs.filter(
    (p) => p.score && p.score !== "green",
  );
  const timedOutPairs = relevantPairs.filter((p) => p.timed_out);
  const hasConflicts = conflictPairs.length > 0 || timedOutPairs.length > 0;

  const lines = [MARKER, "## Grove Conflict Report", ""];

  if (!hasConflicts) {
    lines.push(
      "No conflicts detected with other open PRs.",
      "",
    );
    if (relevantPairs.length > 0) {
      lines.push(
        `Analyzed against ${relevantPairs.length} open ${relevantPairs.length === 1 ? "PR" : "PRs"} — all clear.`,
      );
    }

    // Show merge order warnings even for clean PRs
    if (result.merge_order && result.merge_order.status !== "complete") {
      lines.push(...formatMergeOrder(result.merge_order));
    }

    return { body: lines.join("\n"), hasConflicts: false };
  }

  if (conflictPairs.length > 0) {
    lines.push(
      `Found potential conflicts with **${conflictPairs.length}** open ${conflictPairs.length === 1 ? "PR" : "PRs"}:`,
      "",
    );

    lines.push("| PR | Severity | Overlaps |");
    lines.push("|:---|:---------|:---------|");

    for (const pair of conflictPairs) {
      const other = pair.a === prLabel ? pair.b : pair.a;
      const otherPr = prs.find((p) => labelForPr(prs, p.number) === other);
      const prLink = otherPr
        ? `[${sanitize(other)}](${otherPr.html_url})`
        : sanitize(other);
      const emoji = SCORE_EMOJI[pair.score] ?? "";
      const label = SCORE_LABEL[pair.score] ?? pair.score;
      const overlapSummary = summarizeOverlaps(pair.overlaps);
      lines.push(`| ${prLink} | ${emoji} ${label} | ${overlapSummary} |`);
    }

    lines.push("");

    for (const pair of conflictPairs) {
      if (pair.overlaps.length === 0) continue;
      const other = pair.a === prLabel ? pair.b : pair.a;
      lines.push(...formatPairDetails(sanitize(other), pair));
    }
  }

  if (timedOutPairs.length > 0) {
    lines.push(
      `> **\u{26A0}\u{FE0F} ${timedOutPairs.length} ${timedOutPairs.length === 1 ? "pair" : "pairs"} timed out** — analysis was incomplete for:`,
      "",
    );
    for (const pair of timedOutPairs) {
      const other = pair.a === prLabel ? pair.b : pair.a;
      lines.push(`> - ${sanitize(other)}`);
    }
    lines.push("");
  }

  lines.push(...formatMergeOrder(result.merge_order));
  lines.push("", "---", `*Updated by [Grove](https://github.com/NathanDrake2406/grove)*`);

  return { body: lines.join("\n"), hasConflicts: true };
}

export function formatMatrixBody(result, baseBranch) {
  const lines = [
    MARKER,
    `## Grove Conflict Matrix — \`${sanitize(baseBranch)}\``,
    "",
  ];

  if (result.pairs.length === 0) {
    lines.push("No pairs to analyze.");
    return lines.join("\n");
  }

  const conflictPairs = result.pairs.filter(
    (p) => p.score && p.score !== "green",
  );
  const timedOutPairs = result.pairs.filter((p) => p.timed_out);

  if (conflictPairs.length === 0 && timedOutPairs.length === 0) {
    lines.push(
      `All **${result.pairs.length}** PR pairs are conflict-free.`,
    );
    lines.push(...formatMergeOrder(result.merge_order));
    lines.push("", "---", `*Updated by [Grove](https://github.com/NathanDrake2406/grove)*`);
    return lines.join("\n");
  }

  if (conflictPairs.length > 0) {
    lines.push(
      `**${conflictPairs.length}** of ${result.pairs.length} PR pairs have potential conflicts:`,
      "",
    );

    lines.push("| PR A | PR B | Severity | Overlaps |");
    lines.push("|:-----|:-----|:---------|:---------|");

    for (const pair of conflictPairs) {
      const emoji = SCORE_EMOJI[pair.score] ?? "";
      const label = SCORE_LABEL[pair.score] ?? pair.score;
      const overlapSummary = summarizeOverlaps(pair.overlaps);
      lines.push(`| ${sanitize(pair.a)} | ${sanitize(pair.b)} | ${emoji} ${label} | ${overlapSummary} |`);
    }

    lines.push("");

    for (const pair of conflictPairs) {
      if (pair.overlaps.length === 0) continue;
      lines.push(...formatPairDetails(`${sanitize(pair.a)} \u{2194} ${sanitize(pair.b)}`, pair));
    }
  }

  if (timedOutPairs.length > 0) {
    lines.push(
      `> **\u{26A0}\u{FE0F} ${timedOutPairs.length} ${timedOutPairs.length === 1 ? "pair" : "pairs"} timed out:**`,
      "",
    );
    for (const pair of timedOutPairs) {
      lines.push(`> - ${sanitize(pair.a)} \u{2194} ${sanitize(pair.b)}`);
    }
    lines.push("");
  }

  lines.push(...formatMergeOrder(result.merge_order));

  if (result.skipped?.length > 0) {
    lines.push("", "### Skipped Refs", "");
    for (const s of result.skipped) {
      lines.push(`- \`${sanitize(s.ref)}\`: ${sanitize(s.reason)}`);
    }
  }

  lines.push("", "---", `*Updated by [Grove](https://github.com/NathanDrake2406/grove)*`);
  return lines.join("\n");
}

function summarizeOverlaps(overlaps) {
  if (!overlaps || overlaps.length === 0) return "\u{2014}";
  const counts = {};
  for (const o of overlaps) {
    counts[o.type] = (counts[o.type] ?? 0) + 1;
  }
  return Object.entries(counts)
    .map(([type, count]) => `${count} ${type}`)
    .join(", ");
}

function formatPairDetails(heading, pair) {
  const lines = [
    `<details>`,
    `<summary><strong>${heading}</strong> \u{2014} ${pair.overlaps.length} ${pair.overlaps.length === 1 ? "overlap" : "overlaps"}</summary>`,
    "",
  ];

  for (const o of pair.overlaps) {
    lines.push(formatOverlap(o));
  }

  lines.push("", "</details>", "");
  return lines;
}

function formatOverlap(o) {
  switch (o.type) {
    case "file":
      return `- **File** \`${sanitize(o.path)}\` \u{2014} ${sanitize(o.a_change)} / ${sanitize(o.b_change)}`;
    case "hunk":
      return `- **Hunk** \`${sanitize(o.path)}\` lines ${o.a_range[0]}\u{2013}${o.a_range[1]} \u{2229} ${o.b_range[0]}\u{2013}${o.b_range[1]} (${o.overlap_lines} lines)`;
    case "symbol":
      return `- **Symbol** \`${sanitize(o.symbol)}\` in \`${sanitize(o.path)}\` \u{2014} ${sanitize(o.a_modification)} / ${sanitize(o.b_modification)}`;
    case "dependency":
      return `- **Dependency** \`${sanitize(o.changed_export)}\` in \`${sanitize(o.changed_file)}\` (changed in ${sanitize(o.changed_in)}) \u{2192} imported by \`${sanitize(o.affected_file)}\``;
    case "schema":
      return `- **Schema** \`${sanitize(o.a_file)}\` / \`${sanitize(o.b_file)}\` \u{2014} ${sanitize(o.detail)}`;
    default:
      return `- **${sanitize(o.type)}** ${sanitize(JSON.stringify(o))}`;
  }
}

function formatMergeOrder(mergeOrder) {
  if (!mergeOrder) return [];

  const lines = ["", "### Suggested Merge Order", ""];

  if (mergeOrder.status !== "complete") {
    const warnings = {
      cycle: "Dependency cycle detected \u{2014} this order is an arbitrary fallback, not a reliable topological sort.",
      partial: "Some pairs timed out \u{2014} this order may be incomplete.",
      unavailable: "Too many pairs timed out to compute a meaningful order.",
    };
    lines.push(`> **\u{26A0}\u{FE0F} ${warnings[mergeOrder.status] ?? `Status: ${mergeOrder.status}`}**`, "");
  }

  if (mergeOrder.status === "unavailable") return lines;

  if (mergeOrder.sequenced?.length > 0) {
    mergeOrder.sequenced.forEach((ref, i) => {
      lines.push(`${i + 1}. ${sanitize(ref)}`);
    });
  }

  if (mergeOrder.independent?.length > 0) {
    lines.push("", "**Independent** (merge in any order):");
    for (const ref of mergeOrder.independent) {
      lines.push(`- ${sanitize(ref)}`);
    }
  }

  if (mergeOrder.cycle_note) {
    lines.push("", `> ${sanitize(mergeOrder.cycle_note)}`);
  }

  if (mergeOrder.incomplete_pairs?.length > 0) {
    lines.push("", "**Incomplete pairs** (timed out):");
    for (const p of mergeOrder.incomplete_pairs) {
      lines.push(`- ${sanitize(p.a)} \u{2194} ${sanitize(p.b)}`);
    }
  }

  return lines;
}

function labelForPr(prs, prNumber) {
  const pr = prs.find((p) => p.number === prNumber);
  if (!pr) return `PR #${prNumber}`;
  return `PR #${pr.number} (${pr.head.ref})`;
}
