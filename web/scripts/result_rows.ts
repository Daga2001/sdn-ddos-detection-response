// The Results tab's one-row-per-run CSV, built without a browser.
//
// The unattended campaign (scripts/campaign/lab_campaign.py --records DIR) saves every
// run as {run, events}. This script scores each record with exactly the code of the
// Results tab (src/results.ts), so a row here is the row the tab would download, and
// stacks the rows under one header for scripts/compare_runs.py.
//
//   cd web && node --experimental-strip-types scripts/result_rows.ts \
//       ../records/held_out/*.json > ../held_out_rows.csv
//
// Without Node on the machine, the same with Docker from the repository root:
//   docker run --rm -v "$PWD":/w -w /w/web node:24-bookworm-slim \
//       node --experimental-strip-types scripts/result_rows.ts ../records/held_out/*.json
import { readFileSync } from "node:fs";
import { resultRow, runResults } from "../src/results.ts";
import { normalizeExperiment } from "../src/types.ts";
import type { Observation, Run } from "../src/types.ts";

const quote = (text: string) =>
  /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;

const files = process.argv.slice(2);
if (!files.length) {
  process.stderr.write("usage: result_rows.ts RECORD.json [RECORD.json ...]\n");
  process.exit(2);
}

let header: string[] | null = null;
let skipped = 0;
for (const file of files) {
  const { run, events } = JSON.parse(readFileSync(file, "utf-8")) as {
    run: Run;
    events: Observation[];
  };
  const sorted = [...events].sort(
    (a, b) => Date.parse(a.ts) - Date.parse(b.ts) || a.seq - b.seq,
  );
  const experiment = run?.settings ? normalizeExperiment(run.settings) : null;
  const results = runResults({
    events: sorted,
    topology: run?.topology ?? null,
    experiment: experiment?.attackers.length ? experiment : null,
    run,
    active: false,
  });
  if (!results) {
    process.stderr.write(`${file}: no attack recorded, no row\n`);
    skipped++;
    continue;
  }
  const row = resultRow(results);
  const names = row.map(([name]) => name);
  if (header === null) {
    header = names;
    process.stdout.write(header.map(quote).join(",") + "\n");
  } else if (names.join(",") !== header.join(",")) {
    // Detectors have different columns; repeat the header, compare_runs reads it.
    header = names;
    process.stdout.write(header.map(quote).join(",") + "\n");
  }
  process.stdout.write(row.map(([, value]) => quote(value)).join(",") + "\n");
}
if (skipped) process.stderr.write(`${skipped} record(s) without a row\n`);
