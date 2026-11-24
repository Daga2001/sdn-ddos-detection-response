// Rows for History > Compare runs. Run with `npm run test:unit`.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  COMPARE_COLUMNS,
  formatP,
  mergeRows,
  parseCsv,
  rowsCsv,
  rowsFromCsv,
  slim,
} from "../src/compare.ts";

test("CSV fields keep quotes, commas and line breaks", () => {
  const text = 'a,b,c\r\n1,"x, y","say ""hi"""\n2,,"two\nlines"\n';
  assert.deepEqual(parseCsv(text), [
    ["a", "b", "c"],
    ["1", "x, y", 'say "hi"'],
    ["2", "", "two\nlines"],
  ]);
  assert.throws(() => parseCsv('a,"open'), /inside a quoted field/);
});

test("stacked results-row files repeat the header and still give one row per run", () => {
  const text =
    "run_id,detector,tp\nr1,rule,2\n\nrun_id,detector,tp,fp\nr2,llm,2,1\n";
  const rows = rowsFromCsv(text);
  assert.deepEqual(rows, [
    { run_id: "r1", detector: "rule", tp: "2" },
    { run_id: "r2", detector: "llm", tp: "2", fp: "1" },
  ]);
  assert.throws(() => rowsFromCsv("r1,rule\n", "x.csv"), /x.csv: this is not/);
});

test("a run added twice is counted once and only compared columns are sent", () => {
  const merged = mergeRows(
    [{ run_id: "r1", tp: "1" }],
    [
      { run_id: "r1", tp: "2" },
      { run_id: "r2", tp: "0" },
    ],
  );
  assert.equal(merged.length, 2);
  assert.equal(merged[0].tp, "2");
  const small = slim({ run_id: "r1", tp: "2", prompt_sha256: "abc" });
  assert.equal(Object.keys(small).length, COMPARE_COLUMNS.length);
  assert.equal(small.tp, "2");
  assert.equal(small.fn, "");
  assert.ok(!("prompt_sha256" in small));
  const csv = rowsCsv([{ run_id: "r1", validity_notes: 'a, "b"' }]);
  assert.equal(csv.split("\n")[0], COMPARE_COLUMNS.join(","));
  assert.ok(csv.includes('"a, ""b"""'));
});

test("p-values print like the report", () => {
  assert.equal(formatP(0.0000123), "<0.001");
  assert.equal(formatP(0.061), "0.061");
  assert.equal(formatP(0.4912), "0.491");
  assert.equal(formatP(1), "1");
});
