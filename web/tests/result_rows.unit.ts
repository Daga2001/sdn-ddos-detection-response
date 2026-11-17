// The headless row builder gives the Results tab's row. Run with `npm run test:unit`.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { resultRowCsv, runResults } from "../src/results.ts";
import { emptyExperiment } from "../src/types.ts";
import type { Experiment, Observation, Topology } from "../src/types.ts";

const at = (second: number) =>
  new Date(Date.UTC(2026, 0, 1) + second * 1000).toISOString();
let seq = 0;
const ev = (second: number, kind: string, data: Record<string, any> = {}) =>
  ({
    run_id: "11111111-2222-4333-8444-555555555555",
    seq: ++seq,
    ts: at(second),
    kind,
    data: { observed_at: at(second), ...data },
  }) as Observation;

const names = ["a1", "v1", "c1"];
const topology: Topology = {
  version: 1,
  name: "t",
  description: "",
  switches: [{ name: "s1", dpid: 1, position: { x: 0, y: 0 } }],
  hosts: names.map((name, index) => ({
    name,
    ip: `10.0.0.${index + 1}/24`,
    position: { x: 0, y: 0 },
  })),
  links: names.map((host) => ({
    id: `link-${host}`,
    source: "s1",
    target: host,
    bandwidth_mbps: null,
    delay_ms: 0,
    loss_percent: 0,
  })),
};
const experiment: Experiment = {
  ...emptyExperiment,
  attackers: ["a1"],
  victims: ["v1"],
  confirm_isolated_lab: true,
  purpose: "held_out",
  scenario: "TC-3",
};
const events = [
  ev(1, "detection_config", {
    mode: "rule",
    rule_pktrate: 50,
    poll_seconds: 1,
  }),
  ev(2, "phase", { state: "baseline" }),
  ev(30, "phase", { state: "attack" }),
  ev(30, "attack_started", {}),
  ev(33, "detection", { ipv4_src: "10.0.0.1", probability: 1 }),
  ev(60, "attack_stopped", {}),
  ev(60, "phase", { state: "recovery" }),
  ev(120, "phase", { state: "completed" }),
];
const run = {
  id: "11111111-2222-4333-8444-555555555555",
  status: "completed",
  settings: experiment,
  topology,
};

test("a saved record gives the same row as the Results tab", () => {
  const dir = mkdtempSync(join(tmpdir(), "rows-"));
  const file = join(dir, "run.json");
  // The campaign saves events in arrival order; the script sorts them.
  writeFileSync(file, JSON.stringify({ run, events: [...events].reverse() }));
  const csv = execFileSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--no-warnings",
      "scripts/result_rows.ts",
      file,
    ],
    { encoding: "utf-8" },
  );
  const expected = runResults({
    events,
    topology,
    experiment,
    run,
    active: false,
  });
  assert.ok(expected);
  assert.equal(csv.trim(), resultRowCsv(expected));
  assert.match(csv, /held_out/);
  assert.match(csv, /TC-3/);
});
