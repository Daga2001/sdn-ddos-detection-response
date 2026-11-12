// Unit tests for the building blocks of the evaluation metrics. Run with `npm run test:unit`.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Experiment, Observation, Topology } from "../src/types.ts";
import { emptyExperiment, phaseSpans } from "../src/types.ts";
import {
  attackerDetectionOffsets,
  calibration,
  flowDecisions,
  victimRecovery,
} from "../src/evaluation.ts";
import { checkSeries } from "../src/traffic.ts";

const at = (second: number) =>
  new Date(Date.UTC(2026, 0, 1, 0, 0, 0) + second * 1000).toISOString();
let seq = 0;
function ev(second: number, kind: string, data: Record<string, any> = {}) {
  return {
    run_id: "r",
    seq: ++seq,
    ts: at(second),
    kind,
    data: { observed_at: at(second), ...data },
  } as Observation;
}

const names = ["a1", "a2", "v1", "v2", "c1", "c2"];
const ip = (name: string) => `10.0.0.${names.indexOf(name) + 1}`;
const topology: Topology = {
  version: 1,
  name: "t",
  description: "",
  switches: [{ name: "s1", dpid: 1, position: { x: 0, y: 0 } }],
  hosts: names.map((name) => ({
    name,
    ip: `${ip(name)}/24`,
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
  attackers: ["a1", "a2"],
  victims: ["v1"],
  confirm_isolated_lab: true,
};

// baseline 0-30 s, attack 30-60 s, recovery 60-120 s
function phases() {
  return [
    ev(0, "phase", { state: "baseline" }),
    ev(30, "phase", { state: "attack" }),
    ev(30, "attack_started", {}),
    ev(60, "attack_stopped", {}),
    ev(60, "phase", { state: "recovery" }),
    ev(120, "phase", { state: "completed" }),
  ];
}

function flows(second: number, rows: Record<string, any>[]) {
  return ev(second, "flows", { dpid: 1, rows });
}

test("calibration is 0 for perfect probabilities and matches hand values", () => {
  const perfect = calibration([
    [1, 1],
    [0, 0],
  ]);
  assert.equal(perfect.brier, 0);
  assert.equal(perfect.ece, 0);
  const half = calibration([
    [0.8, 1],
    [0.8, 0],
  ]);
  assert.ok(Math.abs((half.brier ?? 0) - 0.34) < 1e-9);
  // One bin holding p = 0.8 with half of the cases positive: |0.5 - 0.8| = 0.3.
  assert.ok(Math.abs((half.ece ?? 0) - 0.3) < 1e-9);
  assert.deepEqual(calibration([]), { brier: null, ece: null, n: 0 });
  // p = 1 falls in the last bin, not past it.
  assert.equal(calibration([[1, 0]]).ece, 1);
});

test("detection time counts each attacker once, from the attack start", () => {
  const events = [
    ...phases(),
    ev(10, "detection", { ipv4_src: ip("a1") }), // before the attack: ignored
    ev(35, "detection", { ipv4_src: ip("a1") }),
    ev(40, "detection", { ipv4_src: ip("a1") }),
    // entropy candidates and a response are evidence too
    ev(48, "detection", { candidates: [ip("c1")] }),
    ev(50, "mitigation_requested", { ipv4_src: ip("a2") }),
  ];
  const timing = attackerDetectionOffsets(events, topology, experiment);
  assert.equal(timing.total, 2);
  assert.deepEqual(timing.offsets, [5, 20]);
});

test("flow decisions follow the experiment's roles and phases", () => {
  const events = [
    ...phases(),
    flows(10, [
      { ipv4_src: ip("a1"), prob_ddos: 0.1, label: 0 }, // attacker idle: TN
      { ipv4_src: ip("c1"), prob_ddos: 0.9, label: 1 }, // FP
    ]),
    flows(40, [
      { ipv4_src: ip("a1"), prob_ddos: 0.95, label: 1 }, // TP
      { ipv4_src: ip("a2"), prob_ddos: 0.3, label: 0 }, // FN
      { ipv4_src: ip("c2"), prob_ddos: 0.05, label: 0 }, // TN
      { ipv4_src: ip("v1"), prob_ddos: 0.9, label: 1 }, // victim: skipped
      { ipv4_src: ip("c2"), prob_ddos: null, label: 0 }, // not judged: ignored
    ]),
    flows(70, [{ ipv4_src: ip("a1"), prob_ddos: 0.9, label: 1 }]), // skipped
  ];
  const spans = phaseSpans(events, Date.parse(at(120)));
  const result = flowDecisions(events, topology, experiment, spans);
  assert.equal(result.tp, 1);
  assert.equal(result.fn, 1);
  assert.equal(result.fp, 1);
  assert.equal(result.tn, 2);
  assert.equal(result.skipped, 2);
  assert.equal(result.scored.length, 5);
});

test("several victims recover when the last one does (equation 9)", () => {
  const check = (second: number, target: string, ok = true) =>
    ev(second, "service", {
      target,
      success: ok,
      http_code: ok ? 200 : 0,
      latency_ms: ok ? 10 : null,
      connect_ms: 1,
    });
  const events = [
    ...phases(),
    ...Array.from({ length: 12 }, (_, i) => check(i, "v1")),
    ...Array.from({ length: 12 }, (_, i) => check(i, "v2")),
    ...Array.from({ length: 12 }, (_, i) => check(61 + i, "v1")),
    check(61, "v2", false),
    check(62, "v2", false),
    ...Array.from({ length: 12 }, (_, i) => check(65 + i, "v2")),
  ];
  const spans = phaseSpans(events, Date.parse(at(120)));
  const tStop = Date.parse(at(60));
  const result = victimRecovery(
    checkSeries(events),
    ["v1", "v2"],
    spans,
    tStop,
    Date.parse(at(120)),
  );
  assert.deepEqual(
    result.perVictim.map((item) => item.seconds),
    [1, 5],
  );
  assert.equal(result.overall, "5 s");

  const stuck = victimRecovery(
    checkSeries(
      events.filter((e) => !(e.data.target === "v2" && e.ts > at(60))),
    ),
    ["v1", "v2"],
    spans,
    tStop,
    Date.parse(at(120)),
  );
  assert.match(stuck.overall, /not recovered within 60 s/);
});
