// Unit tests for the detection results maths. Run with `npm run test:unit`.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  analyzeDetection,
  computeMetrics,
  detectionSteps,
  flaggedAddresses,
  percent,
  retainEvents,
  liveLimit,
  describeRun,
} from "../src/detection.ts";
import type { Experiment, Observation, Topology } from "../src/types.ts";
import { emptyExperiment } from "../src/types.ts";

const topology: Topology = {
  version: 1,
  name: "t",
  description: "",
  switches: [{ name: "s1", dpid: 1, position: { x: 0, y: 0 } }],
  hosts: [
    ["a1", 1],
    ["a2", 2],
    ["v", 3],
    ["c1", 4],
    ["c2", 5],
    ["c3", 6],
  ].map(([name, n]) => ({
    name: name as string,
    ip: `10.0.0.${n}/24`,
    position: { x: 0, y: 0 },
  })),
  links: ["a1", "a2", "v", "c1", "c2", "c3"].map((h) => ({
    id: `link-${h}`,
    source: "s1",
    target: h,
    bandwidth_mbps: null,
    delay_ms: 0,
    loss_percent: 0,
  })),
};
const experiment: Experiment = {
  ...emptyExperiment,
  attackers: ["a1", "a2"],
  victims: ["v"],
  confirm_isolated_lab: true,
};

let seq = 0;
const at = (second: number) =>
  new Date(Date.UTC(2026, 0, 1, 0, 0, second)).toISOString();
function ev(second: number, kind: string, data: Record<string, any> = {}) {
  return { run_id: "r", seq: ++seq, ts: at(second), kind, data } as Observation;
}
const phases = [
  ev(0, "phase", { state: "baseline" }),
  ev(30, "phase", { state: "attack" }),
  ev(30, "attack_started", {}),
  ev(90, "attack_stopped", {}),
  ev(90, "phase", { state: "recovery" }),
  ev(120, "phase", { state: "completed" }),
];

test("host level confusion matrix: VP, FN, FP and VN", () => {
  const events = [
    ...phases,
    ev(38, "detection", {
      ipv4_src: "10.0.0.1",
      probability: 0.98,
      threshold: 0.8,
    }),
    ev(40, "detection", { ipv4_src: "10.0.0.1", probability: 0.9 }),
    ev(45, "detection", { ipv4_src: "10.0.0.4", probability: 0.85 }), // legit c1
  ];
  const result = analyzeDetection(events, topology, experiment, false);
  assert.deepEqual(result.confusion, { vp: 1, fn: 1, fp: 1, vn: 2 });
  const row = (name: string) => result.hosts.find((h) => h.name === name)!;
  assert.equal(row("a1").verdict, "VP");
  assert.equal(row("a1").detections, 2);
  assert.equal(row("a1").firstOffsetS, 8);
  assert.equal(row("a1").maxProbability, 0.98);
  assert.equal(row("a2").verdict, "FN");
  assert.equal(row("c1").verdict, "FP");
  assert.equal(row("c2").verdict, "VN");
  assert.equal(row("v").verdict, null);
  assert.equal(result.threshold, 0.8);
  assert.equal(result.firstDetectionS, 8);
  assert.equal(result.allDetectedS, null); // a2 was never detected
  assert.equal(result.metrics.precision, 0.5);
  assert.equal(result.metrics.recall, 0.5);
  assert.ok(Math.abs(result.metrics.falsePositiveRate! - 1 / 3) < 1e-9);
  assert.ok(Math.abs(result.metrics.accuracy! - 0.6) < 1e-9);
});

test("an attacker's verdict stays open while the attack is still going", () => {
  const live = [
    ev(0, "phase", { state: "baseline" }),
    ev(30, "phase", { state: "attack" }),
  ];
  const result = analyzeDetection(live, topology, experiment, true);
  assert.equal(result.attackOver, false);
  assert.equal(result.confusion.fn, 0);
  assert.equal(result.hosts.find((h) => h.name === "a1")!.verdict, null);
  assert.equal(result.metrics.recall, null);
});

test("entropy candidates count as detections and every attacker can be caught", () => {
  const events = [
    ...phases,
    ev(41, "detection", {
      ipv4_src: "10.0.0.1",
      candidates: ["10.0.0.1", "10.0.0.2"],
      detector: "entropy",
    }),
  ];
  const result = analyzeDetection(events, topology, experiment, false);
  assert.deepEqual(result.confusion, { vp: 2, fn: 0, fp: 0, vn: 3 });
  assert.equal(result.allDetectedS, 11);
  assert.deepEqual(
    flaggedAddresses({ ipv4_src: "a", candidates: ["a", "b"] }),
    ["a", "b"],
  );
});

test("an entropy alarm does not invent a probability threshold", () => {
  const events = [
    ...phases,
    ev(41, "detection", {
      ipv4_src: "10.0.0.1",
      candidates: ["10.0.0.1"],
      detector: "entropy",
      threshold: 1,
    }),
  ];
  assert.equal(
    analyzeDetection(events, topology, experiment, false).threshold,
    null,
  );
});

test("the victim and unknown addresses are reported apart", () => {
  const events = [
    ...phases,
    ev(40, "detection", { ipv4_src: "10.0.0.3" }),
    ev(41, "detection", { ipv4_src: "192.168.9.9" }),
  ];
  const result = analyzeDetection(events, topology, experiment, false);
  assert.deepEqual(result.victimFlagged, ["v"]);
  assert.deepEqual(result.unknownFlagged, ["192.168.9.9"]);
  assert.equal(result.confusion.fp, 0); // neither enters the matrix
});

test("responses, collateral, service by phase and load toward the victim", () => {
  const link = (second: number, kbps: number) =>
    ev(second, "links", {
      links: [{ link_id: "link-v", rates: { rx_bps: 5, tx_bps: kbps * 1000 } }],
    });
  const events = [
    ...phases,
    link(10, 2),
    link(35, 500),
    link(60, 20),
    link(80, 1),
    ev(10, "service", { success: true, latency_ms: 100 }),
    ev(50, "service", { success: false, latency_ms: null }),
    ev(60, "service", { success: true, latency_ms: 300 }),
    ev(100, "service", { success: true, latency_ms: 50 }),
    ev(38, "detection", { ipv4_src: "10.0.0.1" }),
    ev(40, "mitigation_requested", {
      ipv4_src: "10.0.0.1",
      action: "rate_limit_50pps",
    }),
    ev(41, "mitigation_requested", { ipv4_src: "10.0.0.5" }),
    ev(110, "controller", { cpu_percent: 12.5, rss_bytes: 104857600 }),
  ];
  const result = analyzeDetection(events, topology, experiment, false);
  assert.deepEqual(
    result.responses.map((r) => [r.host, r.action, r.onAttacker, r.offsetS]),
    [
      ["a1", "rate_limit_50pps", true, 10],
      ["c2", "temporary_drop", false, 11],
    ],
  );
  assert.deepEqual(result.collateral, ["c2"]);
  assert.equal(result.service.baseline.ok, 1);
  assert.equal(result.service.attack.probes, 2);
  assert.equal(result.service.attack.meanLatencyMs, 300);
  assert.equal(result.service.recovery.ok, 1);
  assert.equal(result.load.baselineKbps, 2);
  assert.equal(result.load.attackPeakKbps, 500);
  assert.equal(result.load.attackMeanKbps, (500 + 20 + 1) / 3);
  assert.equal(result.load.afterResponseKbps, (20 + 1) / 2); // from 10 s after the response
  assert.equal(result.controller.cpuMax, 12.5);
  assert.equal(result.controller.ramMaxMiB, 100);
});

test("attackers picked in the form do not score anything before a run", () => {
  const idle = analyzeDetection([], topology, experiment, false);
  assert.equal(idle.hasExperiment, false);
  assert.deepEqual(idle.confusion, { vp: 0, fn: 0, fp: 0, vn: 0 });
  // A run that stopped before the attack started never produces a false negative.
  const early = [
    ev(0, "phase", { state: "baseline" }),
    ev(5, "phase", { state: "stopped" }),
  ];
  const result = analyzeDetection(early, topology, experiment, false);
  assert.equal(result.attackOver, false);
  assert.equal(result.confusion.fn, 0);
});

test("without an experiment there is nothing to score", () => {
  const result = analyzeDetection(
    [ev(0, "phase", { state: "running" })],
    topology,
    null,
    true,
  );
  assert.equal(result.hasExperiment, false);
  assert.deepEqual(result.confusion, { vp: 0, fn: 0, fp: 0, vn: 0 });
  assert.equal(result.metrics.accuracy, null);
});

test("metrics are undefined, not zero, when there is nothing to divide", () => {
  const empty = computeMetrics({ vp: 0, fn: 0, fp: 0, vn: 0 });
  assert.ok(Object.values(empty).every((v) => v === null));
  const perfect = computeMetrics({ vp: 3, fn: 0, fp: 0, vn: 5 });
  assert.equal(perfect.f1, 1);
  assert.equal(perfect.specificity, 1);
  assert.equal(percent(0.256, 1), "25.6 %");
  assert.equal(percent(null), "—");
});

test("cumulative step series count each host once", () => {
  const events = [
    ...phases,
    ev(40, "detection", { ipv4_src: "10.0.0.1" }),
    ev(41, "detection", { ipv4_src: "10.0.0.1" }),
    ev(42, "detection", { ipv4_src: "10.0.0.2" }),
    ev(43, "detection", { ipv4_src: "10.0.0.4" }),
  ];
  const steps = detectionSteps(events, topology, experiment);
  assert.deepEqual(
    steps.detected.map(([, n]) => n),
    [1, 2],
  );
  assert.deepEqual(
    steps.falsePositives.map(([, n]) => n),
    [1],
  );
});

test("a host the controller acted on counts as detected even if its event was lost", () => {
  const events = [
    ...phases,
    ev(38, "detection", { ipv4_src: "10.0.0.1" }),
    // h2's detection event was dropped under load, but the response was recorded.
    ev(45, "mitigation_requested", {
      ipv4_src: "10.0.0.2",
      action: "temporary_drop",
    }),
    ev(50, "gap", { count: 120, source: "controller" }),
    ev(51, "gap", { count: 30, source: "controller" }),
  ];
  const result = analyzeDetection(events, topology, experiment, false);
  assert.deepEqual(result.confusion, { vp: 2, fn: 0, fp: 0, vn: 3 });
  const a2 = result.hosts.find((h) => h.name === "a2")!;
  assert.equal(a2.fromResponse, true);
  assert.equal(a2.detections, 0);
  assert.equal(a2.firstOffsetS, 15);
  assert.equal(result.droppedEvents, 150);
});

test("a response against a legitimate client is a false positive", () => {
  const events = [
    ...phases,
    ev(40, "mitigation_requested", { ipv4_src: "10.0.0.5" }),
  ];
  const result = analyzeDetection(events, topology, experiment, false);
  assert.equal(result.hosts.find((h) => h.name === "c2")!.verdict, "FP");
});

test("a long run drops bulk events first and never the ones the results need", () => {
  const needed = [
    ev(0, "phase", { state: "baseline" }),
    ev(30, "attack_started", {}),
    ev(31, "detection", { ipv4_src: "10.0.0.1" }),
  ];
  const bulk = Array.from({ length: liveLimit + 500 }, (_, i) =>
    ev(40 + (i % 50), "flows", { rows: [] }),
  );
  const kept = retainEvents([...needed, ...bulk]);
  assert.equal(kept.length, liveLimit);
  assert.ok(needed.every((event) => kept.includes(event)));
  // The oldest bulk events are the ones that went.
  assert.equal(kept.includes(bulk[0]), false);
  assert.equal(kept.includes(bulk[bulk.length - 1]), true);
  // Small lists are returned untouched.
  assert.equal(retainEvents(needed), needed);
});

test("the History line says what judged a run and how it answered", () => {
  const base = { id: "r", status: "completed" };
  assert.equal(
    describeRun({
      ...base,
      detector_mode: "llm",
      detector_model: "llama3.2:3b",
      attackers: 3,
      mitigation: "true",
      policy: "escalate",
      dry_run: "false",
    }),
    "LLM llama3.2:3b · 3 attackers · escalate (real rules)",
  );
  assert.equal(
    describeRun({
      ...base,
      detector_mode: "entropy",
      attackers: 1,
      mitigation: "true",
      policy: "block",
      dry_run: "true",
    }),
    "Entropy · 1 attacker · block (simulated)",
  );
  // Detection off never shows a response; an old run with no setup shows nothing.
  assert.equal(
    describeRun({
      ...base,
      detector_mode: "off",
      attackers: 2,
      mitigation: "true",
    }),
    "No detection · 2 attackers",
  );
  assert.equal(describeRun(base), "");
});
