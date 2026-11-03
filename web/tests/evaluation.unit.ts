// Unit tests for the proposal evaluation metrics. Run with `npm run test:unit`.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Experiment, Observation, Topology } from "../src/types.ts";
import { emptyExperiment, phaseSpans } from "../src/types.ts";
import {
  EVALUATION,
  attackerDetectionOffsets,
  calibration,
  flowDecisions,
  metricsCsv,
  pointsDelta,
  proposalMetrics,
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

test("loss and availability change in percentage points", () => {
  assert.equal(pointsDelta(5, 0), "+5 pp");
  assert.equal(pointsDelta(90, 100), "-10 pp");
  assert.equal(pointsDelta(null, 0), "—");
});

test("the proposal table scores a run and names its sources", () => {
  const events = [
    ...phases(),
    ev(1, "detection_config", { mode: "llm", mitigation: true }),
    ev(35, "detection", { ipv4_src: ip("a1"), probability: 0.9 }),
    ev(36, "detection", { ipv4_src: ip("c1"), probability: 0.85 }),
    ev(39, "mitigation_requested", { ipv4_src: ip("a1"), action: "block" }),
    flows(40, [{ ipv4_src: ip("a1"), prob_ddos: 0.9, label: 1 }]),
    // victim link: 100 packets/s before the response, 10 after it settled
    ...[32, 34, 36, 38].map((second) =>
      ev(second, "links", {
        links: [{ link_id: "link-v1", rates: { tx_pps: 100, tx_bps: 0 } }],
      }),
    ),
    ...[50, 52, 54].map((second) =>
      ev(second, "links", {
        links: [{ link_id: "link-v1", rates: { tx_pps: 10, tx_bps: 0 } }],
      }),
    ),
  ];
  const rows = proposalMetrics(
    events,
    topology,
    experiment,
    Date.parse(at(120)),
  );
  assert.ok(rows);
  const value = (label: string) =>
    rows!.find((row) => row.label.startsWith(label))?.value ?? "";
  assert.equal(value("Detection Rate"), "50%");
  // c1, c2 and the idle v2 are the legitimate clients; only c1 was named.
  assert.equal(value("False Alarm Rate"), "33.3%");
  assert.match(value("Average attack detection time"), /^5 s \(1 of 2/);
  assert.match(value("Early Detection Rate"), /^50% \(1 of 2\)/);
  assert.match(value("Response time"), /^9 s after/);
  assert.equal(value("Detection-to-response delay"), "4 s");
  assert.match(value("Mitigation effectiveness"), /^90% less/);
  assert.match(value("Confidence calibration"), /Brier 0\.01/);
  assert.match(value("Output consistency"), /compare_llms\.py/);
  assert.match(value("Bandwidth"), /not recorded/);
  assert.ok(rows!.every((row) => row.source.length > 0));
  assert.equal(EVALUATION.earlyDetectionS, 10);
  const csv = metricsCsv(rows!);
  assert.match(csv.split("\n")[0], /^group,metric,value,definition,source$/);
  assert.equal(csv.split("\n").length, rows!.length + 1);
});

test("an entropy run says calibration does not apply; an off run scores nothing", () => {
  const entropy = proposalMetrics(
    [...phases(), ev(1, "detection_config", { mode: "entropy" })],
    topology,
    experiment,
    Date.parse(at(120)),
  )!;
  assert.match(
    entropy.find((row) => row.label === "Confidence calibration")!.value,
    /entropy detector reports no probability/,
  );
  const off = proposalMetrics(
    [...phases(), ev(1, "detection_config", { mode: "off" })],
    topology,
    experiment,
    Date.parse(at(120)),
  )!;
  assert.equal(
    off.find((row) => row.label === "Detection Rate (DR)")!.value,
    "no detector ran in this run",
  );
  assert.equal(
    proposalMetrics(phases(), topology, { ...experiment, attackers: [] }, 0),
    null,
  );
});

test("CSV quotes embedded quotes", () => {
  const csv = metricsCsv([
    {
      group: "Model",
      label: 'a "b"',
      value: "1, 2",
      definition: "d",
      source: "s",
    },
  ]);
  assert.equal(csv.split("\n")[1], '"Model","a ""b""","1, 2","d","s"');
});
