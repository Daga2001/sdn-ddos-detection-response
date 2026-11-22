// Unit tests for Traffic-tab measurements. Run with `npm run test:unit`.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Experiment, Observation, Topology } from "../src/types.ts";
import { emptyExperiment } from "../src/types.ts";
import {
  RECOVERY,
  checkSeries,
  controllerSeries,
  judgeController,
  judgeService,
  percentile,
  phaseTable,
  recordedForwarding,
  recoveryText,
  trafficMarkers,
  versus,
} from "../src/traffic.ts";
import { phaseSpans } from "../src/types.ts";

const at = (second: number) =>
  new Date(Date.UTC(2026, 0, 1, 0, 0, second)).toISOString();
let seq = 0;
function ev(second: number, kind: string, data: Record<string, any> = {}) {
  return {
    run_id: "r",
    seq: ++seq,
    ts: data.observed_at ?? at(second),
    kind,
    data: { observed_at: at(second), ...data },
  } as Observation;
}

const topology: Topology = {
  version: 1,
  name: "t",
  description: "",
  switches: [{ name: "s1", dpid: 1, position: { x: 0, y: 0 } }],
  hosts: ["a1", "v", "c1"].map((name, index) => ({
    name,
    ip: `10.0.0.${index + 1}/24`,
    position: { x: 0, y: 0 },
  })),
  links: ["a1", "v", "c1"].map((host) => ({
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
  victims: ["v"],
  confirm_isolated_lab: true,
};

function phases() {
  return [
    ev(0, "phase", { state: "baseline" }),
    ev(30, "phase", { state: "attack" }),
    ev(60, "attack_stopped", {}),
    ev(60, "phase", { state: "recovery" }),
    ev(120, "phase", { state: "completed" }),
  ];
}

function check(second: number, ok: boolean, total = 10) {
  return ev(second, "service", {
    success: ok,
    http_code: ok ? 200 : 0,
    latency_ms: ok ? total : null,
    connect_ms: ok ? 1 : null,
  });
}

function controller(second: number, cpu: number, rate: number) {
  return ev(second, "controller", {
    cpu_percent: cpu,
    packet_in_handled_per_s: rate,
    rss_bytes: 1000,
  });
}

test("percentile matches numpy linear interpolation", () => {
  assert.ok(Math.abs((percentile([1, 2, 3, 4], 95) ?? 0) - 3.85) < 1e-9);
  assert.equal(percentile([10], 95), 10);
  assert.equal(percentile([], 95), null);
});

test("a missing forwarding field shows what the old run actually used", () => {
  assert.equal(recordedForwarding({ mode: "llm" }), "per_port");
  assert.equal(recordedForwarding({ mode: "off" }), "per_port");
  assert.equal(
    recordedForwarding({ mode: "entropy", matchPorts: true }),
    "per_port",
  );
  assert.equal(recordedForwarding({ mode: "entropy" }), "per_port");
  assert.equal(
    recordedForwarding({ mode: "entropy", matchPorts: false }),
    "port_free",
  );
  assert.equal(
    recordedForwarding({ forwarding: "port_free", mode: "llm" }),
    "port_free",
  );
});

test("a failed website check stays visible", () => {
  const checks = checkSeries([check(1, true), check(2, false), check(3, true)]);
  assert.equal(checks[1].answered, false);
  assert.equal(checks.filter((item) => !item.answered).length, 1);
});

test("normal recovery names the first of ten good checks and the controller window", () => {
  const events = [
    ...phases(),
    ...Array.from({ length: 12 }, (_, index) => check(index, true, 10)),
    ...Array.from({ length: 12 }, (_, index) => check(61 + index, true, 12)),
    controller(0, 10, 1),
    controller(10, 20, 2),
    controller(70, 25, 3),
    controller(75, 22, 4),
  ];
  const spans = phaseSpans(events, Date.parse(at(120)));
  const tStop = Date.parse(at(60));
  const service = judgeService(
    checkSeries(events),
    spans,
    tStop,
    Date.parse(at(120)),
  );
  assert.equal(service.kind, "recovered");
  if (service.kind === "recovered")
    assert.equal(service.at, Date.parse(at(61)));
  assert.equal(recoveryText(service, tStop, Date.parse(at(120))), "1 s");
  const controllerOutcome = judgeController(
    [
      { t: Date.parse(at(0)), cpu: 10, rate: 1 },
      { t: Date.parse(at(10)), cpu: 20, rate: 2 },
      { t: Date.parse(at(70)), cpu: 25, rate: 3 },
      { t: Date.parse(at(75)), cpu: 22, rate: 4 },
    ],
    spans,
    tStop,
  );
  assert.equal(controllerOutcome.kind, "recovered");
  const markers = trafficMarkers(
    events,
    topology,
    experiment,
    Date.parse(at(120)),
  );
  assert.ok(
    markers.some((marker) => marker.label === "service back to normal"),
  );
  assert.ok(
    markers.some((marker) => marker.label === "controller back to normal"),
  );
  assert.equal(RECOVERY.normalChecks, 10);
});

test("a run that never settles says so and does not estimate", () => {
  const events = [
    ...phases(),
    ...Array.from({ length: 12 }, (_, index) => check(index, true, 10)),
    ...Array.from({ length: 12 }, (_, index) => check(61 + index, false)),
    controller(0, 10, 1),
    controller(10, 10, 1),
    controller(70, 90, 100),
    controller(75, 90, 100),
  ];
  const table = phaseTable(events, topology, experiment, Date.parse(at(120)));
  assert.ok(table);
  assert.match(table!.below[2], /not recovered within 60 s/);
  assert.match(table!.below[3], /not recovered within 60 s/);
  assert.equal(table!.below[2].includes("about"), false);
});

test("a short baseline is not judged", () => {
  const events = [
    ...phases(),
    ...Array.from({ length: 9 }, (_, index) => check(index, true, 10)),
    controller(0, 10, 1),
  ];
  const spans = phaseSpans(events, Date.parse(at(120)));
  const tStop = Date.parse(at(60));
  assert.equal(
    judgeService(checkSeries(events), spans, tStop, Date.parse(at(120))).kind,
    "too-short",
  );
  assert.equal(
    judgeController([{ t: Date.parse(at(0)), cpu: 10, rate: 1 }], spans, tStop)
      .kind,
    "too-short",
  );
  const table = phaseTable(events, topology, experiment, Date.parse(at(120)));
  assert.match(table!.below[2], /baseline too short to judge/);
  assert.match(table!.below[3], /baseline too short to judge/);
});

test("a baseline of zero shows the plain difference, not a percent", () => {
  assert.equal(versus(10, 0), "10");
  assert.equal(versus(0, 0), "0");
  assert.match(versus(15, 10), /%/);
  const events = [
    ...phases(),
    ev(1, "links", {
      links: [
        {
          link_id: "link-v",
          rates: { tx_pps: 0, tx_bps: 0, rx_pps: 0, rx_bps: 0 },
        },
      ],
    }),
    ev(40, "links", {
      links: [
        {
          link_id: "link-v",
          rates: { tx_pps: 10, tx_bps: 0, rx_pps: 0, rx_bps: 0 },
        },
      ],
    }),
  ];
  const table = phaseTable(events, topology, experiment, Date.parse(at(120)));
  const row = table!.rows.find((item) =>
    item.label.includes("delivered to victim"),
  );
  assert.equal(row?.attackVs, "10");
  assert.equal(row?.attackVs.includes("%"), false);
});

test("markers use the detection tab's first naming and first response", () => {
  const events = [
    ...phases(),
    ev(40, "detection", { ipv4_src: "10.0.0.1", probability: 0.9 }),
    ev(45, "mitigation_requested", { ipv4_src: "10.0.0.1", action: "block" }),
  ];
  const markers = trafficMarkers(
    events,
    topology,
    experiment,
    Date.parse(at(120)),
  );
  assert.deepEqual(
    markers.map((marker) => marker.label),
    ["first attacker detected", "first response"],
  );
  assert.equal(markers[0].t, Date.parse(at(40)));
  assert.equal(markers[1].t, Date.parse(at(45)));
});

test("network totals add each switch's latest reply, not the replies of a clock second", () => {
  const table = (ms: number, dpid: number, rules: number, sent: number) =>
    ({
      run_id: "r",
      seq: ++seq,
      ts: new Date(Date.UTC(2026, 0, 1, 0, 0, 0, ms)).toISOString(),
      kind: "switch_table",
      data: { dpid, flow_rules: rules, packet_in_sent_per_s: sent },
    }) as Observation;
  // Switch 1 answers twice inside second 0; switch 2 answers in second 1.
  const events = [
    table(100, 1, 1000, 10),
    table(900, 1, 1000, 10),
    table(1100, 2, 500, 5),
  ];
  const series = controllerSeries(events);
  assert.deepEqual(
    series.rules.map((p) => p.count),
    [1000, 1000, 1500],
  );
  assert.deepEqual(
    series.sent.map((p) => p.rate),
    [10, 10, 15],
  );
});
