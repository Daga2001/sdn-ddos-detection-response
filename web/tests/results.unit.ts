// Unit tests for the Results tab's numbers and files. Run with `npm run test:unit`.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Experiment, Observation, Topology } from "../src/types.ts";
import { emptyExperiment, phaseSpans } from "../src/types.ts";
import {
  decisionCost,
  formatChange,
  formatValue,
  metricsTableCsv,
  resultRow,
  resultRowCsv,
  runResults,
} from "../src/results.ts";
import type { Metric, RunResults } from "../src/results.ts";

const at = (second: number) =>
  new Date(Date.UTC(2026, 0, 1, 0, 0, 0) + second * 1000).toISOString();
let seq = 0;
function ev(second: number, kind: string, data: Record<string, any> = {}) {
  return {
    run_id: "11111111-2222-4333-8444-555555555555",
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

function scored(events: Observation[], mode = "llm"): RunResults {
  const results = runResults({
    events: [
      ev(1, "detection_config", {
        mode,
        model: "llama3.2:3b",
        prompt: "lab",
        threshold: 0.8,
        poll_seconds: 1,
        mitigation: true,
        response: { policy: "block", dry_run: false },
        forwarding: "port_free",
        entropy: { window_seconds: 5, warmup_windows: 16, measure: "norm" },
      }),
      ...phases(),
      ...events,
    ],
    topology,
    experiment,
    run: { id: "11111111-2222-4333-8444-555555555555", status: "completed" },
    active: false,
  });
  assert.ok(results);
  return results;
}

const metric = (results: RunResults, key: string): Metric => {
  const found = results.metrics.find((item) => item.key === key);
  assert.ok(found, `metric ${key}`);
  return found;
};

function llmRun(): Observation[] {
  return [
    ev(35, "detection", { ipv4_src: ip("a1"), probability: 0.9 }),
    ev(36, "detection", { ipv4_src: ip("c1"), probability: 0.85 }),
    ev(39, "mitigation_requested", { ipv4_src: ip("a1"), action: "block" }),
    ev(40, "flows", {
      dpid: 1,
      rows: [{ ipv4_src: ip("a1"), prob_ddos: 0.9, label: 1 }],
    }),
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
    // the model: one call of 2 samples at 400 ms each, one of 1 at 1000 ms
    ev(33, "decision_cost", {
      detector: "llm",
      decisions: 2,
      reused: 0,
      elapsed_ms: 800,
      ms_per_decision: 400,
      failed: false,
    }),
    ev(45, "decision_cost", {
      detector: "llm",
      decisions: 1,
      reused: 3,
      elapsed_ms: 1000,
      ms_per_decision: 1000,
      failed: false,
    }),
    ev(20, "controller", {
      cpu_percent: 5,
      rss_bytes: 104857600,
      decisions_total: 0,
      decision_ms_total: 0,
      decisions_reused_total: 0,
      decisions_failed_total: 0,
      polls_skipped_total: 0,
      detector_cpu_seconds: 10,
      detector_cpu_percent: 2,
      detector_rss_bytes: 52428800,
    }),
    ev(50, "controller", {
      cpu_percent: 40,
      rss_bytes: 125829120,
      decisions_total: 3,
      decision_ms_total: 1800,
      decisions_reused_total: 3,
      decisions_failed_total: 0,
      polls_skipped_total: 4,
      detector_cpu_seconds: 10.3,
      detector_cpu_percent: 12,
      detector_rss_bytes: 62914560,
    }),
    // website checks: all answered in the baseline, two of four failed in the attack
    ...[5, 10, 15, 20].map((second) =>
      ev(second, "service", { http_code: 200, latency_ms: 10 }),
    ),
    ev(32, "service", { http_code: 200, latency_ms: 40 }),
    ev(37, "service", { http_code: 0, latency_ms: null }),
    ev(42, "service", { http_code: 0, latency_ms: null }),
    ev(47, "service", { http_code: 200, latency_ms: 60 }),
  ];
}

test("an LLM run is scored per host, with its secondary per-flow unit", () => {
  const results = scored(llmRun());
  assert.equal(metric(results, "detection_rate").value, 50);
  // c1, c2 and the idle v2 are the legitimate clients; only c1 was named.
  assert.equal(
    Math.round((metric(results, "false_alarm_rate").value as number) * 10),
    333,
  );
  assert.equal(metric(results, "first_detection").value, 5);
  assert.equal(metric(results, "mean_detection").value, 5);
  assert.equal(metric(results, "all_detected").value, null);
  assert.equal(metric(results, "early_detection_rate").value, 50);
  assert.equal(metric(results, "flow_decisions").value, 1);
  assert.equal(metric(results, "flow_detection_rate").value, 100);
  assert.equal(
    Number((metric(results, "brier").value as number).toFixed(3)),
    0.01,
  );
  assert.equal(metric(results, "victim_named").value, "no");
  assert.equal(metric(results, "forwarding").value, "port_free");
  assert.equal(metric(results, "response").value, "block");
  assert.equal(metric(results, "poll_interval").value, 1);
  assert.equal(metric(results, "attack_length").value, 30);
});

test("the cost of each decision comes from the controller's totals and calls", () => {
  const results = scored(llmRun());
  assert.equal(
    metric(results, "decision_unit").value,
    "one flow sample sent to the model",
  );
  assert.equal(metric(results, "decisions").value, 3);
  assert.equal(metric(results, "decisions_reused").value, 3);
  assert.equal(metric(results, "time_per_decision_mean").value, 600);
  assert.equal(metric(results, "time_per_decision_median").value, 400);
  // 3 decisions in a 30 s attack
  assert.equal(metric(results, "decisions_per_s_attack").value, 0.1);
  assert.equal(metric(results, "decision_capacity_per_s").value, 2.5);
  assert.equal(metric(results, "polls_skipped").value, 4);
  // 0.3 s of detector CPU for 3 decisions
  assert.equal(
    Math.round(metric(results, "detector_cpu_per_decision").value as number),
    100,
  );
  assert.equal(metric(results, "detector_ram_peak").value, 60);
  assert.deepEqual(metric(results, "detector_cpu").phases, {
    baseline: 2,
    attack: 12,
    recovery: null,
  });
  assert.deepEqual(metric(results, "ryu_cpu").phases, {
    baseline: 5,
    attack: 40,
    recovery: null,
  });
});

test("service, response and recovery are measured from the recorded events", () => {
  const results = scored(llmRun());
  const availability = metric(results, "availability");
  assert.deepEqual(availability.phases, {
    baseline: 100,
    attack: 50,
    recovery: null,
  });
  assert.equal(formatChange(availability), "-50 pts");
  assert.equal(formatChange(metric(results, "request_time_median")), "+400 %");
  assert.equal(metric(results, "time_to_first_failure").value, 7);
  assert.equal(metric(results, "response_time").value, 9);
  assert.equal(metric(results, "detection_to_response").value, 4);
  assert.equal(metric(results, "attackers_responded").value, 1);
  assert.equal(metric(results, "collateral").value, 0);
  assert.equal(metric(results, "mitigation_effectiveness").value, 90);
  // too few baseline checks to judge recovery: said, not estimated
  assert.equal(metric(results, "service_recovery").value, null);
  assert.equal(
    metric(results, "service_recovery").note,
    "baseline too short to judge",
  );
});

test("an entropy run says what does not apply, and a no-defense run scores nothing", () => {
  const entropy = scored([], "entropy");
  assert.equal(metric(entropy, "flow_detection_rate").value, null);
  assert.match(
    metric(entropy, "brier").note ?? "",
    /entropy decides per window/,
  );
  assert.equal(
    metric(entropy, "decision_unit").value,
    "one evaluated window of the whole network",
  );
  assert.equal(metric(entropy, "model").value, null);
  assert.equal(metric(entropy, "entropy_measure").value, "norm");
  assert.match(
    metric(entropy, "decisions").note ?? "",
    /no cost data reached the lab/,
  );
  const off = scored([], "off");
  assert.equal(metric(off, "detection_rate").value, null);
  assert.match(metric(off, "detection_rate").note ?? "", /no-defense/);
  assert.match(metric(off, "decisions").note ?? "", /no-defense/);
  assert.equal(metric(off, "decision_unit").value, null);
});

test("every run writes the same columns in the same order, whatever the detector", () => {
  const columns = (results: RunResults) =>
    resultRow(results).map(([name]) => name);
  const llm = columns(scored(llmRun()));
  assert.deepEqual(columns(scored([], "entropy")), llm);
  assert.deepEqual(columns(scored([], "off")), llm);
  assert.equal(new Set(llm).size, llm.length, "column names are unique");
  for (const name of [
    "run_id",
    "detection_rate_pct",
    "time_per_decision_mean_ms",
    "detector_cpu_baseline_pct",
    "detector_cpu_attack_pct",
    "availability_attack_pct",
    "service_recovery_s",
    "valid",
  ])
    assert.ok(llm.includes(name), name);
  const csv = resultRowCsv(scored(llmRun())).split("\n");
  assert.equal(csv.length, 2);
  assert.equal(csv[0].split(",").length, llm.length);
});

test("the long CSV has one line per value, with its definition", () => {
  const results = scored(llmRun());
  const lines = metricsTableCsv(results).split("\n");
  assert.equal(lines[0], "group,metric,column,phase,value,shown,definition");
  const phased = results.metrics.filter((m) => m.phased).length;
  assert.equal(lines.length, 1 + results.metrics.length + phased * 2);
  assert.ok(
    lines.some((line) =>
      line.startsWith(
        "Cost,Time per decision (mean),time_per_decision_mean_ms,,600,600 ms,",
      ),
    ),
  );
});

test("a run is flagged when it should not be counted", () => {
  const valid = scored(llmRun());
  // The test run's 30 s baseline is too short for the recovery rule: said, not hidden.
  assert.deepEqual(valid.problems, [
    "The baseline was too short to learn the website's normal response time, so recovery cannot be measured (the protocol uses 300 s).",
  ]);
  assert.equal(metric(valid, "valid").value, "no");
  // A controller that sent nothing, and a recovery shorter than 10 checks, are flagged.
  const silent = runResults({
    events: [
      ev(0, "phase", { state: "baseline" }),
      ev(30, "phase", { state: "attack" }),
      ev(30, "attack_started", {}),
      ev(60, "attack_stopped", {}),
      ev(60, "phase", { state: "recovery" }),
      ev(66, "phase", { state: "completed" }),
    ],
    topology,
    experiment,
    run: { id: "x", status: "completed" },
    active: false,
  });
  assert.ok(silent);
  assert.match(silent.problems.join(" "), /controller sent no samples/);
  assert.match(
    silent.problems.join(" "),
    /recovery phase \(6 s\) was shorter than the 10/,
  );
  const stopped = scored([...llmRun(), ev(50, "stop_requested", {})]);
  assert.match(stopped.problems.join(" "), /stopped before it finished/);
  assert.equal(metric(stopped, "valid").value, "no");
  // 30 s of baseline is shorter than 16 windows of 5 s
  const entropy = scored([], "entropy");
  assert.match(
    entropy.problems.join(" "),
    /shorter than the entropy warm-up \(80 s\)/,
  );
});

test("nothing is scored before the attack starts", () => {
  const baselineOnly = runResults({
    events: [ev(0, "phase", { state: "baseline" })],
    topology,
    experiment,
    active: true,
  });
  assert.equal(baselineOnly, null);
  assert.equal(
    runResults({
      events: phases(),
      topology,
      experiment: { ...experiment, attackers: [] },
      active: false,
    }),
    null,
  );
});

test("failed calls cost time but give no time per decision", () => {
  const events = [
    ...phases(),
    ev(40, "decision_cost", {
      decisions: 1,
      ms_per_decision: 30000,
      failed: true,
    }),
    ev(41, "decision_cost", {
      decisions: 1,
      ms_per_decision: 500,
      failed: false,
    }),
  ];
  const cost = decisionCost(events, phaseSpans(events, Date.parse(at(120))));
  assert.equal(cost.decisions, 2);
  assert.equal(cost.failed, 1);
  assert.equal(cost.medianMs, 500);
});

test("values are shown with their unit and quoted safely in CSV", () => {
  assert.equal(formatValue(12.345, "pct"), "12.3 %");
  assert.equal(formatValue(3.456, "ms"), "3.46 ms");
  assert.equal(formatValue(null, "s"), "—");
  assert.equal(formatValue("x", "text"), "x");
  const results = scored([]);
  results.metrics.unshift({
    key: "quoted",
    label: 'a "b"',
    unit: "text",
    group: "Run",
    definition: "d",
    value: "1, 2",
  });
  assert.equal(resultRowCsv(results).split("\n")[1].split(",")[0], '"1');
  assert.match(metricsTableCsv(results), /"a ""b""",quoted,,"1, 2"/);
});
