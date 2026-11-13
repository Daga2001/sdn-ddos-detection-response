/**
 * Every number the final report needs from one run, in one place.
 *
 * Pure functions: no chart library, no clock, no network. The Results tab shows
 * these metrics and the downloads write exactly the same values, so what the tab
 * shows is what the report gets. Every metric has a fixed CSV column, filled or
 * empty, whatever the detector, so the rows of many runs stack into one table.
 *
 * Ground truth is the experiment itself (see detection.ts): the attackers are the
 * positives, the legitimate clients the negatives, the victim is reported apart.
 * The main unit is one host per run; the LLM's per-flow numbers are secondary.
 */
import { analyzeDetection } from "./detection.ts";
import type { Analysis } from "./detection.ts";
import {
  EVALUATION,
  attackerDetectionOffsets,
  calibration,
  flowDecisions,
  victimRecovery,
} from "./evaluation.ts";
import {
  checkSeries,
  controllerSeries,
  cpuSeries,
  judgeController,
  mean,
  median,
  peak,
  percentile,
  phaseOf,
  pingSeries,
  recordedForwarding,
  recoveryText,
  trafficSeries,
} from "./traffic.ts";
import { phaseSpans } from "./types.ts";
import type {
  Experiment,
  Observation,
  PhaseSpan,
  Run,
  Topology,
} from "./types.ts";

export type Phase = "baseline" | "attack" | "recovery";
export const PHASES: Phase[] = ["baseline", "attack", "recovery"];

/** pct is already 0–100; score is a unitless number such as a Brier score. */
export type Unit =
  | "pct"
  | "s"
  | "ms"
  | "mib"
  | "count"
  | "per_s"
  | "score"
  | "text";

export type Group =
  | "Run"
  | "Detection"
  | "Cost"
  | "Service"
  | "Network"
  | "Response"
  | "Recovery"
  | "Validity";

export type Value = number | string | null;

export type Metric = {
  /** CSV column; a per-phase metric writes key_baseline, key_attack, key_recovery. */
  key: string;
  label: string;
  unit: Unit;
  group: Group;
  definition: string;
  value?: Value;
  phases?: Record<Phase, number | null>;
  /** How the attack phase is compared with the baseline in the tab. */
  change?: "relative" | "points";
  /** Shown instead of an empty value, e.g. why a metric does not apply. */
  note?: string;
  /** Written as three CSV columns (one per phase) even when it does not apply. */
  phased?: boolean;
};

export type RunResults = {
  /** The attack is over and the record is complete: numbers will not change. */
  final: boolean;
  analysis: Analysis;
  metrics: Metric[];
  /** Reasons this run should not be counted; empty when it is valid. */
  problems: string[];
  detector: string;
};

/** Recovery needs this many answered website checks in a row, one a second. */
const RECOVERY_CHECKS_NEEDED = 10;

/** Why a detector metric is empty in a run that had no detector. */
export const NO_DETECTOR = "no detector ran (no-defense run)";

/** A metric that cannot exist for this run's detector (shown once, as a list). */
export function doesNotApply(metric: Metric): boolean {
  const empty =
    (metric.value === null || metric.value === undefined) && !metric.phases;
  return (
    empty &&
    (metric.note === NO_DETECTOR ||
      (metric.note ?? "").startsWith("not applicable"))
  );
}

export const NOT_MEASURED = [
  "GPU use, GPU memory and power on the computer that runs the language model (Ollama). The detector CPU and memory here are the detector service's own; with the LLM the model itself runs on that computer.",
  "Bandwidth between legitimate hosts: the lab runs no iperf stream.",
  "LLM output consistency: the model answers at temperature 0 with a fixed seed and the controller reuses verdicts for identical samples, so repeated answers are identical by design.",
];

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function at(event: Observation): number {
  return Date.parse(event.data?.observed_at ?? event.ts);
}

const numbers = (values: (number | null)[]) =>
  values.filter((value): value is number => value !== null);

function byPhase<T extends { t: number }>(
  items: T[],
  spans: PhaseSpan[],
  phase: Phase,
): T[] {
  return items.filter((item) => phaseOf(spans, item.t) === phase);
}

function perPhase(
  pick: (phase: Phase) => number | null,
): Record<Phase, number | null> {
  return {
    baseline: pick("baseline"),
    attack: pick("attack"),
    recovery: pick("recovery"),
  };
}

const ratioPct = (numerator: number, denominator: number) =>
  denominator > 0 ? (numerator / denominator) * 100 : null;

const toPct = (value: number | null) => (value === null ? null : value * 100);

function spanSeconds(spans: PhaseSpan[], phase: Phase): number | null {
  const total = spans
    .filter((span) => span.state === phase)
    .reduce((sum, span) => sum + (span.end - span.start), 0);
  return total > 0 ? total / 1000 : null;
}

function attackStartMs(events: Observation[]): number | null {
  const started =
    events.find((event) => event.kind === "attack_started") ??
    events.find(
      (event) => event.kind === "phase" && event.data.state === "attack",
    );
  const ms = started ? Date.parse(started.ts) : NaN;
  return Number.isFinite(ms) ? ms : null;
}

/** Warm-up of the entropy detector in seconds, as the Detection panel computes it. */
export function warmupSeconds(entropy: Record<string, any>): number | null {
  const windows = finite(entropy?.warmup_windows);
  const seconds = finite(entropy?.window_seconds);
  if (windows === null || seconds === null) return null;
  return windows * Math.max(seconds, 2.5);
}

/**
 * The cost of the detector's decisions, from the controller's decision_cost events
 * and the running totals it sends with every controller sample.
 */
export function decisionCost(events: Observation[], spans: PhaseSpan[]) {
  const calls = events
    .filter((event) => event.kind === "decision_cost")
    .map((event) => ({
      t: at(event),
      decisions: finite(event.data.decisions) ?? 0,
      perDecision: finite(event.data.ms_per_decision),
      failed: event.data.failed === true,
    }));
  // Every decision of a call took the call's time per decision.
  const times: number[] = [];
  for (const call of calls)
    if (call.perDecision !== null && !call.failed)
      for (let i = 0; i < call.decisions; i += 1) times.push(call.perDecision);
  const samples = events
    .filter((event) => event.kind === "controller")
    .map((event) => ({ t: at(event), data: event.data }));
  const last = samples.findLast(
    (sample) => finite(sample.data.decisions_total) !== null,
  )?.data;
  const fromEvents = calls.reduce((sum, call) => sum + call.decisions, 0);
  const total = finite(last?.decisions_total) ?? fromEvents;
  const totalMs = finite(last?.decision_ms_total);
  const failed =
    finite(last?.decisions_failed_total) ??
    calls
      .filter((call) => call.failed)
      .reduce((sum, call) => sum + call.decisions, 0);
  const attackSeconds = spanSeconds(spans, "attack");
  const attackDecisions = byPhase(calls, spans, "attack").reduce(
    (sum, call) => sum + call.decisions,
    0,
  );
  // Detector CPU time per decision: CPU seconds its request threads spent
  // deciding, between the first and the last sample that carry both totals,
  // divided by the decisions in between. The process's whole CPU time is not
  // used: health checks and usage readings would be charged to the decisions.
  const paired = samples.filter(
    (sample) =>
      finite(sample.data.detector_decision_cpu_seconds) !== null &&
      finite(sample.data.decisions_total) !== null,
  );
  let cpuMsPerDecision: number | null = null;
  if (paired.length >= 2) {
    const first = paired[0].data;
    const end = paired[paired.length - 1].data;
    const decided = end.decisions_total - first.decisions_total;
    const cpu =
      end.detector_decision_cpu_seconds - first.detector_decision_cpu_seconds;
    if (decided > 0 && cpu >= 0) cpuMsPerDecision = (cpu * 1000) / decided;
  }
  const detectorCpu = samples.map((sample) => ({
    t: sample.t,
    cpu: finite(sample.data.detector_cpu_percent),
    ram: finite(sample.data.detector_rss_bytes),
  }));
  return {
    recorded: calls.length > 0 || last !== undefined,
    decisions: total,
    reused: finite(last?.decisions_reused_total),
    failed,
    meanMs:
      totalMs !== null && total > 0 ? totalMs / total : (mean(times) ?? null),
    medianMs: median(times),
    p95Ms: percentile(times, 95),
    perSecondAttack:
      attackSeconds !== null && calls.length
        ? attackDecisions / attackSeconds
        : null,
    skippedPolls: finite(last?.polls_skipped_total),
    cpuMsPerDecision,
    detectorCpu,
  };
}

/** The phases' measured length, the setup and every metric of one run. */
export function runResults(input: {
  events: Observation[];
  topology: Topology | null;
  experiment: Experiment | null;
  run?: Partial<Run> | null;
  active: boolean;
}): RunResults | null {
  const { events, topology, experiment, run, active } = input;
  if (!experiment?.attackers?.length) return null;
  // Only an experiment that reached its attack has anything to score: an
  // observation, or a run still in its baseline, does not.
  const attacked = events.some(
    (event) =>
      event.kind === "attack_started" ||
      (event.kind === "phase" && event.data.state === "attack"),
  );
  if (!attacked) return null;
  // A loop, not Math.max(...list): a long record can exceed the argument limit.
  let runEnd = events.length ? -Infinity : Date.now();
  for (const event of events) {
    const ms = Date.parse(event.ts);
    if (ms > runEnd) runEnd = ms;
  }
  const spans = phaseSpans(events, runEnd);
  const analysis = analyzeDetection(events, topology, experiment, active);
  const config = analysis.config ?? {};
  const detector: string =
    config.mode ?? experiment.detection?.mode ?? "unknown";
  const llm = detector === "llm";
  const entropy = detector === "entropy";
  const off = detector === "off";
  const metrics: Metric[] = [];
  const add = (metric: Metric) =>
    metrics.push(metric.phases ? { ...metric, phased: true } : metric);
  const notApplicable = (why: string) => ({ value: null, note: why });
  const noDetector = NO_DETECTOR;

  // -- What was tested ------------------------------------------------------------
  const forwarding = recordedForwarding({
    forwarding: config.forwarding ?? run?.forwarding,
    mode: detector,
    matchPorts: config.entropy?.match_ports,
  });
  const response = config.response ?? experiment.detection?.response ?? {};
  const mitigation = config.mitigation ?? experiment.mitigation;
  const responseText = !mitigation
    ? "off"
    : response.dry_run
      ? `${response.policy ?? "block"} (dry run)`
      : (response.policy ?? "block");
  const runText = (
    key: string,
    label: string,
    value: Value,
    definition: string,
    group: Group = "Run",
  ) => add({ key, label, unit: "text", group, definition, value });
  runText("run_id", "Run id", run?.id ?? events[0]?.run_id ?? null, "Run id.");
  runText(
    "started_utc",
    "Started (UTC)",
    run?.started_at ?? events[0]?.ts ?? null,
    "When the run started.",
  );
  runText(
    "topology",
    "Topology",
    topology
      ? `${topology.name} · ${topology.switches.length} switches · ${topology.hosts.length} hosts`
      : null,
    "Network the run used.",
  );
  runText(
    "detector",
    "Detector",
    detector,
    "llm, entropy or off (no defense).",
  );
  runText(
    "model",
    "Language model",
    llm ? (config.model ?? null) : null,
    "Ollama model tag (LLM runs only).",
  );
  runText(
    "prompt",
    "Prompt profile",
    llm ? (config.prompt ?? null) : null,
    "Examples given to the model (LLM runs only).",
  );
  add({
    key: "probability_threshold",
    label: "Probability threshold",
    unit: "score",
    group: "Run",
    definition: "A flow is an attack when P(attack) is at least this value.",
    value: llm ? (finite(config.threshold) ?? null) : null,
  });
  runText(
    "entropy_measure",
    "Entropy measure",
    entropy ? (config.entropy?.measure ?? "shannon") : null,
    "Which entropy the detector computes (entropy runs only).",
  );
  add({
    key: "entropy_window",
    label: "Entropy window",
    unit: "s",
    group: "Run",
    definition: "Seconds of traffic per entropy decision.",
    value: entropy ? finite(config.entropy?.window_seconds) : null,
  });
  add({
    key: "poll_interval",
    label: "Statistics poll",
    unit: "s",
    group: "Run",
    definition: "How often the controller asks the switches for flow counters.",
    value: finite(config.poll_seconds ?? experiment.detection?.poll_seconds),
  });
  runText(
    "forwarding",
    "Forwarding rules",
    forwarding,
    "per_port: one rule per destination port; port_free: one rule per source, destination and protocol.",
  );
  runText(
    "response",
    "Response",
    responseText,
    "Response policy the controller applied, or off.",
  );
  add({
    key: "attackers",
    label: "Attackers",
    unit: "count",
    group: "Run",
    definition: "Hosts that sent attack traffic.",
    value: experiment.attackers.length,
  });
  runText(
    "attacker_hosts",
    "Attacker hosts",
    experiment.attackers.join(" "),
    "Names of the attackers.",
  );
  runText(
    "victims",
    "Victims",
    experiment.victims.join(" "),
    "Names of the victims.",
  );
  runText(
    "traffic",
    "Attack traffic",
    experiment.traffic.join("+"),
    "Kinds of attack traffic.",
  );
  add({
    key: "rate",
    label: "Attack rate per attacker",
    unit: "per_s",
    group: "Run",
    definition: "Packets per second each attacker sends to each victim.",
    value: experiment.rate,
  });
  for (const phase of PHASES)
    add({
      key: `${phase}_length`,
      label: `${phase[0].toUpperCase()}${phase.slice(1)} length`,
      unit: "s",
      group: "Run",
      definition: `Measured length of the ${phase} phase.`,
      value: spanSeconds(spans, phase),
    });

  // -- How well it detected (one host per run) ------------------------------------
  const c = analysis.confusion;
  const m = analysis.metrics;
  const scored = (value: Value) =>
    off ? notApplicable(noDetector) : { value };
  const count = (key: string, label: string, value: number, def: string) =>
    add({
      key,
      label,
      unit: "count",
      group: "Detection",
      definition: def,
      ...scored(value),
    });
  count("tp", "True positives", c.vp, "Attackers named at least once.");
  count("fn", "False negatives", c.fn, "Attackers never named.");
  count("fp", "False positives", c.fp, "Legitimate clients named.");
  count("tn", "True negatives", c.vn, "Legitimate clients never named.");
  const rate = (key: string, label: string, value: number | null, d: string) =>
    add({
      key,
      label,
      unit: "pct",
      group: "Detection",
      definition: d,
      ...scored(toPct(value)),
    });
  rate(
    "detection_rate",
    "Detection rate (recall)",
    m.recall,
    "TP / (TP + FN), per host. Detection rate and recall are the same formula.",
  );
  rate(
    "false_alarm_rate",
    "False alarm rate",
    m.falsePositiveRate,
    "FP / (FP + TN), per host.",
  );
  rate("precision", "Precision", m.precision, "TP / (TP + FP), per host.");
  rate(
    "accuracy",
    "Accuracy",
    m.accuracy,
    "(TP + TN) / all hosts scored. Most hosts are legitimate, so read it after DR and FAR.",
  );
  rate("f1", "F1", m.f1, "2 · precision · recall / (precision + recall).");
  const timing = attackerDetectionOffsets(events, topology, experiment);
  const seconds = (
    key: string,
    label: string,
    value: number | null,
    d: string,
  ) =>
    add({
      key,
      label,
      unit: "s",
      group: "Detection",
      definition: d,
      ...(off ? notApplicable(noDetector) : { value }),
    });
  seconds(
    "first_detection",
    "First attacker detected",
    timing.offsets.length ? timing.offsets[0] : null,
    "Seconds from the attack start to the first attacker named.",
  );
  seconds(
    "mean_detection",
    "Average detection time",
    mean(timing.offsets),
    "Mean, over the attackers named, of the seconds from the attack start to their first naming. Undetected attackers are not in the mean: read it with the detection rate.",
  );
  seconds(
    "all_detected",
    "All attackers detected",
    timing.total > 0 && timing.offsets.length === timing.total
      ? timing.offsets[timing.offsets.length - 1]
      : null,
    "Seconds from the attack start until the last attacker was named; empty if one never was.",
  );
  const early = timing.offsets.filter(
    (offset) => offset <= EVALUATION.earlyDetectionS,
  ).length;
  rate(
    "early_detection_rate",
    `Early detection rate (≤ ${EVALUATION.earlyDetectionS} s)`,
    timing.total ? early / timing.total : null,
    `Attackers named within ${EVALUATION.earlyDetectionS} s of the attack start / all attackers.`,
  );
  add({
    key: "victim_named",
    label: "Victim named as a source",
    unit: "text",
    group: "Detection",
    definition: "Whether the detector named a victim as an attacker.",
    ...(off
      ? notApplicable(noDetector)
      : { value: analysis.victimFlagged.length ? "yes" : "no" }),
  });
  const flows = flowDecisions(events, topology, experiment, spans);
  const flowCount = flows.tp + flows.fn + flows.fp + flows.tn;
  const flowWhy = off
    ? noDetector
    : entropy
      ? "not applicable: entropy decides per window, not per flow"
      : "no judged flows recorded";
  const flowMetric = (key: string, label: string, unit: Unit, value: Value) =>
    add({
      key,
      label,
      unit,
      group: "Detection",
      definition:
        "Secondary unit, LLM only: one judged flow on one switch in one poll. Attackers' flows during the attack are attacks; legitimate clients' flows, and attackers' flows in the baseline, are normal.",
      ...(llm && flowCount ? { value } : notApplicable(flowWhy)),
    });
  flowMetric("flow_decisions", "Judged flows", "count", flowCount);
  flowMetric(
    "flow_detection_rate",
    "Per-flow detection rate",
    "pct",
    ratioPct(flows.tp, flows.tp + flows.fn),
  );
  flowMetric(
    "flow_false_alarm_rate",
    "Per-flow false alarm rate",
    "pct",
    ratioPct(flows.fp, flows.fp + flows.tn),
  );
  const calibrated = calibration(flows.scored);
  flowMetric("brier", "Brier score", "score", calibrated.brier);
  flowMetric(
    "ece",
    `Expected calibration error (${EVALUATION.calibrationBins} bins)`,
    "score",
    calibrated.ece,
  );

  // -- What each decision cost ------------------------------------------------------
  const cost = decisionCost(events, spans);
  const unit = llm
    ? "one flow sample sent to the model"
    : entropy
      ? "one evaluated window of the whole network"
      : "none";
  const costWhy = off
    ? noDetector
    : "not recorded: no cost data reached the lab from the controller in this run";
  const costMetric = (
    key: string,
    label: string,
    u: Unit,
    value: number | null,
    definition: string,
  ) =>
    add({
      key,
      label,
      unit: u,
      group: "Cost",
      definition,
      ...(cost.recorded && !off ? { value } : notApplicable(costWhy)),
    });
  add({
    key: "decision_unit",
    label: "One decision is",
    unit: "text",
    group: "Cost",
    definition: "What one detector decision is for this detector.",
    ...(off ? notApplicable(noDetector) : { value: unit }),
  });
  costMetric(
    "decisions",
    "Decisions made",
    "count",
    cost.decisions,
    "Calls the detector answered or failed during the run (cached LLM verdicts excluded).",
  );
  costMetric(
    "decisions_reused",
    "Verdicts reused from the cache",
    "count",
    llm ? cost.reused : null,
    "LLM only: flows answered from the controller's cache of identical samples, at no model cost.",
  );
  if (!llm && !off)
    Object.assign(metrics[metrics.length - 1], {
      value: null,
      note: "not applicable: only the LLM reuses verdicts",
    });
  costMetric(
    "decisions_failed",
    "Failed decisions",
    "count",
    cost.failed,
    "Calls that returned no verdict (timeout or error); their time is still counted.",
  );
  costMetric(
    "time_per_decision_mean",
    "Time per decision (mean)",
    "ms",
    cost.meanMs,
    "Time the controller waited for the detector, divided by the decisions: detector service round trip, model call included.",
  );
  costMetric(
    "time_per_decision_median",
    "Time per decision (median)",
    "ms",
    cost.medianMs,
    "Median of the time per decision of the answered calls.",
  );
  costMetric(
    "time_per_decision_p95",
    "Time per decision (95th percentile)",
    "ms",
    cost.p95Ms,
    "95 % of the answered decisions took at most this long.",
  );
  costMetric(
    "decisions_per_s_attack",
    "Decisions per second (attack)",
    "per_s",
    cost.perSecondAttack,
    "Decisions made during the attack phase / its length.",
  );
  costMetric(
    "decision_capacity_per_s",
    "Decision capacity",
    "per_s",
    cost.medianMs ? 1000 / cost.medianMs : null,
    "1000 / median time per decision: decisions per second the detector could answer one after another.",
  );
  costMetric(
    "polls_skipped",
    "Polls not judged",
    "count",
    llm ? cost.skippedPolls : null,
    "LLM only: switch polls replaced by a newer poll before the model could judge them, a sign the model could not keep up.",
  );
  if (!llm && !off)
    Object.assign(metrics[metrics.length - 1], {
      value: null,
      note: "not applicable: entropy judges every window",
    });
  costMetric(
    "detector_cpu_per_decision",
    "Detector CPU time per decision",
    "ms",
    cost.cpuMsPerDecision,
    "CPU time the detector service's request threads spent deciding (thread CPU time, so waiting for Ollama does not count) / decisions. With the LLM the model itself runs in Ollama, outside this process.",
  );
  const detectorCpu = perPhase((phase) =>
    mean(numbers(byPhase(cost.detectorCpu, spans, phase).map((s) => s.cpu))),
  );
  add({
    key: "detector_cpu",
    label: "Detector service CPU (mean)",
    unit: "pct",
    group: "Cost",
    definition:
      "CPU of the detector service process, percent of one core, from its own CPU time between controller samples.",
    phased: true,
    ...(cost.recorded && !off
      ? { phases: detectorCpu, change: "relative" as const }
      : notApplicable(costWhy)),
  });
  costMetric(
    "detector_ram_peak",
    "Detector service memory (peak)",
    "mib",
    peak(numbers(cost.detectorCpu.map((s) => s.ram))) === null
      ? null
      : (peak(numbers(cost.detectorCpu.map((s) => s.ram))) as number) / 1048576,
    "Highest resident memory of the detector service process.",
  );
  const cpu = cpuSeries(events);
  const ryuCpu = perPhase((phase) =>
    mean(numbers(byPhase(cpu.ryu, spans, phase).map((s) => s.cpu))),
  );
  add({
    key: "ryu_cpu",
    label: "Controller CPU (Ryu, mean)",
    unit: "pct",
    group: "Cost",
    definition:
      "CPU of the Ryu controller process (psutil), percent of one core, sampled every poll.",
    phases: ryuCpu,
    change: "relative",
  });
  add({
    key: "ryu_cpu_peak_attack",
    label: "Controller CPU peak (attack)",
    unit: "pct",
    group: "Cost",
    definition: "Highest Ryu CPU sample during the attack.",
    value: peak(numbers(byPhase(cpu.ryu, spans, "attack").map((s) => s.cpu))),
  });
  const ryuRam = perPhase((phase) => {
    const top = peak(numbers(byPhase(cpu.ryu, spans, phase).map((s) => s.ram)));
    return top === null ? null : top / 1048576;
  });
  add({
    key: "ryu_ram_peak",
    label: "Controller memory (Ryu, peak)",
    unit: "mib",
    group: "Cost",
    definition: "Highest resident memory of the Ryu process per phase.",
    phases: ryuRam,
    change: "relative",
  });
  add({
    key: "ovs_cpu",
    label: "Switch CPU (Open vSwitch, mean)",
    unit: "pct",
    group: "Cost",
    definition: "CPU of ovs-vswitchd only.",
    phases: perPhase((phase) =>
      mean(numbers(byPhase(cpu.ovs, spans, phase).map((s) => s.cpu))),
    ),
    change: "relative",
  });
  add({
    key: "machine_cpu",
    label: "Lab machine CPU (mean)",
    unit: "pct",
    group: "Cost",
    definition:
      "CPU of the whole lab machine (the VM running Mininet and Ryu).",
    phases: perPhase((phase) =>
      mean(numbers(byPhase(cpu.machine, spans, phase).map((s) => s.cpu))),
    ),
    change: "relative",
  });

  // -- Effect on legitimate users ---------------------------------------------------
  const checks = checkSeries(events);
  add({
    key: "availability",
    label: "Service availability",
    unit: "pct",
    group: "Service",
    definition:
      "Website checks answered with HTTP 200 / checks made, per phase (one check a second from the legitimate clients).",
    phases: perPhase((phase) => {
      const rows = byPhase(checks, spans, phase);
      return ratioPct(
        rows.filter((check) => check.answered).length,
        rows.length,
      );
    }),
    change: "points",
  });
  add({
    key: "request_time_median",
    label: "Website request time (median)",
    unit: "ms",
    group: "Service",
    definition: "Median total time of the answered website checks.",
    phases: perPhase((phase) =>
      median(
        numbers(
          byPhase(checks, spans, phase)
            .filter((check) => check.answered)
            .map((check) => check.total),
        ),
      ),
    ),
    change: "relative",
  });
  const pings = pingSeries(events);
  add({
    key: "ping_rtt_mean",
    label: "Ping round-trip time (mean)",
    unit: "ms",
    group: "Service",
    definition:
      "Mean RTT of the 5 pings per second from a legitimate client to each victim.",
    phases: perPhase((phase) =>
      mean(byPhase(pings.rtt, spans, phase).map((point) => point.rtt)),
    ),
    change: "relative",
  });
  add({
    key: "ping_loss",
    label: "Ping loss",
    unit: "pct",
    group: "Service",
    definition: "Pings with no reply within 1 s / pings sent, per phase.",
    phases: perPhase((phase) => {
      const rows = events.filter(
        (event) => event.kind === "ping" && phaseOf(spans, at(event)) === phase,
      );
      const sent = rows.reduce((s, e) => s + (Number(e.data.sent) || 0), 0);
      const lost = rows.reduce((s, e) => s + (Number(e.data.lost) || 0), 0);
      return ratioPct(lost, sent);
    }),
    change: "points",
  });
  const start = attackStartMs(events);
  const firstFailure =
    start === null
      ? null
      : checks.find((check) => check.t >= start && !check.answered);
  add({
    key: "time_to_first_failure",
    label: "First failed website check",
    unit: "s",
    group: "Service",
    definition:
      "Seconds from the attack start to the first website check that failed; empty if none failed. In a no-defense run this is how long the service lasts.",
    value:
      firstFailure && start !== null ? (firstFailure.t - start) / 1000 : null,
    note: firstFailure
      ? undefined
      : "no check failed during or after the attack",
  });

  // -- Network and control plane ----------------------------------------------------
  const traffic = trafficSeries(events, topology, experiment).points;
  add({
    key: "victim_pps",
    label: "Packets delivered to the victims",
    unit: "per_s",
    group: "Network",
    definition: "Packets per second the switches sent on the victims' links.",
    phases: perPhase((phase) =>
      mean(numbers(byPhase(traffic, spans, phase).map((p) => p.victim))),
    ),
    change: "relative",
  });
  add({
    key: "attacker_pps",
    label: "Packets sent by the attackers",
    unit: "per_s",
    group: "Network",
    definition: "Packets per second received from the attackers' links.",
    phases: perPhase((phase) =>
      mean(numbers(byPhase(traffic, spans, phase).map((p) => p.attackers))),
    ),
    change: "relative",
  });
  const controller = controllerSeries(events);
  add({
    key: "packet_in_sent",
    label: "Packet-Ins sent by the switches",
    unit: "per_s",
    group: "Network",
    definition:
      "Packets that missed every rule and were sent to the controller, per second (table-miss counters).",
    phases: perPhase((phase) =>
      mean(numbers(byPhase(controller.sent, spans, phase).map((p) => p.rate))),
    ),
    change: "relative",
  });
  add({
    key: "packet_in_handled",
    label: "Packet-Ins handled by Ryu",
    unit: "per_s",
    group: "Network",
    definition: "Packet-In messages the controller processed per second.",
    phases: perPhase((phase) =>
      mean(
        numbers(byPhase(controller.handled, spans, phase).map((p) => p.rate)),
      ),
    ),
    change: "relative",
  });
  const rules = controller.rules.filter(
    (point): point is { t: number; count: number } => point.count !== null,
  );
  add({
    key: "flow_rules",
    label: "Flow rules in all switches (mean)",
    unit: "count",
    group: "Network",
    definition: "Rules held by all switches together, from each poll.",
    phases: perPhase((phase) =>
      mean(byPhase(rules, spans, phase).map((p) => p.count)),
    ),
    change: "relative",
  });
  const attackRules = byPhase(rules, spans, "attack");
  const top = attackRules.reduce<{ t: number; count: number } | null>(
    (best, point) => (best === null || point.count > best.count ? point : best),
    null,
  );
  const baselineRules = mean(
    byPhase(rules, spans, "baseline").map((p) => p.count),
  );
  add({
    key: "flow_rules_peak_attack",
    label: "Flow rules peak (attack)",
    unit: "count",
    group: "Network",
    definition: "Most rules held by all switches during the attack.",
    value: top?.count ?? null,
  });
  add({
    key: "flow_rule_growth",
    label: "Flow-rule growth",
    unit: "per_s",
    group: "Network",
    definition:
      "(Attack peak − baseline mean) rules / seconds from the attack start to that peak.",
    value:
      top !== null && baselineRules !== null && start !== null && top.t > start
        ? (top.count - baselineRules) / ((top.t - start) / 1000)
        : null,
  });

  // -- Response -------------------------------------------------------------------
  const firstResponse = analysis.responses.find(
    (row) => row.onAttacker && row.offsetS !== null,
  );
  const noResponse = !mitigation
    ? "response off in this run"
    : response.dry_run
      ? "dry run: nothing was applied"
      : "no response against an attacker";
  add({
    key: "response_time",
    label: "Response time",
    unit: "s",
    group: "Response",
    definition:
      "Seconds from the attack start to the first response the controller applied against an attacker.",
    ...(firstResponse
      ? { value: firstResponse.offsetS }
      : notApplicable(noResponse)),
  });
  add({
    key: "detection_to_response",
    label: "Detection to response",
    unit: "s",
    group: "Response",
    definition:
      "First response against an attacker minus the first attacker naming (confirmation included).",
    ...(firstResponse && timing.offsets.length
      ? { value: (firstResponse.offsetS as number) - timing.offsets[0] }
      : notApplicable(noResponse)),
  });
  add({
    key: "attackers_responded",
    label: "Attackers acted on",
    unit: "count",
    group: "Response",
    definition: "Distinct attackers the controller limited or blocked.",
    value: new Set(
      analysis.responses
        .filter((row) => row.onAttacker)
        .map((row) => row.host ?? row.source),
    ).size,
  });
  add({
    key: "collateral",
    label: "Others acted on",
    unit: "count",
    group: "Response",
    definition:
      "Distinct legitimate clients or victims the controller limited or blocked: false alarms that reached the network.",
    value: analysis.collateral.length,
    note: analysis.collateral.length
      ? analysis.collateral.join(", ")
      : undefined,
  });
  const responseMs =
    start !== null && firstResponse?.offsetS != null
      ? start + firstResponse.offsetS * 1000
      : null;
  const victimRate = (from: number, to: number) =>
    mean(
      numbers(
        traffic
          .filter(
            (p) => p.t >= from && p.t < to && phaseOf(spans, p.t) === "attack",
          )
          .map((p) => p.victim),
      ),
    );
  const before =
    start !== null && responseMs !== null
      ? victimRate(start, responseMs)
      : null;
  const after =
    responseMs !== null
      ? victimRate(responseMs + EVALUATION.responseSettleS * 1000, Infinity)
      : null;
  add({
    key: "mitigation_effectiveness",
    label: "Mitigation effectiveness",
    unit: "pct",
    group: "Response",
    definition: `1 − (packets/s delivered to the victims from ${EVALUATION.responseSettleS} s after the first response to the attack end) / (packets/s delivered between the attack start and that response).`,
    ...(before !== null && after !== null && before > 0
      ? { value: (1 - after / before) * 100 }
      : notApplicable(
          firstResponse ? "not enough traffic samples" : noResponse,
        )),
  });

  // -- Recovery (equations 8 and 9 of the proposal) ---------------------------------
  const stopped = events.find((event) => event.kind === "attack_stopped");
  const tStop = stopped ? at(stopped) : null;
  const service = victimRecovery(
    checks,
    experiment.victims,
    spans,
    tStop,
    runEnd,
  );
  const allRecovered = service.perVictim.every((item) => item.seconds !== null);
  add({
    key: "service_recovery",
    label: "Service recovery time",
    unit: "s",
    group: "Recovery",
    definition:
      "t_stable − t_stop. t_stable is the first of 10 website checks in a row, after the attack stops, that are answered with HTTP 200 and no slower than the worse of twice the baseline 95th percentile and that percentile + 20 ms. With several victims, the latest of them.",
    ...(allRecovered && service.perVictim.length
      ? {
          value: Math.max(
            ...service.perVictim.map((item) => item.seconds as number),
          ),
        }
      : notApplicable(service.overall)),
  });
  const controllerOutcome = judgeController(
    cpu.ryu.map((point, index) => ({
      t: point.t,
      cpu: point.cpu,
      rate: controller.handled[index]?.rate ?? null,
    })),
    spans,
    tStop,
  );
  add({
    key: "controller_recovery",
    label: "Controller recovery time",
    unit: "s",
    group: "Recovery",
    definition:
      "t_stable − t_stop. t_stable is the first controller sample after which, for 10 s, Ryu's CPU stays within 10 points of its baseline peak and its Packet-In rate within the worse of twice the baseline peak and that peak + 5/s.",
    ...(controllerOutcome.kind === "recovered" && tStop !== null
      ? { value: (controllerOutcome.at - tStop) / 1000 }
      : notApplicable(recoveryText(controllerOutcome, tStop, runEnd))),
  });

  // -- Is this run usable? ----------------------------------------------------------
  const problems: string[] = [];
  const status = run?.status;
  if (events.some((event) => event.kind === "stop_requested"))
    problems.push("The run was stopped before it finished.");
  else if (status && !active && !["completed", "idle"].includes(status))
    problems.push(`The run ended as “${status}”, not completed.`);
  if (!events.some((event) => event.kind === "attack_stopped") && !active)
    problems.push("The record has no end of the attack.");
  if (analysis.droppedEvents > 0)
    problems.push(
      `The lab dropped ${analysis.droppedEvents} telemetry events under load, so a detection or response may be missing.`,
    );
  if (entropy) {
    const warmup = warmupSeconds(config.entropy ?? {});
    const baseline = spanSeconds(spans, "baseline");
    if (warmup !== null && baseline !== null && baseline < warmup)
      problems.push(
        `The baseline (${Math.round(baseline)} s) was shorter than the entropy warm-up (${Math.round(warmup)} s), so the detector was still learning when the attack began.`,
      );
  }
  if (!byPhase(checks, spans, "attack").length && !active)
    problems.push("No website checks were recorded during the attack.");
  // A controller that crashed, even partly, is visible in its own output (the
  // Commands tab) or in the controller_error events it sends.
  const controllerIds = new Set(
    events
      .filter((e) => e.kind === "command" && e.data.node === "controller")
      .map((e) => e.data.id),
  );
  const controllerOutput = events
    .filter((e) => e.kind === "command_output" && controllerIds.has(e.data.id))
    .map((e) => String(e.data.text ?? ""))
    .join("\n");
  const reported = events.filter((e) => e.kind === "controller_error");
  if (
    reported.length ||
    /Traceback|uncaught exception/.test(controllerOutput)
  ) {
    const line =
      controllerOutput.match(/^\s*(\w+(?:Error|Exception)\b[^\n]*)$/m)?.[1] ??
      (reported[0] ? String(reported[0].data.error ?? "") : "");
    problems.push(
      `The controller hit an internal error during the run${line ? ` (${line.slice(0, 160)})` : ""}, so its statistics and detections may be incomplete. Its output is in the Commands tab.`,
    );
  }
  if (!events.some((event) => event.kind === "controller") && !active)
    problems.push(
      "The controller sent no samples during the run (no CPU, Packet-In, flow-rule or judged-flow data), so the detection, cost and control-plane numbers are missing.",
    );
  if (!active && service.overall === "baseline too short to judge")
    problems.push(
      "The baseline was too short to learn the website's normal response time, so recovery cannot be measured (the protocol uses 300 s).",
    );
  const recoverySeconds = spanSeconds(spans, "recovery");
  if (
    !active &&
    recoverySeconds !== null &&
    recoverySeconds < RECOVERY_CHECKS_NEEDED
  )
    problems.push(
      `The recovery phase (${Math.round(recoverySeconds)} s) was shorter than the ${RECOVERY_CHECKS_NEEDED} website checks in a row that recovery needs (the protocol uses 300 s).`,
    );
  const notReady = events.some(
    (event) =>
      event.kind === "detector" &&
      phaseOf(spans, at(event)) === "attack" &&
      event.data.status !== undefined &&
      event.data.status !== "ready",
  );
  if (notReady && !off)
    problems.push("The detector service was not ready during the attack.");
  add({
    key: "valid",
    label: "Valid run",
    unit: "text",
    group: "Validity",
    definition:
      "yes when none of the problems listed in validity_notes applies.",
    value: active ? null : problems.length ? "no" : "yes",
  });
  add({
    key: "validity_notes",
    label: "Problems",
    unit: "text",
    group: "Validity",
    definition: "Why the run should not be counted.",
    value: problems.join(" "),
  });

  return {
    final: !active && analysis.attackOver,
    analysis,
    metrics,
    problems,
    detector,
  };
}

// -- Formatting and files -----------------------------------------------------------

function trim(value: number, digits: number): string {
  const factor = 10 ** digits;
  const rounded = Math.round(value * factor) / factor;
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(digits);
}

export function formatValue(value: Value | undefined, unit: Unit): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "string") return value;
  switch (unit) {
    case "pct":
      return `${trim(value, 1)} %`;
    case "s":
      return `${trim(value, 1)} s`;
    case "ms":
      return `${trim(value, value < 10 ? 2 : 1)} ms`;
    case "mib":
      return `${trim(value, 1)} MiB`;
    case "count":
      return trim(value, 1);
    case "per_s":
      return `${trim(value, 1)}/s`;
    case "score":
      return trim(value, 3);
    default:
      return String(value);
  }
}

/** Attack against baseline: relative for times and rates, points for shares. */
export function formatChange(metric: Metric): string {
  const base = metric.phases?.baseline ?? null;
  const attack = metric.phases?.attack ?? null;
  if (base === null || attack === null) return "—";
  if (metric.change === "points") {
    const delta = attack - base;
    return `${delta > 0 ? "+" : ""}${trim(delta, 1)} pts`;
  }
  if (base === 0) return attack === 0 ? "0 %" : "from 0";
  const pct = ((attack - base) / base) * 100;
  return `${pct > 0 ? "+" : ""}${trim(pct, 1)} %`;
}

const suffix: Record<Unit, string> = {
  pct: "_pct",
  s: "_s",
  ms: "_ms",
  mib: "_mib",
  count: "",
  per_s: "_per_s",
  score: "",
  text: "",
};

/** Column name in the CSV: the key plus its unit, so a column says what it holds. */
export function columnName(metric: Metric, phase?: Phase): string {
  return `${metric.key}${phase ? `_${phase}` : ""}${suffix[metric.unit]}`;
}

function rawValue(value: Value | undefined): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "number") return trim(value, 4);
  return value;
}

/** The run as one row: the same columns, in the same order, for every run. */
export function resultRow(results: RunResults): [string, string][] {
  const row: [string, string][] = [];
  for (const metric of results.metrics) {
    if (metric.phased)
      for (const phase of PHASES)
        row.push([
          columnName(metric, phase),
          rawValue(metric.phases?.[phase] ?? null),
        ]);
    else row.push([columnName(metric), rawValue(metric.value)]);
  }
  return row;
}

const quote = (text: string) =>
  /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;

/** Header plus one data row; rows of several runs can be stacked under one header. */
export function resultRowCsv(results: RunResults): string {
  const row = resultRow(results);
  return [
    row.map(([name]) => quote(name)).join(","),
    row.map(([, value]) => quote(value)).join(","),
  ].join("\n");
}

/** Every metric on its own line with its definition, for the methodology chapter. */
export function metricsTableCsv(results: RunResults): string {
  const lines = ["group,metric,column,phase,value,shown,definition"];
  for (const metric of results.metrics) {
    const cases: [Phase | "", Value | undefined][] = metric.phased
      ? PHASES.map((phase) => [phase, metric.phases?.[phase] ?? null])
      : [["", metric.value]];
    for (const [phase, value] of cases)
      lines.push(
        [
          metric.group,
          metric.label,
          columnName(metric, phase || undefined),
          phase,
          rawValue(value),
          value === null || value === undefined
            ? (metric.note ?? "")
            : formatValue(value, metric.unit),
          metric.definition,
        ]
          .map((text) => quote(String(text)))
          .join(","),
      );
  }
  return lines.join("\n");
}
