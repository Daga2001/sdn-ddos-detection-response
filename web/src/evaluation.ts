/**
 * The evaluation metrics the thesis proposal defines (sections 2.2.8, 2.2.9 and
 * 3.4.1, Table 3.1, equations 2 to 9), computed only from what a run recorded.
 *
 * Pure functions: no chart library, no clock. Every row names the proposal
 * section or equation it implements and the unit it counts. When the run does
 * not record what the proposal asks for, the row says so instead of estimating.
 *
 * Ground truth is the experiment itself, as in the Detection results tab: the
 * hosts made attackers are the positives and the legitimate clients the
 * negatives. The victim is neither.
 */
import { analyzeDetection, flaggedAddresses } from "./detection.ts";
import {
  checkSeries,
  controllerSeries,
  cpuSeries,
  judgeController,
  judgeService,
  mean,
  median,
  peak,
  phaseOf,
  pingSeries,
  recoveryText,
  trafficSeries,
  versus,
} from "./traffic.ts";
import type { CheckPoint } from "./traffic.ts";
import { legitimateClients, phaseSpans } from "./types.ts";
import type { Experiment, Observation, PhaseSpan, Topology } from "./types.ts";

export const EVALUATION = {
  /** An attacker named within this many seconds of the attack start counts as early (EDR). */
  earlyDetectionS: 10,
  /** Equal-width probability bins of the expected calibration error (ECE). */
  calibrationBins: 10,
  /** Seconds after the first response before the remaining attack traffic is measured. */
  responseSettleS: 10,
} as const;

export const EVALUATION_HINT =
  "WHAT: the metrics the thesis proposal promises (section 3.4.1 and Table 3.1), for this run only. HOW TO READ: Model rows score the detector against the experiment's own roles (attackers are positives, legitimate clients negatives, the victim is reported apart); Network rows compare the legitimate traffic of the attack phase with the baseline; System rows are the controller's cost; Recovery uses equations 8 and 9. A dash means the run did not record that input. WHY: the proposal's results chapter needs the same numbers for every detector, LLM or entropy, computed the same way. One run is one sample: report the mean and a confidence interval over repeated runs (docs/evaluation-protocol.md).";

export type MetricGroup =
  | "Model"
  | "Network"
  | "System"
  | "Response"
  | "Recovery";

export type MetricRow = {
  group: MetricGroup;
  label: string;
  value: string;
  /** Formula or measurement rule. */
  definition: string;
  /** Where the proposal defines it. */
  source: string;
};

type Phase = "baseline" | "attack" | "recovery";

const bareIp = (ip: string) => ip.split("/")[0];

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function at(event: Observation): number {
  return Date.parse(event.data?.observed_at ?? event.ts);
}

function round(value: number, digits = 1): string {
  const factor = 10 ** digits;
  const rounded = Math.round(value * factor) / factor;
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(digits);
}

function pct(value: number | null, digits = 1): string {
  return value === null ? "—" : `${round(value * 100, digits)}%`;
}

function seconds(value: number | null): string {
  return value === null ? "—" : `${round(value)} s`;
}

/** Percentage-point difference: the honest change for a rate whose baseline is often 0. */
export function pointsDelta(
  phase: number | null,
  baseline: number | null,
): string {
  if (phase === null || baseline === null) return "—";
  const delta = phase - baseline;
  const text = round(delta);
  return `${delta > 0 ? "+" : ""}${text} pp`;
}

function attackStartMs(events: Observation[]): number | null {
  const started = events.find((event) => event.kind === "attack_started");
  const phase = events.find(
    (event) => event.kind === "phase" && event.data.state === "attack",
  );
  const stamp = (started ?? phase)?.ts;
  if (!stamp) return null;
  const ms = Date.parse(stamp);
  return Number.isFinite(ms) ? ms : null;
}

/**
 * Seconds from the attack start to the first time each attacker was named, for the
 * attackers that were named at or after the start. A response against a source is
 * evidence of a detection, as in the Detection results tab.
 */
export function attackerDetectionOffsets(
  events: Observation[],
  topology: Topology | null,
  experiment: Experiment | null,
): { total: number; offsets: number[] } {
  const attackers = new Set(experiment?.attackers ?? []);
  const start = attackStartMs(events);
  if (start === null || attackers.size === 0)
    return { total: attackers.size, offsets: [] };
  const byIp = new Map(
    (topology?.hosts ?? []).map((host) => [bareIp(host.ip), host.name]),
  );
  const first = new Map<string, number>();
  const note = (address: string, ms: number) => {
    const name = byIp.get(address);
    if (!name || !attackers.has(name) || !Number.isFinite(ms) || ms < start)
      return;
    const offset = (ms - start) / 1000;
    const known = first.get(name);
    if (known === undefined || offset < known) first.set(name, offset);
  };
  for (const event of events) {
    if (event.kind === "detection")
      for (const address of flaggedAddresses(event.data))
        note(address, Date.parse(event.ts));
    else if (event.kind === "mitigation_requested")
      note(String(event.data.ipv4_src ?? ""), Date.parse(event.ts));
  }
  return {
    total: attackers.size,
    offsets: [...first.values()].sort((a, b) => a - b),
  };
}

export type FlowDecisions = {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  /** [probability of attack, truth] for every scored decision. */
  scored: [number, 0 | 1][];
  /** Judged rows with no ground truth (victim replies, attackers after the attack). */
  skipped: number;
};

/**
 * Decision-level confusion from the flow rows the controller annotated with the
 * model's probability (`prob_ddos`). A row is one judged flow on one switch in one
 * poll. Truth: an attacker's flow during the attack phase is an attack; a legitimate
 * client's flow, or an attacker's flow during the baseline, is normal. Everything
 * else (the victim's replies, attackers' leftover counters after the attack) has no
 * unambiguous label and is skipped.
 */
export function flowDecisions(
  events: Observation[],
  topology: Topology | null,
  experiment: Experiment | null,
  spans: PhaseSpan[],
): FlowDecisions {
  const result: FlowDecisions = {
    tp: 0,
    fp: 0,
    fn: 0,
    tn: 0,
    scored: [],
    skipped: 0,
  };
  if (!topology || !experiment) return result;
  const ipOf = new Map(
    topology.hosts.map((host) => [host.name, bareIp(host.ip)]),
  );
  const attackers = new Set(
    experiment.attackers.map((name) => ipOf.get(name)).filter(Boolean),
  );
  const legit = new Set(
    legitimateClients(topology, experiment)
      .map((name) => ipOf.get(name))
      .filter(Boolean),
  );
  for (const event of events) {
    if (event.kind !== "flows") continue;
    const phase = phaseOf(spans, at(event));
    for (const row of event.data.rows ?? []) {
      const probability = finite(row?.prob_ddos);
      if (probability === null) continue;
      const source = typeof row.ipv4_src === "string" ? row.ipv4_src : null;
      let truth: 0 | 1 | null = null;
      if (source !== null && attackers.has(source))
        truth = phase === "attack" ? 1 : phase === "baseline" ? 0 : null;
      else if (source !== null && legit.has(source)) truth = 0;
      if (truth === null) {
        result.skipped += 1;
        continue;
      }
      const predicted = row.label === 1 || row.label === "1";
      if (truth === 1 && predicted) result.tp += 1;
      else if (truth === 1) result.fn += 1;
      else if (predicted) result.fp += 1;
      else result.tn += 1;
      result.scored.push([Math.min(1, Math.max(0, probability)), truth]);
    }
  }
  return result;
}

/**
 * Brier score and expected calibration error (equal-width bins) of the reported
 * probability of attack. 0 is perfect for both.
 */
export function calibration(
  scored: [number, 0 | 1][],
  bins: number = EVALUATION.calibrationBins,
): { brier: number | null; ece: number | null; n: number } {
  if (!scored.length) return { brier: null, ece: null, n: 0 };
  const brier = mean(
    scored.map(([probability, truth]) => (probability - truth) ** 2),
  );
  const buckets = Array.from({ length: bins }, () => ({ n: 0, p: 0, y: 0 }));
  for (const [probability, truth] of scored) {
    const index = Math.min(
      bins - 1,
      Math.max(0, Math.floor(probability * bins)),
    );
    buckets[index].n += 1;
    buckets[index].p += probability;
    buckets[index].y += truth;
  }
  const ece = buckets.reduce(
    (sum, bucket) =>
      bucket.n === 0
        ? sum
        : sum +
          (bucket.n / scored.length) *
            Math.abs(bucket.y / bucket.n - bucket.p / bucket.n),
    0,
  );
  return { brier, ece, n: scored.length };
}

/**
 * Equations 8 and 9: T_recovery = t_stable - t_stop for each victim's website
 * checks, and for several victims the latest of them. Null `at` means not recovered.
 */
export function victimRecovery(
  checks: CheckPoint[],
  victims: string[],
  spans: PhaseSpan[],
  tStop: number | null,
  runEnd: number,
): {
  perVictim: { victim: string; text: string; seconds: number | null }[];
  overall: string;
} {
  const tagged = checks.some((check) => check.target !== null);
  const groups = tagged
    ? victims.map((victim) => ({
        victim,
        checks: checks.filter((check) => check.target === victim),
      }))
    : [{ victim: victims.join(", "), checks }];
  const perVictim = groups.map((group) => {
    const outcome = judgeService(group.checks, spans, tStop, runEnd);
    return {
      victim: group.victim,
      text: recoveryText(outcome, tStop, runEnd),
      seconds:
        outcome.kind === "recovered" && tStop !== null
          ? (outcome.at - tStop) / 1000
          : null,
    };
  });
  const recovered = perVictim.map((item) => item.seconds);
  const overall =
    perVictim.length &&
    recovered.every((value): value is number => value !== null)
      ? `${round(Math.max(...recovered))} s`
      : (perVictim.find((item) => item.seconds === null)?.text ?? "—");
  return { perVictim, overall };
}

function byPhase<T extends { t: number }>(
  items: T[],
  spans: PhaseSpan[],
  phase: Phase,
): T[] {
  return items.filter((item) => phaseOf(spans, item.t) === phase);
}

function triple(
  values: Record<Phase, number | null>,
  unit: string,
  digits = 1,
): string {
  const show = (value: number | null) =>
    value === null ? "—" : `${round(value, digits)}${unit}`;
  return `baseline ${show(values.baseline)} · attack ${show(values.attack)} · recovery ${show(values.recovery)}`;
}

/** Every metric of the proposal for one run, or null for an observation without attackers. */
export function proposalMetrics(
  events: Observation[],
  topology: Topology | null,
  experiment: Experiment | null,
  runEnd: number,
): MetricRow[] | null {
  if (!experiment?.attackers?.length) return null;
  if (!events.some((event) => event.kind === "phase")) return null;
  const spans = phaseSpans(events, runEnd);
  const analysis = analyzeDetection(events, topology, experiment, false);
  const mode = analysis.config?.mode as string | undefined;
  const detectorOff = mode === "off";
  const rows: MetricRow[] = [];
  const add = (row: MetricRow) => rows.push(row);

  // -- Model evaluation (sections 2.2.8, 2.2.9.1 and 3.4.1) ---------------------
  const c = analysis.confusion;
  const m = analysis.metrics;
  const offDetail = "no detector ran in this run";
  const model = (value: string) => (detectorOff ? offDetail : value);
  add({
    group: "Model",
    label: "Confusion matrix (hosts)",
    value: model(`TP ${c.vp} · FN ${c.fn} · FP ${c.fp} · TN ${c.vn}`),
    definition:
      "Unit: one host per run. TP attacker named at least once; FN attacker never named; FP legitimate client named; TN legitimate client never named.",
    source: "§2.2.7, §3.4.1 (error matrix)",
  });
  add({
    group: "Model",
    label: "Detection Rate (DR)",
    value: model(pct(m.recall)),
    definition: "DR = TP / (TP + FN), the same value as recall.",
    source: "§2.2.8 eq. 2 and 3",
  });
  add({
    group: "Model",
    label: "False Alarm Rate (FAR)",
    value: model(pct(m.falsePositiveRate)),
    definition: "FAR = FP / (FP + TN) over the legitimate clients.",
    source: "§2.2.8 eq. 7",
  });
  add({
    group: "Model",
    label: "Precision · Accuracy · F1",
    value: model(`${pct(m.precision)} · ${pct(m.accuracy)} · ${pct(m.f1)}`),
    definition:
      "Pre = TP / (TP + FP); Acc = (TP + TN) / (TP + TN + FP + FN); F1 = 2·Recall·Pre / (Recall + Pre).",
    source: "§2.2.8 eq. 4–6",
  });
  const timing = attackerDetectionOffsets(events, topology, experiment);
  const averageS = mean(timing.offsets);
  add({
    group: "Model",
    label: "Average attack detection time",
    value: model(
      averageS === null
        ? "no attacker named after the attack started"
        : `${seconds(averageS)} (${timing.offsets.length} of ${timing.total} attackers; first ${seconds(timing.offsets[0])}, last ${seconds(timing.offsets[timing.offsets.length - 1])})`,
    ),
    definition:
      "Mean, over the attackers named at or after the attack start, of the seconds from the attack start to their first naming. Undetected attackers are not in the mean: read it with DR.",
    source: "§2.2.9.1",
  });
  const early = timing.offsets.filter(
    (offset) => offset <= EVALUATION.earlyDetectionS,
  ).length;
  add({
    group: "Model",
    label: `Early Detection Rate (EDR, ≤ ${EVALUATION.earlyDetectionS} s)`,
    value: model(
      timing.total
        ? `${pct(early / timing.total)} (${early} of ${timing.total})`
        : "—",
    ),
    definition: `Share of all attackers named within ${EVALUATION.earlyDetectionS} s of the attack start (about two 5 s polls). The proposal names EDR without a horizon; this one is fixed in docs/evaluation-protocol.md.`,
    source: "§2.1.6",
  });
  const decisions = flowDecisions(events, topology, experiment, spans);
  const decisionCount =
    decisions.tp + decisions.fp + decisions.fn + decisions.tn;
  const flowDr =
    decisions.tp + decisions.fn
      ? decisions.tp / (decisions.tp + decisions.fn)
      : null;
  const flowFar =
    decisions.fp + decisions.tn
      ? decisions.fp / (decisions.fp + decisions.tn)
      : null;
  const noProbability =
    mode === "entropy"
      ? "not applicable: the entropy detector reports no probability"
      : "no judged flow rows with a probability in this view";
  add({
    group: "Model",
    label: "DR · FAR per judged flow",
    value: detectorOff
      ? offDetail
      : decisionCount
        ? `${pct(flowDr)} · ${pct(flowFar)} (${decisionCount} decisions: TP ${decisions.tp} · FN ${decisions.fn} · FP ${decisions.fp} · TN ${decisions.tn}; ${decisions.skipped} without ground truth)`
        : noProbability,
    definition:
      "Unit: one judged flow on one switch in one poll, as the controller logged it. Attackers' flows in the attack phase are attacks; legitimate clients' flows, and attackers' flows in the baseline, are normal. Victim replies are skipped.",
    source: "§3.4.1 (classification logs vs ground-truth labels)",
  });
  const calibrated = calibration(decisions.scored);
  add({
    group: "Model",
    label: "Confidence calibration",
    value: detectorOff
      ? offDetail
      : calibrated.n
        ? `Brier ${round(calibrated.brier ?? 0, 3)} · ECE ${round(calibrated.ece ?? 0, 3)} (${calibrated.n} decisions)`
        : noProbability,
    definition: `Brier = mean((p − y)²); ECE = Σ (n_b / N)·|mean(y) − mean(p)| over ${EVALUATION.calibrationBins} equal-width bins of p, the reported probability of attack. 0 is perfect for both.`,
    source: "§3.4.1 (confidence calibration)",
  });
  add({
    group: "Model",
    label: "Output consistency",
    value:
      mode === "llm"
        ? "measured offline: scripts/compare_llms.py --repeats N (column consist)"
        : "not applicable to this detector",
    definition:
      "Share of repeated queries over the same traffic window that give the same verdict. A live run cannot measure it: the controller caches one verdict per identical sample (SDN_LLM_CACHE_SIZE) and decodes at temperature 0.",
    source: "§3.4.1 (output consistency)",
  });

  // -- Network evaluation (section 3.4.1, legitimate traffic) -------------------
  const phases: Phase[] = ["baseline", "attack", "recovery"];
  const read = (pick: (phase: Phase) => number | null) =>
    Object.fromEntries(phases.map((phase) => [phase, pick(phase)])) as Record<
      Phase,
      number | null
    >;
  const pings = pingSeries(events);
  const rtt = read((phase) =>
    mean(byPhase(pings.rtt, spans, phase).map((point) => point.rtt)),
  );
  add({
    group: "Network",
    label: "Latency (mean ping RTT)",
    value: pings.rtt.length
      ? `${triple(rtt, " ms", 2)} · degradation ${versus(rtt.attack, rtt.baseline)}`
      : "no pings recorded",
    definition:
      "Mean round-trip time of the 5/s pings from one legitimate client to each victim. Degradation = (attack − baseline) / baseline.",
    source: "§2.2.9.2, §3.4.1",
  });
  const loss = read((phase) => {
    const rows = events.filter(
      (event) => event.kind === "ping" && phaseOf(spans, at(event)) === phase,
    );
    const sent = rows.reduce(
      (sum, event) => sum + (Number(event.data.sent) || 0),
      0,
    );
    const lost = rows.reduce(
      (sum, event) => sum + (Number(event.data.lost) || 0),
      0,
    );
    return sent ? (lost / sent) * 100 : null;
  });
  add({
    group: "Network",
    label: "Packet loss (ping)",
    value:
      loss.baseline === null && loss.attack === null
        ? "no pings recorded"
        : `${triple(loss, "%")} · degradation ${pointsDelta(loss.attack, loss.baseline)}`,
    definition:
      "Lost pings / sent pings per phase. Degradation in percentage points, because the baseline loss is usually 0 and a relative change would be undefined.",
    source: "§3.4.1",
  });
  const checks = checkSeries(events);
  const availability = read((phase) => {
    const rows = byPhase(checks, spans, phase);
    return rows.length
      ? (rows.filter((check) => check.answered).length / rows.length) * 100
      : null;
  });
  const serviceTime = read((phase) =>
    median(
      byPhase(checks, spans, phase)
        .filter((check) => check.answered && check.total !== null)
        .map((check) => check.total as number),
    ),
  );
  add({
    group: "Network",
    label: "Legitimate service availability",
    value: checks.length
      ? `${triple(availability, "%")} · degradation ${pointsDelta(availability.attack, availability.baseline)}`
      : "no website checks recorded",
    definition:
      "Website checks answered with HTTP 200 / checks made, per phase (1 check per second from the legitimate clients).",
    source: "§1.5, §3.4.1 (legitimate traffic degradation)",
  });
  add({
    group: "Network",
    label: "Legitimate request time (median)",
    value: checks.length
      ? `${triple(serviceTime, " ms")} · degradation ${versus(serviceTime.attack, serviceTime.baseline)}`
      : "no website checks recorded",
    definition:
      "Median total time of the answered website checks. Degradation = (attack − baseline) / baseline.",
    source: "§3.4.1 (legitimate traffic degradation)",
  });
  add({
    group: "Network",
    label: "Bandwidth (iperf -u)",
    value: "not recorded: the lab runs no iperf stream",
    definition:
      "The proposal measures throughput and datagram loss with iperf in UDP mode between legitimate pairs. Until the lab runs it, report the link rates of the Traffic chart only as offered load, not as legitimate goodput.",
    source: "§2.2.9.3, §3.4.1",
  });

  // -- System evaluation (section 3.4.1) ----------------------------------------
  const cpu = cpuSeries(events);
  const ryuCpu = read((phase) =>
    mean(
      byPhase(cpu.ryu, spans, phase)
        .map((point) => point.cpu)
        .filter((value): value is number => value !== null),
    ),
  );
  const ryuCpuPeak = peak(
    byPhase(cpu.ryu, spans, "attack")
      .map((point) => point.cpu)
      .filter((value): value is number => value !== null),
  );
  add({
    group: "System",
    label: "Controller CPU (Ryu, mean)",
    value: cpu.ryu.length
      ? `${triple(ryuCpu, "%")} · attack peak ${ryuCpuPeak === null ? "—" : `${round(ryuCpuPeak)}%`}`
      : "no controller samples recorded",
    definition:
      "psutil CPU percent of the Ryu process, sampled every second (the proposal asks for at least every 30 s).",
    source: "§2.2.9.4, §3.4.1",
  });
  const ram = read((phase) =>
    peak(
      byPhase(cpu.ryu, spans, phase)
        .map((point) => point.ram)
        .filter((value): value is number => value !== null)
        .map((bytes) => bytes / 1048576),
    ),
  );
  add({
    group: "System",
    label: "Controller RAM (Ryu RSS, peak)",
    value: cpu.ryu.length
      ? `${triple(ram, " MiB")} · change ${versus(ram.attack, ram.baseline)}`
      : "no controller samples recorded",
    definition: "Highest resident memory of the Ryu process per phase.",
    source: "§2.2.9.4, §3.4.1",
  });
  const ovs = read((phase) =>
    mean(
      byPhase(cpu.ovs, spans, phase)
        .map((point) => point.cpu)
        .filter((value): value is number => value !== null),
    ),
  );
  add({
    group: "System",
    label: "Data-plane CPU (Open vSwitch, mean)",
    value: cpu.ovs.some((point) => point.cpu !== null)
      ? triple(ovs, "%")
      : "no Open vSwitch samples recorded",
    definition:
      "CPU of ovs-vswitchd only; kernel forwarding and the Mininet host shells are not sampled per process.",
    source: "§3.4.1 (per-process Mininet consumption)",
  });
  const controller = controllerSeries(events);
  const handled = read((phase) =>
    mean(
      byPhase(controller.handled, spans, phase)
        .map((point) => point.rate)
        .filter((value): value is number => value !== null),
    ),
  );
  const handledPeak = peak(
    byPhase(controller.handled, spans, "attack")
      .map((point) => point.rate)
      .filter((value): value is number => value !== null),
  );
  add({
    group: "System",
    label: "Controller throughput (Packet-Ins handled/s)",
    value: controller.handled.length
      ? `${triple(handled, "")} · attack peak ${handledPeak === null ? "—" : round(handledPeak)}`
      : "no Packet-In counter recorded",
    definition:
      "Change of Ryu's internal Packet-In counter divided by the elapsed time between samples.",
    source: "§3.4.1",
  });
  const rules = controller.rules.filter(
    (point): point is { t: number; count: number } => point.count !== null,
  );
  const baselineRules = mean(
    byPhase(rules, spans, "baseline").map((point) => point.count),
  );
  const attackRules = byPhase(rules, spans, "attack");
  const top = attackRules.reduce<{ t: number; count: number } | null>(
    (best, point) => (best === null || point.count > best.count ? point : best),
    null,
  );
  const start = attackStartMs(events);
  const growth =
    top !== null && baselineRules !== null && start !== null && top.t > start
      ? (top.count - baselineRules) / ((top.t - start) / 1000)
      : null;
  add({
    group: "System",
    label: "Flow-table growth",
    value: rules.length
      ? `baseline mean ${baselineRules === null ? "—" : round(baselineRules)} rules · attack peak ${top === null ? "—" : top.count} · growth ${growth === null ? "—" : `${round(growth)} rules/s`}`
      : "no flow-rule counts recorded",
    definition:
      "Rules held by all switches (dump-flows count). Growth = (attack peak − baseline mean) / seconds from the attack start to that peak.",
    source: "§3.4.1 (ovs-ofctl dump-flows)",
  });

  // -- Response (section 1.5: response time; section 3.2.2) ---------------------
  const firstResponse = analysis.responses.find(
    (row) => row.onAttacker && row.offsetS !== null,
  );
  const mitigationOn = analysis.config?.mitigation === true;
  add({
    group: "Response",
    label: "Response time",
    value: firstResponse
      ? `${seconds(firstResponse.offsetS)} after the attack started (${firstResponse.action})`
      : mitigationOn
        ? "no response against an attacker"
        : "mitigation off in this run",
    definition:
      "Seconds from the attack start to the first response the controller requested against an attacker.",
    source: "§1.5, §3.2.2",
  });
  const firstDetection = timing.offsets.length ? timing.offsets[0] : null;
  add({
    group: "Response",
    label: "Detection-to-response delay",
    value:
      firstResponse && firstDetection !== null
        ? seconds((firstResponse.offsetS as number) - firstDetection)
        : "—",
    definition:
      "First response against an attacker minus the first attacker naming (confirmation polls and dry-run included).",
    source: "§3.2.2 (decision then response)",
  });
  add({
    group: "Response",
    label: "Responses against non-attackers",
    value: analysis.responses.length
      ? `${analysis.collateral.length}${analysis.collateral.length ? ` (${analysis.collateral.join(", ")})` : ""}`
      : "no responses recorded",
    definition:
      "Distinct legitimate clients or victims the controller acted on: the false alarms that reached the network.",
    source: "§2.1.5 (false positives under flash crowds)",
  });
  const victimPoints = trafficSeries(events, topology, experiment).points;
  const victimRate = (from: number, to: number) =>
    mean(
      victimPoints
        .filter(
          (point) =>
            point.t >= from &&
            point.t < to &&
            phaseOf(spans, point.t) === "attack" &&
            point.victim !== null,
        )
        .map((point) => point.victim as number),
    );
  const responseMs =
    start !== null && firstResponse?.offsetS != null
      ? start + firstResponse.offsetS * 1000
      : null;
  const before =
    start !== null && responseMs !== null
      ? victimRate(start, responseMs)
      : null;
  const after =
    responseMs !== null
      ? victimRate(responseMs + EVALUATION.responseSettleS * 1000, Infinity)
      : null;
  add({
    group: "Response",
    label: "Mitigation effectiveness",
    value:
      before !== null && after !== null && before > 0
        ? `${pct(1 - after / before)} less traffic delivered to the victims (${round(before)} → ${round(after)} packets/s)`
        : "—",
    definition: `1 − (packets/s delivered to the victims from ${EVALUATION.responseSettleS} s after the first response to the attack end) / (packets/s delivered between the attack start and that response).`,
    source: "§3.4.2 (effectiveness of the mitigation)",
  });

  // -- Recovery (equations 8 and 9) ---------------------------------------------
  const stopped = events.find((event) => event.kind === "attack_stopped");
  const tStop = stopped ? at(stopped) : null;
  const recovery = victimRecovery(
    checks,
    experiment.victims,
    spans,
    tStop,
    runEnd,
  );
  add({
    group: "Recovery",
    label:
      experiment.victims.length > 1
        ? "Service recovery time, all victims"
        : "Service recovery time",
    value:
      experiment.victims.length > 1
        ? `${recovery.overall} (${recovery.perVictim.map((item) => `${item.victim}: ${item.text}`).join("; ")})`
        : recovery.overall,
    definition:
      experiment.victims.length > 1
        ? "T = max(t_stable,1 … t_stable,n) − t_stop, t_stable,i being the first of 10 normal checks in a row to victim i (see the phase-summary hint)."
        : "T = t_stable − t_stop, t_stable being the first of 10 normal checks in a row (see the phase-summary hint).",
    source: experiment.victims.length > 1 ? "§3.4.2.4 eq. 9" : "§3.4.2.2 eq. 8",
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
    group: "Recovery",
    label: "Controller recovery time",
    value: recoveryText(controllerOutcome, tStop, runEnd),
    definition:
      "T = t_stable − t_stop, t_stable being the first sample after which Ryu's CPU and Packet-In rate stay in the baseline range for 10 s.",
    source: "§2.2.6, §3.4.2.2 eq. 8",
  });
  return rows;
}

/** The rows as CSV, one metric per line, for the thesis' results tables. */
export function metricsCsv(rows: MetricRow[]): string {
  const quote = (text: string) => `"${text.replace(/"/g, '""')}"`;
  return [
    "group,metric,value,definition,source",
    ...rows.map((row) =>
      [row.group, row.label, row.value, row.definition, row.source]
        .map(quote)
        .join(","),
    ),
  ].join("\n");
}
