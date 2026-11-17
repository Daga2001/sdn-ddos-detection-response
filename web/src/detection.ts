/**
 * Detection results, computed only from what a run recorded.
 *
 * Ground truth is the experiment itself: the hosts the user made attackers are
 * the positives, the hosts that stand in for ordinary users are the negatives.
 * The unit is the host, one case each per run: an attacker the detector named at
 * least once is a true positive (VP), an attacker it never named a false negative
 * (FN), a legitimate client it named a false positive (FP) and one it never named
 * a true negative (VN). The victim is neither: it is reported on its own.
 */
import { legitimateClients, phaseSpans } from "./types.ts";
import type {
  Run,
  DetectionConfig,
  Experiment,
  Observation,
  Topology,
} from "./types.ts";

export type Verdict = "VP" | "FN" | "FP" | "VN";
export type Role = "attacker" | "legit" | "victim";

export type HostRow = {
  name: string;
  ip: string;
  role: Role;
  /** Named as an attacker by the detector at least once. */
  flagged: boolean;
  detections: number;
  /** Seconds after the attack started (negative: before it). */
  firstOffsetS: number | null;
  maxProbability: number | null;
  /** null for the victim, or while an attacker's verdict is still open. */
  verdict: Verdict | null;
  /** Response actions the controller requested against this host. */
  actions: string[];
  /** Named only through the response: its detection event was not recorded. */
  fromResponse?: boolean;
};

export type Confusion = { vp: number; fn: number; fp: number; vn: number };
export type Metrics = {
  precision: number | null;
  recall: number | null;
  falsePositiveRate: number | null;
  specificity: number | null;
  accuracy: number | null;
  f1: number | null;
};
export type ResponseRow = {
  offsetS: number | null;
  source: string;
  host: string | null;
  action: string;
  onAttacker: boolean;
};
export type PhaseService = {
  probes: number;
  ok: number;
  meanLatencyMs: number | null;
};
export type Analysis = {
  /** The run carried an experiment (attackers known). Observation runs do not. */
  hasExperiment: boolean;
  attackStart: number | null;
  /** Verdicts of attackers are final only once the attack is over. */
  attackOver: boolean;
  hosts: HostRow[];
  confusion: Confusion;
  metrics: Metrics;
  /** Seconds from the attack start to the first / the last attacker detected. */
  firstDetectionS: number | null;
  allDetectedS: number | null;
  victimFlagged: string[];
  unknownFlagged: string[];
  detectionEvents: number;
  /** Telemetry events the lab dropped under load: detections may be missing. */
  droppedEvents: number;
  threshold: number | null;
  responses: ResponseRow[];
  collateral: string[];
  service: Record<string, PhaseService>;
  load: {
    baselineKbps: number | null;
    attackMeanKbps: number | null;
    attackPeakKbps: number | null;
    afterResponseKbps: number | null;
  };
  controller: { cpuMax: number | null; ramMaxMiB: number | null };
  config: Record<string, any> | null;
};

const ratio = (numerator: number, denominator: number) =>
  denominator > 0 ? numerator / denominator : null;

export function computeMetrics(c: Confusion): Metrics {
  const precision = ratio(c.vp, c.vp + c.fp);
  const recall = ratio(c.vp, c.vp + c.fn);
  const falsePositiveRate = ratio(c.fp, c.fp + c.vn);
  return {
    precision,
    recall,
    falsePositiveRate,
    specificity: falsePositiveRate === null ? null : 1 - falsePositiveRate,
    accuracy: ratio(c.vp + c.vn, c.vp + c.fn + c.fp + c.vn),
    f1:
      precision !== null && recall !== null && precision + recall > 0
        ? (2 * precision * recall) / (precision + recall)
        : null,
  };
}

const bareIp = (ip: string) => ip.split("/")[0];
const mean = (values: number[]) =>
  values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;

/** Addresses a detection event names: the flow's source plus entropy candidates. */
export function flaggedAddresses(data: Record<string, any>): string[] {
  const names = new Set<string>();
  if (typeof data.ipv4_src === "string") names.add(data.ipv4_src);
  if (Array.isArray(data.candidates))
    for (const item of data.candidates)
      if (typeof item === "string") names.add(item);
  return [...names];
}

export function analyzeDetection(
  events: Observation[],
  topology: Topology | null,
  experiment: Experiment | null,
  active: boolean,
): Analysis {
  // The form may hold attackers before anything ran: score only what a run recorded.
  const hasExperiment =
    !!experiment &&
    experiment.attackers.length > 0 &&
    events.some((e) => e.kind === "phase");
  const hosts = topology?.hosts ?? [];
  const byIp = new Map(hosts.map((h) => [bareIp(h.ip), h]));
  const attackers = new Set(experiment?.attackers ?? []);
  const victims = new Set(experiment?.victims ?? []);
  const legit = new Set(
    topology && experiment ? legitimateClients(topology, experiment) : [],
  );

  const started = events.find((e) => e.kind === "attack_started");
  const phaseAttack = events.find(
    (e) => e.kind === "phase" && e.data.state === "attack",
  );
  const attackStartTs = (started ?? phaseAttack)?.ts;
  const attackStart = attackStartTs ? Date.parse(attackStartTs) : null;
  const attackOver =
    events.some((e) => e.kind === "attack_stopped") ||
    (!active && hasExperiment && attackStart !== null);
  const offset = (ts: string) =>
    attackStart === null ? null : (Date.parse(ts) - attackStart) / 1000;

  const rows = new Map<string, HostRow>();
  const roleOf = (name: string): Role | null =>
    attackers.has(name)
      ? "attacker"
      : victims.has(name)
        ? "victim"
        : legit.has(name)
          ? "legit"
          : null;
  for (const host of hosts) {
    const role = roleOf(host.name);
    if (!role) continue;
    rows.set(host.name, {
      name: host.name,
      ip: bareIp(host.ip),
      role,
      flagged: false,
      detections: 0,
      firstOffsetS: null,
      maxProbability: null,
      verdict: null,
      actions: [],
    });
  }

  const unknown = new Set<string>();
  let detectionEvents = 0;
  let threshold: number | null = null;
  for (const event of events) {
    if (event.kind !== "detection") continue;
    detectionEvents += 1;
    // The entropy detector has no probability threshold (it reports a placeholder of 1).
    if (
      typeof event.data.threshold === "number" &&
      event.data.detector !== "entropy"
    )
      threshold = event.data.threshold;
    for (const address of flaggedAddresses(event.data)) {
      const host = byIp.get(address);
      const row = host ? rows.get(host.name) : undefined;
      if (!row) {
        unknown.add(address);
        continue;
      }
      row.flagged = true;
      row.detections += 1;
      const at = offset(event.ts);
      if (at !== null && (row.firstOffsetS === null || at < row.firstOffsetS))
        row.firstOffsetS = at;
      if (typeof event.data.probability === "number")
        row.maxProbability = Math.max(
          row.maxProbability ?? 0,
          event.data.probability,
        );
    }
  }

  const responses: ResponseRow[] = [];
  for (const event of events) {
    if (event.kind !== "mitigation_requested") continue;
    const source = String(event.data.ipv4_src ?? "");
    const host = byIp.get(source);
    const action = String(event.data.action ?? "temporary_drop");
    responses.push({
      offsetS: offset(event.ts),
      source,
      host: host?.name ?? null,
      action,
      onAttacker: !!host && attackers.has(host.name),
    });
    const row = host ? rows.get(host.name) : undefined;
    if (row) {
      row.actions.push(action);
      // The controller only acts on a source its detector named, so a response is
      // evidence of a detection even if that detection event was dropped.
      if (!row.flagged) {
        row.flagged = true;
        row.fromResponse = true;
      }
      const at = offset(event.ts);
      if (at !== null && (row.firstOffsetS === null || at < row.firstOffsetS))
        row.firstOffsetS = at;
    }
  }

  const confusion: Confusion = { vp: 0, fn: 0, fp: 0, vn: 0 };
  for (const row of hasExperiment ? rows.values() : []) {
    if (row.role === "attacker") {
      if (row.flagged) row.verdict = "VP";
      else if (attackOver) row.verdict = "FN";
    } else if (row.role === "legit") {
      row.verdict = row.flagged ? "FP" : "VN";
    }
    if (row.verdict === "VP") confusion.vp += 1;
    else if (row.verdict === "FN") confusion.fn += 1;
    else if (row.verdict === "FP") confusion.fp += 1;
    else if (row.verdict === "VN") confusion.vn += 1;
  }

  const attackerOffsets = [...rows.values()]
    .filter((r) => r.role === "attacker" && r.firstOffsetS !== null)
    .map((r) => r.firstOffsetS as number);
  const allDetected =
    attackers.size > 0 && attackerOffsets.length === attackers.size;

  // Service probes and the traffic reaching the victim, split by phase.
  const endMs = events.length
    ? Date.parse(events[events.length - 1].ts)
    : Date.now();
  const spans = phaseSpans(events, endMs);
  const phaseOf = (ts: string) => {
    const at = Date.parse(ts);
    return spans.find((s) => at >= s.start && at < s.end)?.state ?? null;
  };
  const probes: Record<string, { n: number; ok: number; latency: number[] }> =
    {};
  for (const event of events) {
    if (event.kind !== "service") continue;
    const phase = phaseOf(event.ts);
    if (!phase) continue;
    const bucket = (probes[phase] ??= { n: 0, ok: 0, latency: [] });
    bucket.n += 1;
    if (event.data.success) {
      bucket.ok += 1;
      if (typeof event.data.latency_ms === "number")
        bucket.latency.push(event.data.latency_ms);
    }
  }
  const service: Record<string, PhaseService> = {};
  for (const [phase, b] of Object.entries(probes))
    service[phase] = { probes: b.n, ok: b.ok, meanLatencyMs: mean(b.latency) };

  const victimLinks = new Set(
    (topology?.links ?? [])
      .filter(
        (l) =>
          (victims.has(l.source) && !victims.has(l.target)) ||
          (victims.has(l.target) && !victims.has(l.source)),
      )
      .map((l) => l.id),
  );
  const loadPoints = loadSeries(events, victimLinks);
  const firstResponse = responses.find(
    (r) => r.onAttacker && r.offsetS !== null,
  );
  const inPhase = (state: string) =>
    loadPoints.filter(([ts]) => phaseOf(new Date(ts).toISOString()) === state);
  const attackLoad = inPhase("attack").map(([, kbps]) => kbps);
  const afterResponse =
    attackStart !== null && firstResponse?.offsetS != null
      ? loadPoints
          .filter(
            ([ts]) =>
              (ts - attackStart) / 1000 >= firstResponse.offsetS! + 10 &&
              phaseOf(new Date(ts).toISOString()) === "attack",
          )
          .map(([, kbps]) => kbps)
      : [];

  const cpu = events
    .filter((e) => e.kind === "controller")
    .map((e) => Number(e.data.cpu_percent))
    .filter(Number.isFinite);
  const ram = events
    .filter((e) => e.kind === "controller")
    .map((e) => Number(e.data.rss_bytes) / 1048576)
    .filter(Number.isFinite);

  const announced = events.findLast((e) => e.kind === "detection_config");
  const config: Record<string, any> | null =
    announced?.data ?? (experiment?.detection as DetectionConfig | null);

  return {
    hasExperiment,
    attackStart,
    attackOver,
    hosts: [...rows.values()],
    confusion,
    metrics: computeMetrics(confusion),
    firstDetectionS: attackerOffsets.length
      ? Math.min(...attackerOffsets)
      : null,
    allDetectedS: allDetected ? Math.max(...attackerOffsets) : null,
    victimFlagged: [...rows.values()]
      .filter((r) => r.role === "victim" && r.flagged)
      .map((r) => r.name),
    unknownFlagged: [...unknown],
    detectionEvents,
    droppedEvents: events
      .filter((e) => e.kind === "gap" && e.data.source === "controller")
      .reduce((sum, e) => sum + (Number(e.data.count) || 0), 0),
    threshold,
    responses,
    collateral: [
      ...new Set(
        responses
          .filter((r) => !r.onAttacker && r.host)
          .map((r) => r.host as string),
      ),
    ],
    service,
    load: {
      baselineKbps: mean(inPhase("baseline").map(([, kbps]) => kbps)),
      attackMeanKbps: mean(attackLoad),
      attackPeakKbps: attackLoad.length ? Math.max(...attackLoad) : null,
      afterResponseKbps: mean(afterResponse),
    },
    controller: {
      cpuMax: cpu.length ? Math.max(...cpu) : null,
      ramMaxMiB: ram.length ? Math.max(...ram) : null,
    },
    config,
  };
}

/** [timestamp ms, kb/s] of the traffic the switches send toward the victim. */
export function loadSeries(
  events: Observation[],
  linkIds: Set<string>,
): [number, number][] {
  const points: [number, number][] = [];
  for (const event of events) {
    if (event.kind !== "links") continue;
    let bits = 0;
    let seen = false;
    for (const row of event.data.links ?? []) {
      if (!linkIds.has(row.link_id) || !row.rates) continue;
      bits += Number(row.rates.tx_bps) || 0;
      seen = true;
    }
    if (seen) points.push([Date.parse(event.ts), bits / 1000]);
  }
  return points;
}

/** Step series of cumulative attackers detected and false positives over time. */
export function detectionSteps(
  events: Observation[],
  topology: Topology | null,
  experiment: Experiment | null,
): { detected: [number, number][]; falsePositives: [number, number][] } {
  const byIp = new Map(
    (topology?.hosts ?? []).map((h) => [bareIp(h.ip), h.name]),
  );
  const attackers = new Set(experiment?.attackers ?? []);
  const legit = new Set(
    topology && experiment ? legitimateClients(topology, experiment) : [],
  );
  const caught = new Set<string>();
  const wrong = new Set<string>();
  const detected: [number, number][] = [];
  const falsePositives: [number, number][] = [];
  for (const event of events) {
    if (event.kind !== "detection") continue;
    const at = Date.parse(event.ts);
    for (const address of flaggedAddresses(event.data)) {
      const name = byIp.get(address);
      if (!name) continue;
      if (attackers.has(name) && !caught.has(name)) {
        caught.add(name);
        detected.push([at, caught.size]);
      } else if (legit.has(name) && !wrong.has(name)) {
        wrong.add(name);
        falsePositives.push([at, wrong.size]);
      }
    }
  }
  return { detected, falsePositives };
}

export function percent(value: number | null, digits = 0): string {
  return value === null ? "—" : `${(value * 100).toFixed(digits)} %`;
}

/**
 * The live view keeps about 2,000 events. Bulk kinds (flow tables, rule dumps, command
 * output) go first when it is full, so a long run never loses the phases, detections,
 * probes and responses the Detection results are computed from.
 */
const bulkKinds = new Set([
  "flows",
  "mitigation_observed",
  "command_output",
  "packet",
  "packets",
  "detector",
]);
export const liveLimit = 1999;
export function retainEvents(list: Observation[]): Observation[] {
  let excess = list.length - liveLimit;
  if (excess <= 0) return list;
  return list.filter((event) => {
    if (excess > 0 && bulkKinds.has(event.kind)) {
      excess -= 1;
      return false;
    }
    return true;
  });
}

/** One line for the History list: what judged the run, how many attacked, the response. */
export function describeRun(run: Run): string {
  const parts: string[] = [];
  if (run.detector_mode === "llm")
    parts.push(`LLM ${run.detector_model ?? ""}`.trim());
  else if (run.detector_mode === "rule") parts.push("Packet-rate rule");
  else if (run.detector_mode === "entropy") parts.push("Entropy");
  else if (run.detector_mode === "off") parts.push("No detection");
  if (run.attackers)
    parts.push(`${run.attackers} attacker${run.attackers === 1 ? "" : "s"}`);
  if (run.mitigation === "true" && run.detector_mode !== "off")
    parts.push(
      `${run.policy ?? "response"} ${run.dry_run === "true" ? "(simulated)" : "(real rules)"}`,
    );
  parts.push(
    run.forwarding === "port_free" ||
      (run.detector_mode === "entropy" && run.match_ports === "false")
      ? "Port-free rules (Experiment B)"
      : "Per-port rules (Experiment A)",
  );
  return parts.join(" · ");
}

/** One monitored distribution in an entropy window: its value and the learned band. */
export type EntropySignal = {
  value: number | null;
  lower: number | null;
  upper: number | null;
  center: number | null;
  spread: number | null;
  out: boolean;
};
export type EntropyState =
  | "idle"
  | "warmup"
  | "normal"
  | "suspicious"
  | "alarm";
/** What the entropy detector saw and concluded in one window (an `entropy_window` event). */
export type EntropyWindow = {
  at: number;
  window: number;
  state: EntropyState;
  rate: number;
  pairs: number;
  rules: number;
  switches: number;
  streak: number;
  needed: number;
  measure: string;
  centerKind: string;
  signals: Record<string, EntropySignal>;
  panel: Record<string, Record<string, number>>;
  topSrc: [string, number][];
  topDst: [string, number][];
  topPorts: [string, number][];
  candidates: string[];
  /** The settings the window was computed with (measure, centre, context…). */
  config: Record<string, any>;
};

const entropyStates = new Set([
  "idle",
  "warmup",
  "normal",
  "suspicious",
  "alarm",
]);
const numberOrNull = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

/** The entropy windows of a run, oldest first, read off its `entropy_window` events. */
export function entropyWindows(events: Observation[]): EntropyWindow[] {
  const windows: EntropyWindow[] = [];
  for (const event of events) {
    if (event.kind !== "entropy_window") continue;
    const data = event.data;
    const signals: Record<string, EntropySignal> = {};
    for (const [name, raw] of Object.entries(data.signals ?? {})) {
      const signal = raw as Record<string, unknown>;
      signals[name] = {
        value: numberOrNull(signal.value),
        lower: numberOrNull(signal.lower),
        upper: numberOrNull(signal.upper),
        center: numberOrNull(signal.center),
        spread: numberOrNull(signal.spread),
        out: signal.out === true,
      };
    }
    windows.push({
      at: Date.parse(event.ts),
      window: Number(data.window ?? windows.length + 1),
      state: entropyStates.has(data.state) ? data.state : "normal",
      rate: Number(data.total_rate ?? 0),
      pairs: Number(data.pairs ?? 0),
      rules: Number(data.flow_rules ?? 0),
      switches: Number(data.switches ?? 0),
      streak: Number(data.streak ?? 0),
      needed: Number(data.needed ?? 0),
      measure: String(data.measure ?? "shannon"),
      centerKind: String(data.center_kind ?? "ewma"),
      signals,
      panel: data.panel ?? {},
      topSrc: data.top_src ?? [],
      topDst: data.top_dst ?? [],
      topPorts: data.top_dport ?? [],
      candidates: data.candidates ?? [],
      config: data.config ?? {},
    });
  }
  return windows;
}

/** `2.310 [1.90 – 3.40]` : the value and the band it is compared with. */
export function formatSignal(signal: EntropySignal | undefined): string {
  if (!signal || signal.value === null) return "—";
  const band =
    signal.lower !== null && signal.upper !== null
      ? ` [${signal.lower.toFixed(2)} – ${signal.upper.toFixed(2)}]`
      : "";
  return `${signal.value.toFixed(3)}${band}`;
}

/** The entropies the detector reports side by side for every distribution. */
export const panelMeasures: [string, string][] = [
  ["shannon", "Shannon (bits)"],
  ["norm", "Normalised Shannon"],
  ["renyi2", "Rényi α=2"],
  ["renyi10", "Rényi α=10"],
  ["tsallis2", "Tsallis q=2"],
  ["min", "Min-entropy (bits)"],
  ["distinct", "Distinct values"],
];

export const centerLabels: Record<string, string> = {
  ewma: "EWMA mean",
  mean: "rolling mean",
  median: "rolling median",
  yu: "improved EWMA (Yu et al.)",
  ewma_margin: "EWMA minus a margin",
  ewma2: "second-order EWMA",
};

const measureLabels: Record<string, string> = {
  shannon: "Shannon",
  norm: "normalised Shannon",
  renyi: "Rényi",
  tsallis: "Tsallis",
  min: "min-entropy",
};

/** How the normal band is learned, as one readable line (no measure). */
export function describeBand(config: Record<string, any>): string {
  if (!config || !config.center) return "";
  const rolling = config.center !== "ewma";
  const parts = [`Centre: ${centerLabels[config.center] ?? config.center}`];
  if (config.center === "mean" || config.center === "median")
    parts.push(`Spread: ${config.spread === "mad" ? "MAD" : "std"}`);
  if (rolling)
    parts.push(
      `History: ${config.history > 0 ? `${config.history} windows` : "the whole run"}`,
    );
  parts.push(
    `Learns from: ${config.context === "all" ? "every window" : "normal-looking windows"}`,
  );
  if (config.center === "ewma_margin")
    parts.push(`Threshold: EWMA − ${config.margin ?? 0.01}`);
  else if (config.center === "ewma2")
    parts.push(`Threshold: trend − ${config.k} × volatility`);
  else parts.push(`Band: centre ± ${config.k} × spread`);
  if (Array.isArray(config.decide) && config.decide.length)
    parts.push(`Alarm decided by: ${config.decide.join(" + ")}`);
  return parts.join(" · ");
}

/** The detector's settings as one readable line, as it computed the window. */
export function describeEntropyConfig(config: Record<string, any>): string {
  if (!config || !config.measure) return "";
  const order =
    config.measure === "renyi" || config.measure === "tsallis"
      ? ` (order ${config.order})`
      : "";
  return [
    `Measure: ${measureLabels[config.measure] ?? config.measure}${order}`,
    describeBand(config),
  ]
    .filter(Boolean)
    .join(" · ");
}
