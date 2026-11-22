/**
 * Traffic-tab measurements. Pure functions: no chart library, no clock.
 *
 * Percentiles use linear interpolation, numpy's default. Phase boundaries
 * come from phaseSpans(). Recovery constants live in RECOVERY and are shown
 * in the table hint.
 */
import { analyzeDetection } from "./detection.ts";
import { phaseSpans } from "./types.ts";
import type { Experiment, Observation, PhaseSpan, Topology } from "./types.ts";

export const RECOVERY = {
  normalChecks: 10,
  latencyFactor: 2,
  latencySlackMs: 20,
  controllerWindowMs: 10_000,
  cpuSlack: 10,
  packetFactor: 2,
  packetSlack: 5,
  controllerSamples: 2,
  baselineChecks: 10,
  baselineControllerSamples: 2,
} as const;

export const RECOVERY_HINT =
  "Service is back to normal at the start of the first check after the attack stops that begins 10 answered checks in a row, each no slower than the worse of twice the baseline 95th percentile and that percentile plus 20 ms. The controller is back to normal at the first sample after the attack stops where every sample for the next 10 s stays within 10 percentage points of the baseline's highest Ryu CPU and within the worse of twice the baseline's highest Packet-Ins handled per second and that rate plus 5 per second, and at least 2 samples fall in that window. If it does not happen before the run ends, the table says so. It never estimates.";

export type Forwarding = "per_port" | "port_free";

export const FORWARDING_OPTIONS: { id: Forwarding; text: string }[] = [
  {
    id: "per_port",
    text: "Per-port rules (Experiment A) — one rule per destination port; a flood can saturate the controller",
  },
  {
    id: "port_free",
    text: "Port-free rules (Experiment B) — one rule per source, destination and protocol; a flood adds no rules after its first packet",
  },
];

/** What an old saved run actually used, without rewriting the stored row. */
export function recordedForwarding(input: {
  forwarding?: string | null;
  mode?: string | null;
  matchPorts?: boolean | string | null;
}): Forwarding {
  if (input.forwarding === "per_port" || input.forwarding === "port_free")
    return input.forwarding;
  const matchFalse = input.matchPorts === false || input.matchPorts === "false";
  if (input.mode === "entropy" && matchFalse) return "port_free";
  // LLM, off, entropy with match_ports true or missing, and observation
  // sessions (the controller's old default was per-port).
  return "per_port";
}

export function forwardingText(value: Forwarding): string {
  return value === "per_port"
    ? "Per-port rules (Experiment A)"
    : "Port-free rules (Experiment B)";
}

export function percentile(values: number[], p: number): number | null {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  if (sorted.length === 1) return sorted[0];
  const index = (sorted.length - 1) * (p / 100);
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (index - lower) * (sorted[upper] - sorted[lower]);
}

export function median(values: number[]): number | null {
  return percentile(values, 50);
}

export function mean(values: number[]): number | null {
  if (!values.length) return null;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function peak(values: number[]): number | null {
  if (!values.length) return null;
  return Math.max(...values);
}

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function at(event: Observation): number {
  return Date.parse(event.data.observed_at ?? event.ts);
}

export function phaseOf(
  spans: PhaseSpan[],
  ms: number,
): "baseline" | "attack" | "recovery" | null {
  return (
    (spans.find((span) => ms >= span.start && ms < span.end)?.state as
      | "baseline"
      | "attack"
      | "recovery"
      | undefined) ?? null
  );
}

function hostLinkIds(
  topology: Topology | null,
  names: Set<string>,
): Set<string> {
  const hosts = new Set((topology?.hosts ?? []).map((host) => host.name));
  return new Set(
    (topology?.links ?? [])
      .filter((link) => {
        const host =
          hosts.has(link.source) && !hosts.has(link.target)
            ? link.source
            : hosts.has(link.target) && !hosts.has(link.source)
              ? link.target
              : null;
        return host !== null && names.has(host);
      })
      .map((link) => link.id),
  );
}

export type TrafficPoint = {
  t: number;
  attackers: number | null;
  attackersKbps: number | null;
  victim: number | null;
  victimKbps: number | null;
  clients: number | null;
  clientsKbps: number | null;
  all: number | null;
  allKbps: number | null;
};

function sumRates(
  rows: any[],
  ids: Set<string>,
  field: "rx_pps" | "tx_pps" | "rx_bps" | "tx_bps",
): number | null {
  let total = 0;
  let seen = false;
  for (const row of rows) {
    if (!ids.has(row.link_id) || !row.rates) continue;
    const value = finite(row.rates[field]);
    if (value === null) continue;
    total += value;
    seen = true;
  }
  return seen ? total : null;
}

export function trafficSeries(
  events: Observation[],
  topology: Topology | null,
  experiment: Experiment | null,
): { observation: boolean; points: TrafficPoint[] } {
  const hosts = new Set((topology?.hosts ?? []).map((host) => host.name));
  const observation =
    !experiment?.attackers?.length || !experiment?.victims?.length;
  const attackers = hostLinkIds(topology, new Set(experiment?.attackers ?? []));
  const victims = hostLinkIds(topology, new Set(experiment?.victims ?? []));
  const clients = hostLinkIds(
    topology,
    new Set(
      (topology?.hosts ?? [])
        .map((host) => host.name)
        .filter(
          (name) =>
            !experiment?.attackers?.includes(name) &&
            !experiment?.victims?.includes(name),
        ),
    ),
  );
  const allHosts = hostLinkIds(topology, hosts);
  const points = events
    .filter((event) => event.kind === "links")
    .map((event) => {
      const rows = event.data.links ?? [];
      const t = at(event);
      if (observation) {
        const rx = sumRates(rows, allHosts, "rx_pps");
        const kbps = sumRates(rows, allHosts, "rx_bps");
        return {
          t,
          attackers: null,
          attackersKbps: null,
          victim: null,
          victimKbps: null,
          clients: null,
          clientsKbps: null,
          all: rx,
          allKbps: kbps === null ? null : kbps / 1000,
        };
      }
      const attackerBps = sumRates(rows, attackers, "rx_bps");
      const victimBps = sumRates(rows, victims, "tx_bps");
      const clientBps = sumRates(rows, clients, "rx_bps");
      return {
        t,
        attackers: sumRates(rows, attackers, "rx_pps"),
        attackersKbps: attackerBps === null ? null : attackerBps / 1000,
        victim: sumRates(rows, victims, "tx_pps"),
        victimKbps: victimBps === null ? null : victimBps / 1000,
        clients: sumRates(rows, clients, "rx_pps"),
        clientsKbps: clientBps === null ? null : clientBps / 1000,
        all: null,
        allKbps: null,
      };
    });
  return { observation, points };
}

export type CheckPoint = {
  t: number;
  total: number | null;
  connect: number | null;
  answered: boolean;
  httpCode: number | null;
  /** The victim the check was sent to, when the run recorded it. */
  target: string | null;
};

function answeredCheck(data: Record<string, any>): boolean {
  if (typeof data.http_code === "number") return data.http_code === 200;
  return data.success === true;
}

export function checkSeries(events: Observation[]): CheckPoint[] {
  return events
    .filter((event) => event.kind === "service")
    .map((event) => ({
      t: at(event),
      total: finite(event.data.latency_ms),
      connect: finite(event.data.connect_ms),
      answered: answeredCheck(event.data),
      httpCode: finite(event.data.http_code),
      target: typeof event.data.target === "string" ? event.data.target : null,
    }));
}

export function answeredShare(
  checks: CheckPoint[],
): { t: number; pct: number }[] {
  return checks.map((check, index) => {
    const window = checks.slice(Math.max(0, index - 9), index + 1);
    const answered = window.filter((item) => item.answered).length;
    return { t: check.t, pct: (answered / window.length) * 100 };
  });
}

export type PingPoint = { t: number; rtt: number; target: string };
export type LostPing = { t: number; target: string };

export function pingSeries(events: Observation[]): {
  rtt: PingPoint[];
  lost: LostPing[];
} {
  const rtt: PingPoint[] = [];
  const lost: LostPing[] = [];
  for (const event of events) {
    if (event.kind !== "ping") continue;
    const target = String(event.data.target ?? "");
    for (const reply of event.data.replies ?? []) {
      const stamp = Date.parse(reply[0]);
      const value = finite(reply[1]);
      if (Number.isFinite(stamp) && value !== null)
        rtt.push({ t: stamp, rtt: value, target });
    }
    for (const stamp of event.data.lost_at ?? []) {
      const t = Date.parse(stamp);
      if (Number.isFinite(t)) lost.push({ t, target });
    }
  }
  return { rtt, lost };
}

export function controllerSeries(events: Observation[]): {
  handled: { t: number; rate: number | null }[];
  sent: { t: number; rate: number | null }[];
  rules: { t: number; count: number | null }[];
} {
  const handled = events
    .filter((event) => event.kind === "controller")
    .map((event) => ({
      t: at(event),
      rate: finite(event.data.packet_in_handled_per_s),
    }));
  // Network totals: after each switch reply, the sum of every switch's latest value.
  // Summing the replies that fall in one clock second instead counts a switch twice
  // when two of its polls land in the same second and misses the switches whose
  // reply fell in the next one, which under load inflated the rule peak and
  // understated the Packet-Ins sent.
  const latestSent = new Map<string, number>();
  const latestRules = new Map<string, number>();
  const sent: { t: number; rate: number | null }[] = [];
  const rules: { t: number; count: number | null }[] = [];
  const total = (values: Map<string, number>) =>
    [...values.values()].reduce((sum, value) => sum + value, 0);
  const tables = events
    .filter((event) => event.kind === "switch_table")
    .map((event) => ({ event, t: at(event) }))
    .sort((a, b) => a.t - b.t);
  for (const { event, t } of tables) {
    const dpid = String(event.data.dpid ?? "");
    const rate = finite(event.data.packet_in_sent_per_s);
    if (rate !== null) latestSent.set(dpid, rate);
    const count = finite(event.data.flow_rules);
    if (count !== null) latestRules.set(dpid, count);
    sent.push({ t, rate: latestSent.size ? total(latestSent) : null });
    rules.push({ t, count: latestRules.size ? total(latestRules) : null });
  }
  return { handled, sent, rules };
}

export function cpuSeries(events: Observation[]): {
  ryu: { t: number; cpu: number | null; ram: number | null }[];
  ovs: { t: number; cpu: number | null }[];
  machine: { t: number; cpu: number | null }[];
} {
  return {
    ryu: events
      .filter((event) => event.kind === "controller")
      .map((event) => ({
        t: at(event),
        cpu: finite(event.data.cpu_percent),
        ram: finite(event.data.rss_bytes),
      })),
    ovs: events
      .filter((event) => event.kind === "system")
      .map((event) => ({
        t: at(event),
        cpu: finite(event.data.ovs_cpu_percent),
      })),
    machine: events
      .filter((event) => event.kind === "system")
      .map((event) => ({ t: at(event), cpu: finite(event.data.cpu_percent) })),
  };
}

export type RecoveryOutcome =
  | { kind: "too-short" }
  | { kind: "recovered"; at: number }
  | { kind: "not-recovered" };

export function judgeService(
  checks: CheckPoint[],
  spans: PhaseSpan[],
  tStop: number | null,
  runEnd: number,
): RecoveryOutcome {
  if (tStop === null) return { kind: "not-recovered" };
  const baseline = checks.filter(
    (check) =>
      phaseOf(spans, check.t) === "baseline" &&
      check.answered &&
      check.total !== null,
  );
  if (baseline.length < RECOVERY.baselineChecks) return { kind: "too-short" };
  const limit = percentile(
    baseline.map((check) => check.total as number),
    95,
  );
  if (limit === null) return { kind: "too-short" };
  const ceiling = Math.max(
    RECOVERY.latencyFactor * limit,
    limit + RECOVERY.latencySlackMs,
  );
  const after = checks.filter((check) => check.t > tStop && check.t < runEnd);
  const normal = (check: CheckPoint) =>
    check.httpCode === 200 && check.total !== null && check.total <= ceiling;
  for (
    let index = 0;
    index + RECOVERY.normalChecks <= after.length;
    index += 1
  ) {
    const window = after.slice(index, index + RECOVERY.normalChecks);
    if (window.every(normal) && window.every((check) => check.t < runEnd))
      return { kind: "recovered", at: window[0].t };
  }
  return { kind: "not-recovered" };
}

export function judgeController(
  samples: { t: number; cpu: number | null; rate: number | null }[],
  spans: PhaseSpan[],
  tStop: number | null,
): RecoveryOutcome {
  if (tStop === null) return { kind: "not-recovered" };
  const baseline = samples.filter(
    (sample) => phaseOf(spans, sample.t) === "baseline",
  );
  if (baseline.length < RECOVERY.baselineControllerSamples)
    return { kind: "too-short" };
  const cpus = baseline
    .map((sample) => sample.cpu)
    .filter((value): value is number => value !== null);
  const rates = baseline
    .map((sample) => sample.rate)
    .filter((value): value is number => value !== null);
  if (!cpus.length || !rates.length) return { kind: "too-short" };
  const cpuLimit = Math.max(...cpus) + RECOVERY.cpuSlack;
  const highest = Math.max(...rates);
  const rateLimit = Math.max(
    RECOVERY.packetFactor * highest,
    highest + RECOVERY.packetSlack,
  );
  const after = samples.filter((sample) => sample.t > tStop);
  for (const candidate of after) {
    const window = after.filter(
      (sample) =>
        sample.t >= candidate.t &&
        sample.t <= candidate.t + RECOVERY.controllerWindowMs,
    );
    if (window.length < RECOVERY.controllerSamples) continue;
    const ok = window.every(
      (sample) =>
        sample.cpu !== null &&
        sample.cpu <= cpuLimit &&
        sample.rate !== null &&
        sample.rate <= rateLimit,
    );
    if (ok) return { kind: "recovered", at: candidate.t };
  }
  return { kind: "not-recovered" };
}

export function recoveryText(
  outcome: RecoveryOutcome,
  tStop: number | null,
  runEnd: number,
): string {
  if (outcome.kind === "too-short") return "baseline too short to judge";
  if (tStop === null) return "not recovered within 0 s";
  if (outcome.kind === "recovered") {
    const seconds = (outcome.at - tStop) / 1000;
    return `${trimSeconds(seconds)} s`;
  }
  return `not recovered within ${trimSeconds((runEnd - tStop) / 1000)} s`;
}

function trimSeconds(value: number): string {
  const rounded = Math.round(value * 10) / 10;
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(1);
}

export function versus(phase: number | null, baseline: number | null): string {
  if (phase === null || baseline === null) return "—";
  if (baseline === 0) return trimSeconds(phase - baseline);
  const pct = ((phase - baseline) / baseline) * 100;
  const text = trimSeconds(pct);
  return `${text.startsWith("-") ? text : `+${text}`}%`;
}

export type TableRow = {
  label: string;
  baseline: string;
  attack: string;
  recovery: string;
  attackVs: string;
  recoveryVs: string;
};

function cell(value: number | null, suffix = ""): string {
  if (value === null) return "—";
  return `${trimSeconds(value)}${suffix}`;
}

function pair(
  meanValue: number | null,
  peakValue: number | null,
  suffix = "",
): string {
  if (meanValue === null && peakValue === null) return "—";
  return `mean ${cell(meanValue, suffix)} · peak ${cell(peakValue, suffix)}`;
}

function versusPair(
  phaseMean: number | null,
  phasePeak: number | null,
  baseMean: number | null,
  basePeak: number | null,
): string {
  if (phaseMean === null && phasePeak === null) return "—";
  return `mean ${versus(phaseMean, baseMean)} · peak ${versus(phasePeak, basePeak)}`;
}

type Phase = "baseline" | "attack" | "recovery";
const PHASES: Phase[] = ["baseline", "attack", "recovery"];

export function phaseTable(
  events: Observation[],
  topology: Topology | null,
  experiment: Experiment | null,
  runEnd: number,
): { rows: TableRow[]; below: string[]; hint: string } | null {
  if (!experiment?.attackers?.length) return null;
  const spans = phaseSpans(events, runEnd);
  const stopped = events.find((event) => event.kind === "attack_stopped");
  const tStop = stopped ? at(stopped) : null;
  const checks = checkSeries(events);
  const pings = pingSeries(events);
  const traffic = trafficSeries(events, topology, experiment).points;
  const controller = controllerSeries(events);
  const cpu = cpuSeries(events);
  const inPhase = <T extends { t: number }>(items: T[], phase: Phase) =>
    items.filter((item) => phaseOf(spans, item.t) === phase);

  const answered = (phase: Phase) =>
    inPhase(checks, phase).filter((check) => check.answered);
  const answeredPct = (phase: Phase) => {
    const rows = inPhase(checks, phase);
    if (!rows.length) return null;
    return (rows.filter((check) => check.answered).length / rows.length) * 100;
  };
  const answeredCount = (phase: Phase) => {
    const rows = inPhase(checks, phase);
    return `${rows.filter((check) => check.answered).length}/${rows.length}`;
  };
  const times = (phase: Phase) =>
    answered(phase)
      .map((check) => check.total)
      .filter((value): value is number => value !== null);
  const connects = (phase: Phase) =>
    answered(phase)
      .map((check) => check.connect)
      .filter((value): value is number => value !== null);
  const rtts = (phase: Phase) =>
    inPhase(pings.rtt, phase).map((point) => point.rtt);
  const jitterOf = (phase: Phase) => {
    const answeredSeq = events
      .filter((event) => event.kind === "ping")
      .flatMap((event) =>
        (event.data.answered ?? []).map((pair: number[]) => ({
          t: at(event),
          seq: pair[0],
          rtt: pair[1],
        })),
      )
      .filter((item: { t: number }) => phaseOf(spans, item.t) === phase)
      .sort((a: { seq: number }, b: { seq: number }) => a.seq - b.seq);
    const gaps: number[] = [];
    for (let index = 1; index < answeredSeq.length; index += 1) {
      if (answeredSeq[index].seq === answeredSeq[index - 1].seq + 1)
        gaps.push(
          Math.abs(answeredSeq[index].rtt - answeredSeq[index - 1].rtt),
        );
    }
    return mean(gaps);
  };
  const lostPct = (phase: Phase) => {
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
    if (!sent) return null;
    return (lost / sent) * 100;
  };
  const numbers = (
    phase: Phase,
    pick: (point: TrafficPoint) => number | null,
  ) =>
    inPhase(traffic, phase)
      .map(pick)
      .filter((value): value is number => value !== null);

  const row = (
    label: string,
    values: Record<Phase, number | null>,
    format: (value: number | null) => string = (value) => cell(value),
  ): TableRow => ({
    label,
    baseline: format(values.baseline),
    attack: format(values.attack),
    recovery: format(values.recovery),
    attackVs: versus(values.attack, values.baseline),
    recoveryVs: versus(values.recovery, values.baseline),
  });
  const byPhase = (read: (phase: Phase) => number | null) =>
    Object.fromEntries(PHASES.map((phase) => [phase, read(phase)])) as Record<
      Phase,
      number | null
    >;

  const rows: TableRow[] = [
    {
      label: "website checks answered",
      baseline: `${cell(answeredPct("baseline"), "%")} (${answeredCount("baseline")})`,
      attack: `${cell(answeredPct("attack"), "%")} (${answeredCount("attack")})`,
      recovery: `${cell(answeredPct("recovery"), "%")} (${answeredCount("recovery")})`,
      attackVs: versus(answeredPct("attack"), answeredPct("baseline")),
      recoveryVs: versus(answeredPct("recovery"), answeredPct("baseline")),
    },
    row(
      "website check time, median",
      byPhase((phase) => median(times(phase))),
      (value) => cell(value, " ms"),
    ),
    row(
      "website check time, 95th",
      byPhase((phase) => percentile(times(phase), 95)),
      (value) => cell(value, " ms"),
    ),
    row(
      "connection time, median",
      byPhase((phase) => median(connects(phase))),
      (value) => cell(value, " ms"),
    ),
    row(
      "ping median RTT",
      byPhase((phase) => median(rtts(phase))),
      (value) => cell(value, " ms"),
    ),
    row("ping jitter", byPhase(jitterOf), (value) => cell(value, " ms")),
    row("ping lost", byPhase(lostPct), (value) => cell(value, "%")),
    row(
      "packets/s delivered to victim, mean",
      byPhase((phase) => mean(numbers(phase, (point) => point.victim))),
    ),
    row(
      "packets/s sent by attackers, mean",
      byPhase((phase) => mean(numbers(phase, (point) => point.attackers))),
    ),
  ];
  const sentMean = byPhase((phase) =>
    mean(
      inPhase(controller.sent, phase)
        .map((point) => point.rate)
        .filter((v): v is number => v !== null),
    ),
  );
  const sentPeak = byPhase((phase) =>
    peak(
      inPhase(controller.sent, phase)
        .map((point) => point.rate)
        .filter((v): v is number => v !== null),
    ),
  );
  const handledMean = byPhase((phase) =>
    mean(
      inPhase(controller.handled, phase)
        .map((point) => point.rate)
        .filter((v): v is number => v !== null),
    ),
  );
  const handledPeak = byPhase((phase) =>
    peak(
      inPhase(controller.handled, phase)
        .map((point) => point.rate)
        .filter((v): v is number => v !== null),
    ),
  );
  rows.push({
    label: "Packet-Ins/s sent by switches",
    baseline: pair(sentMean.baseline, sentPeak.baseline),
    attack: pair(sentMean.attack, sentPeak.attack),
    recovery: pair(sentMean.recovery, sentPeak.recovery),
    attackVs: versusPair(
      sentMean.attack,
      sentPeak.attack,
      sentMean.baseline,
      sentPeak.baseline,
    ),
    recoveryVs: versusPair(
      sentMean.recovery,
      sentPeak.recovery,
      sentMean.baseline,
      sentPeak.baseline,
    ),
  });
  rows.push({
    label: "Packet-Ins/s handled by Ryu",
    baseline: pair(handledMean.baseline, handledPeak.baseline),
    attack: pair(handledMean.attack, handledPeak.attack),
    recovery: pair(handledMean.recovery, handledPeak.recovery),
    attackVs: versusPair(
      handledMean.attack,
      handledPeak.attack,
      handledMean.baseline,
      handledPeak.baseline,
    ),
    recoveryVs: versusPair(
      handledMean.recovery,
      handledPeak.recovery,
      handledMean.baseline,
      handledPeak.baseline,
    ),
  });
  rows.push(
    row(
      "flow rules, peak",
      byPhase((phase) =>
        peak(
          inPhase(controller.rules, phase)
            .map((point) => point.count)
            .filter((value): value is number => value !== null),
        ),
      ),
    ),
  );
  const cpuRow = (
    label: string,
    points: { t: number; cpu: number | null }[],
  ): TableRow => {
    const read = (phase: Phase, pick: (values: number[]) => number | null) =>
      pick(
        inPhase(points, phase)
          .map((point) => point.cpu)
          .filter((value): value is number => value !== null),
      );
    const means = byPhase((phase) => read(phase, mean));
    const peaks = byPhase((phase) => read(phase, peak));
    return {
      label,
      baseline: pair(means.baseline, peaks.baseline, "%"),
      attack: pair(means.attack, peaks.attack, "%"),
      recovery: pair(means.recovery, peaks.recovery, "%"),
      attackVs: versusPair(
        means.attack,
        peaks.attack,
        means.baseline,
        peaks.baseline,
      ),
      recoveryVs: versusPair(
        means.recovery,
        peaks.recovery,
        means.baseline,
        peaks.baseline,
      ),
    };
  };
  rows.push(cpuRow("Ryu CPU", cpu.ryu));
  rows.push(cpuRow("Open vSwitch CPU", cpu.ovs));
  rows.push(cpuRow("whole machine CPU", cpu.machine));
  rows.push(
    row(
      "Ryu RAM, peak",
      byPhase((phase) =>
        peak(
          inPhase(cpu.ryu, phase)
            .map((point) => point.ram)
            .filter((value): value is number => value !== null)
            .map((bytes) => bytes / 1048576),
        ),
      ),
      (value) => cell(value, " MiB"),
    ),
  );

  const analysis = analyzeDetection(events, topology, experiment, false);
  const service = judgeService(checks, spans, tStop, runEnd);
  const controllerJudge = judgeController(
    cpu.ryu.map((point, index) => ({
      t: point.t,
      cpu: point.cpu,
      rate: controller.handled[index]?.rate ?? null,
    })),
    spans,
    tStop,
  );
  const below = [
    `Time to first detection: ${analysis.firstDetectionS === null ? "—" : `${trimSeconds(analysis.firstDetectionS)} s after the attack started`}`,
    `Time to first response: ${
      analysis.responses.find((row) => row.onAttacker)?.offsetS == null
        ? "—"
        : `${trimSeconds(analysis.responses.find((row) => row.onAttacker)!.offsetS!)} s after the attack started`
    }`,
    `Service recovery time: ${recoveryText(service, tStop, runEnd)}`,
    `Controller recovery time: ${recoveryText(controllerJudge, tStop, runEnd)}`,
  ];
  return { rows, below, hint: RECOVERY_HINT };
}

export type Marker = { t: number; label: string };

export function trafficMarkers(
  events: Observation[],
  topology: Topology | null,
  experiment: Experiment | null,
  runEnd: number,
): Marker[] {
  const analysis = analyzeDetection(events, topology, experiment, false);
  const spans = phaseSpans(events, runEnd);
  const stopped = events.find((event) => event.kind === "attack_stopped");
  const tStop = stopped ? at(stopped) : null;
  const service = judgeService(checkSeries(events), spans, tStop, runEnd);
  const handled = controllerSeries(events).handled;
  const ryu = cpuSeries(events).ryu;
  const controllerJudge = judgeController(
    ryu.map((point, index) => ({
      t: point.t,
      cpu: point.cpu,
      rate: handled[index]?.rate ?? null,
    })),
    spans,
    tStop,
  );
  const markers: Marker[] = [];
  if (analysis.attackStart !== null && analysis.firstDetectionS !== null)
    markers.push({
      t: analysis.attackStart + analysis.firstDetectionS * 1000,
      label: "first attacker detected",
    });
  const response = analysis.responses.find((row) => row.onAttacker);
  if (analysis.attackStart !== null && response?.offsetS != null)
    markers.push({
      t: analysis.attackStart + response.offsetS * 1000,
      label: "first response",
    });
  if (service.kind === "recovered")
    markers.push({ t: service.at, label: "service back to normal" });
  if (controllerJudge.kind === "recovered")
    markers.push({ t: controllerJudge.at, label: "controller back to normal" });
  return markers;
}

export const panelHints = {
  traffic:
    "WHAT: packets each second, split by who sent them and what reached the victim. The tooltip also shows kilobits per second. HOW TO READ: attackers are what left their machines, the victim line is what arrived, and normal clients are the rest. A SYN flood is visible here even when the packets are tiny. WHY: one summed line used to count a packet again on every link and hide the cause.",
  checks:
    "WHAT: how long a normal web request took, and whether it was answered. HOW TO READ: a green dot is an answered check; a red ✗ at the top is a failed one. The right axis is how many of the last 10 checks were answered. WHY: a failed check used to disappear, so an outage looked like a gap in the line.",
  ping: "WHAT: round-trip time from one normal computer to each victim, five times a second. HOW TO READ: the line is answered pings; a red ✗ is a ping that got no reply within 1 second. WHY: it is a second clock, independent of the website check.",
  controller:
    "WHAT: Packet-In messages the switches sent because they had no rule, how many Ryu handled, and how many flow rules the switches held. HOW TO READ: a climb in Packet-Ins with a climb in rules is a flood creating a rule per packet. WHY: it shows whether the controller is the thing that saturated, not only the service.",
  cpu: "WHAT: CPU of Ryu, of Open vSwitch, and of the whole machine, once a second. The tooltip shows Ryu's memory. HOW TO READ: Open vSwitch's CPU is the switch process only; the kernel's packet forwarding is not in that number. WHY: the old readout kept only the latest sample.",
};
