/**
 * Building blocks of the evaluation metrics the thesis defines (detection time,
 * per-flow decisions, calibration, recovery per victim), computed only from what
 * a run recorded. results.ts assembles them into the Results tab and its files.
 *
 * Pure functions: no chart library, no clock.
 *
 * Ground truth is the experiment itself, as in the Results tab: the
 * hosts made attackers are the positives and the legitimate clients the
 * negatives. The victim is neither.
 */
import { flaggedAddresses } from "./detection.ts";
import { judgeService, mean, phaseOf, recoveryText } from "./traffic.ts";
import type { CheckPoint } from "./traffic.ts";
import { legitimateClients } from "./types.ts";
import type { Experiment, Observation, PhaseSpan, Topology } from "./types.ts";

export const EVALUATION = {
  /** An attacker named within this many seconds of the attack start counts as early (EDR). */
  earlyDetectionS: 10,
  /** Equal-width probability bins of the expected calibration error (ECE). */
  calibrationBins: 10,
  /** Seconds after the first response before the remaining attack traffic is measured. */
  responseSettleS: 10,
} as const;

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
