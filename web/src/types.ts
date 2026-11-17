export type Position = { x: number; y: number };
// Not a device the user owns: the lab supplies one managed Ryu controller. The
// id cannot collide with a host or switch, whose names must start with h or s.
export const CONTROLLER_ID = "__controller__";
export type Task = (
  action: () => Promise<void>,
  failureTitle?: string,
) => Promise<void>;
export const activeStates = [
  "starting",
  "running",
  "baseline",
  "attack",
  "recovery",
  "stopping",
];
export type Host = { name: string; ip: string; position: Position };
export type Switch = { name: string; dpid: number; position: Position };
export type Link = {
  id: string;
  source: string;
  target: string;
  bandwidth_mbps: number | null;
  delay_ms: number;
  loss_percent: number;
};
export type Topology = {
  version: 1;
  name: string;
  description: string;
  hosts: Host[];
  switches: Switch[];
  links: Link[];
};
export type TrafficKind = "syn" | "udp" | "icmp";
export const trafficKinds: { id: TrafficKind; label: string; hint: string }[] =
  [
    {
      id: "syn",
      label: "TCP SYN flood",
      hint: "Half-open TCP connection requests to the victim's service port. The classic flood the first scenarios study.",
    },
    {
      id: "udp",
      label: "UDP flood",
      hint: "A stream of UDP datagrams at the victim's service port, the volumetric flood the multi-host scenario combines with SYN.",
    },
    {
      id: "icmp",
      label: "ICMP echo flood",
      hint: "A ping flood of ICMP echo requests. It carries no port, only raw echo traffic toward the victim.",
    },
  ];
export type DetectionMode = "llm" | "rule" | "entropy" | "off";
export type ResponsePolicy = "block" | "rate_limit" | "escalate";
export type EntropyParams = {
  k: number;
  alpha: number;
  warmup_windows: number;
  consecutive_windows: number;
  min_rate: number;
  min_std: number;
  candidate_share: number;
  candidate_min_rate: number;
  update_hold: number;
  alpha_run: number | null;
  window_seconds: number;
  window_mode: "snapshot" | "mean";
  dedupe_switches: boolean;
  /** Which entropy is computed and how its normal band is learned. */
  measure: EntropyMeasure;
  order: number;
  center: ThresholdCenter;
  spread: "std" | "mad";
  history: number;
  context: "normal" | "all";
  watch_ports: boolean;
  watch_protocols: boolean;
  /** Also compute the entropy of the (source, destination) pairs. */
  watch_pairs: boolean;
  /** The distributions allowed to raise an alarm; empty means every watched one. */
  decide: EntropyFeature[];
  /** Margin of the margin threshold: EWMA minus a fixed margin. */
  margin: number;
  /** Packet rate above which the second-order EWMA threshold cannot decrease. */
  rate_threshold: number;
  /** false: forwarding rules ignore the layer-4 port (no rule per reply in a SYN flood). */
  match_ports?: boolean;
};
export type EntropyMeasure = "shannon" | "norm" | "renyi" | "tsallis" | "min";
export type EntropyFeature = "src" | "dst" | "dport" | "proto" | "pair";
export type ThresholdCenter =
  | "ewma"
  | "mean"
  | "median"
  | "yu"
  | "ewma_margin"
  | "ewma2";
export type ResponseParams = {
  policy: ResponsePolicy;
  dry_run: boolean;
  rate_limit_pps: number;
  rate_limit_burst: number | null;
  rate_limit_seconds: number;
  escalate_after_seconds: number;
  block_seconds: number;
  max_active: number;
  confirm_hits: number;
  confirm_seconds: number;
  protected: string[];
};
/** Which detector judges a run and how it is tuned; saved with the experiment. */
export type DetectionConfig = {
  mode: DetectionMode;
  model: string;
  prompt: "insdn" | "lab";
  llm_max_samples: number;
  poll_seconds: number;
  threshold: number;
  /** Packet-rate rule: a judged flow at or above this many packets/s is an attack. */
  rule_pktrate: number;
  entropy: EntropyParams;
  response: ResponseParams;
};
export type Experiment = {
  attackers: string[];
  victims: string[];
  traffic: TrafficKind[];
  rate: number;
  duration: number;
  baseline: number;
  recovery: number;
  mitigation: boolean;
  confirm_isolated_lab: boolean;
  /** null: leave the detector as the lab was started (older runs, no detector). */
  detection: DetectionConfig | null;
};

/** The values measured and calibrated in the lab (docs/detection-modes.md). */
export const defaultEntropy: EntropyParams = {
  k: 2.5,
  alpha: 0.2,
  warmup_windows: 16,
  consecutive_windows: 2,
  min_rate: 2,
  min_std: 0.05,
  candidate_share: 0.3,
  candidate_min_rate: 20,
  update_hold: 0,
  alpha_run: null,
  window_seconds: 5,
  window_mode: "mean",
  dedupe_switches: false,
  measure: "shannon",
  order: 2,
  center: "ewma",
  spread: "std",
  history: 0,
  context: "normal",
  watch_ports: false,
  watch_protocols: false,
  watch_pairs: false,
  decide: [],
  margin: 0.01,
  rate_threshold: 800,
};
export const defaultResponse: ResponseParams = {
  policy: "block",
  dry_run: true,
  rate_limit_pps: 50,
  rate_limit_burst: null,
  rate_limit_seconds: 120,
  escalate_after_seconds: 20,
  block_seconds: 300,
  max_active: 16,
  confirm_hits: 1,
  confirm_seconds: 30,
  protected: [],
};
export const defaultDetection: DetectionConfig = {
  mode: "llm",
  model: "llama3.2:3b",
  prompt: "lab",
  llm_max_samples: 5,
  poll_seconds: 5,
  threshold: 0.8,
  rule_pktrate: 50,
  entropy: defaultEntropy,
  response: defaultResponse,
};

/** LLMs measured in the lab, offered when the detector cannot list what is installed. */
export const knownModels: { name: string; note: string }[] = [
  { name: "llama3.2:3b", note: "most sensitive; flags more legitimate hosts" },
  { name: "gemma2:2b", note: "fewest false alarms, slower per verdict" },
  { name: "qwen2.5:3b", note: "most accurate offline, slowest" },
  { name: "phi3.5", note: "mixed results" },
  { name: "llama3.2:1b", note: "not recommended: too many false alarms" },
];

/** Fill whatever an older record lacks with defaults; null when it had no detection. */
export function normalizeDetection(value: unknown): DetectionConfig | null {
  if (!value || typeof value !== "object") return null;
  const saved = value as Record<string, any>;
  // Runs recorded while the two thresholds were named after the papers they follow.
  const legacy: Record<string, ThresholdCenter> = {
    ding: "ewma_margin",
    z26: "ewma2",
  };
  const entropy: Record<string, any> = {
    ...defaultEntropy,
    ...(saved.entropy ?? {}),
  };
  entropy.center = legacy[entropy.center] ?? entropy.center;
  delete entropy.match_ports;
  if (
    saved.entropy?.epsilon !== undefined &&
    saved.entropy?.margin === undefined
  )
    entropy.margin = saved.entropy.epsilon;
  return {
    ...defaultDetection,
    ...saved,
    entropy: entropy as EntropyParams,
    response: { ...defaultResponse, ...(saved.response ?? {}) },
  };
}

/** What the detector service answers to GET /config, as the workspace's config. */
export function detectionFromService(
  current: Record<string, any> | undefined,
): DetectionConfig {
  if (!current) return defaultDetection;
  const entropy = current.entropy ?? {};
  return {
    ...defaultDetection,
    mode: current.mode ?? defaultDetection.mode,
    model: current.model ?? defaultDetection.model,
    prompt: current.prompt ?? defaultDetection.prompt,
    rule_pktrate: current.rule_pktrate ?? defaultDetection.rule_pktrate,
    entropy: {
      ...defaultEntropy,
      k: entropy.k ?? defaultEntropy.k,
      alpha: entropy.alpha ?? defaultEntropy.alpha,
      warmup_windows: entropy.warmup_windows ?? defaultEntropy.warmup_windows,
      consecutive_windows:
        entropy.consecutive_windows ?? defaultEntropy.consecutive_windows,
      min_rate: entropy.min_total_rate ?? defaultEntropy.min_rate,
      min_std: entropy.min_std ?? defaultEntropy.min_std,
      candidate_share:
        entropy.candidate_share ?? defaultEntropy.candidate_share,
      candidate_min_rate:
        entropy.candidate_min_rate ?? defaultEntropy.candidate_min_rate,
      update_hold: entropy.update_hold ?? defaultEntropy.update_hold,
      alpha_run: entropy.alpha_run ?? null,
      measure: entropy.measure ?? defaultEntropy.measure,
      order: entropy.order ?? defaultEntropy.order,
      center: entropy.center ?? defaultEntropy.center,
      spread: entropy.spread ?? defaultEntropy.spread,
      history: entropy.history ?? defaultEntropy.history,
      context: entropy.context ?? defaultEntropy.context,
      watch_ports: (entropy.features ?? []).includes("dport"),
      watch_protocols: (entropy.features ?? []).includes("proto"),
      watch_pairs: (entropy.features ?? []).includes("pair"),
      decide: entropy.decide ?? defaultEntropy.decide,
      margin: entropy.margin ?? defaultEntropy.margin,
      rate_threshold: entropy.rate_threshold ?? defaultEntropy.rate_threshold,
    },
    response: {
      ...defaultResponse,
      policy: current.response ?? defaultResponse.policy,
      dry_run: current.dry_run ?? defaultResponse.dry_run,
    },
  };
}

export type DetectionOptions = {
  available?: boolean;
  reason?: string;
  current?: Record<string, any>;
  models?: string[];
  models_error?: string;
};

export const emptyExperiment: Experiment = {
  attackers: [],
  victims: [],
  traffic: ["syn"],
  rate: 100,
  duration: 20,
  baseline: 30,
  recovery: 30,
  mitigation: false,
  confirm_isolated_lab: false,
  detection: null,
};

/**
 * Accept both the current attacker/victim shape and the older
 * source/target/client records a saved run may still carry, so replaying an
 * experiment recorded before this change never crashes the workspace.
 */
export function normalizeExperiment(settings: unknown): Experiment {
  const value = (settings ?? {}) as Record<string, any>;
  if (Array.isArray(value.attackers) || Array.isArray(value.victims)) {
    return {
      ...emptyExperiment,
      ...value,
      attackers: value.attackers ?? [],
      victims: value.victims ?? [],
      traffic: value.traffic?.length ? value.traffic : ["syn"],
      detection: normalizeDetection(value.detection),
    };
  }
  return {
    ...emptyExperiment,
    attackers: value.source ? [value.source] : [],
    victims: value.target ? [value.target] : [],
    traffic: ["syn"],
    rate: value.rate ?? emptyExperiment.rate,
    duration: value.duration ?? emptyExperiment.duration,
    baseline: value.baseline ?? emptyExperiment.baseline,
    recovery: value.recovery ?? emptyExperiment.recovery,
    mitigation: !!value.mitigation,
    confirm_isolated_lab: !!value.confirm_isolated_lab,
  };
}

function subnetKey(ip: string): string {
  const [addr, prefixText] = ip.split("/");
  const prefix = Number(prefixText ?? 32);
  const asInt =
    addr.split(".").reduce((total, octet) => total * 256 + Number(octet), 0) >>>
    0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return `${(asInt & mask) >>> 0}/${prefix}`;
}

/**
 * Mirror of the server's rule: legitimate clients are inferred, not chosen —
 * every host in the victims' subnet that is neither an attacker nor a victim.
 */
export function legitimateClients(
  topology: Topology | null,
  experiment: Experiment,
): string[] {
  if (!topology) return [];
  const involved = new Set([...experiment.attackers, ...experiment.victims]);
  const victimSubnets = new Set(
    experiment.victims
      .map((name) => topology.hosts.find((h) => h.name === name))
      .filter((host): host is Host => !!host)
      .map((host) => subnetKey(host.ip)),
  );
  return topology.hosts
    .filter((host) => !involved.has(host.name))
    .filter((host) => victimSubnets.has(subnetKey(host.ip)))
    .map((host) => host.name);
}

/** The switch a host is wired to, for the picker's "switch parent" column. */
export function hostSwitch(
  topology: Topology | null,
  hostName: string,
): string {
  if (!topology) return "—";
  const switches = new Set(topology.switches.map((s) => s.name));
  for (const link of topology.links) {
    if (link.source === hostName && switches.has(link.target))
      return link.target;
    if (link.target === hostName && switches.has(link.source))
      return link.source;
  }
  return "—";
}

export type PhaseSpan = { state: string; start: number; end: number };

/** Measured baseline/attack/recovery intervals, read straight off phase events. */
export function phaseSpans(events: Observation[], endMs: number): PhaseSpan[] {
  const phases = events.filter((e) => e.kind === "phase");
  const spans: PhaseSpan[] = [];
  for (let i = 0; i < phases.length; i++) {
    const state = phases[i].data.state as string;
    if (!["baseline", "attack", "recovery"].includes(state)) continue;
    const start = Date.parse(phases[i].ts);
    const end = i + 1 < phases.length ? Date.parse(phases[i + 1].ts) : endMs;
    if (Number.isFinite(start) && end > start)
      spans.push({ state, start, end });
  }
  return spans;
}

export function formatElapsed(ms: number): string {
  const seconds = Math.max(0, Math.floor(ms / 1000));
  const pad = (n: number) => String(n).padStart(2, "0");
  const hours = Math.floor(seconds / 3600);
  const rest = `${pad(Math.floor((seconds % 3600) / 60))}:${pad(seconds % 60)}`;
  return hours > 0 ? `${hours}:${rest}` : rest;
}
// Observation data is open-ended JSON; individual views only read documented keys.
export type Observation = {
  run_id: string;
  seq: number;
  ts: string;
  kind: string;
  data: Record<string, any>;
};
export type Run = {
  id: string;
  name?: string;
  topology?: Topology;
  status: string;
  started_at?: string;
  settings?: Experiment;
  // A summary of what the run did, as listed in History (all optional: older runs
  // had no detection setup).
  detector_mode?: string | null;
  detector_model?: string | null;
  attackers?: number | null;
  mitigation?: string | null;
  policy?: string | null;
  dry_run?: string | null;
  forwarding?: string | null;
  match_ports?: string | null;
};
export type Status = {
  state: string;
  run_id: string | null;
  persistence_error?: boolean;
  runner_instance_id?: string;
  started_at?: string | null;
  ended_at?: string | null;
  elapsed_ms?: number;
  unavailable?: boolean;
};

export type Notice = {
  tone: "error" | "warning" | "success" | "info";
  title: string;
  detail?: string;
  hint?: string;
};

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const statusMessages: Record<number, string> = {
  400: "The workspace sent a request this lab could not read. Reload the page and try again.",
  401: "Your workspace session has expired. Sign in again with your local access token.",
  403: "This request came from an address the lab does not trust. Open the workspace at the address the lab printed when it started.",
  404: "That record no longer exists. Refresh the history list to see what is still stored.",
  409: "The lab is already busy with another run. Stop the current run before starting a new one.",
  413: "That file is larger than the 1 MiB the workspace accepts.",
  429: "Too many attempts in a short time. Wait a minute, then try again.",
  500: "The lab hit an unexpected internal error. Check the runner logs for the details.",
  503: "A lab service is not answering. Check that the runner and database containers are running.",
};

/** Read whatever the server sent, and never show the user a bare status code. */
function explain(payload: unknown, status: number): string {
  const detail = (payload as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string" && detail.trim()) return detail.trim();
  if (Array.isArray(detail) && detail.length) {
    return detail
      .map((item) => {
        const path = (item?.loc ?? [])
          .filter((part: unknown) => part !== "body" && part !== "query")
          .join(" · ");
        return path ? `${path}: ${item?.msg}` : String(item?.msg ?? "");
      })
      .filter(Boolean)
      .join(" ");
  }
  return (
    statusMessages[status] ??
    `The lab answered with an unexpected error (HTTP ${status}).`
  );
}

export async function api<T>(
  path: string,
  body?: unknown,
  method?: string,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch("/api" + path, {
      method: method ?? (body === undefined ? "GET" : "POST"),
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(
      0,
      "The workspace cannot reach the local lab service. Check that the lab containers are still running, then try again.",
    );
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new ApiError(response.status, explain(payload, response.status));
  }
  return response.json();
}

/** Every recorded event of a run, oldest first, read page by page from the lab. */
export async function fetchRunEvents(id: string): Promise<Observation[]> {
  let all: Observation[] = [];
  let after = 0;
  for (;;) {
    const page = await api<Observation[]>(`/runs/${id}/events?after=${after}`);
    if (!page.length) break;
    all = all.concat(page);
    after = page[page.length - 1].seq;
    if (all.length > 100000)
      throw new Error(
        "This record holds more than 100,000 events, which is too much for the browser to read. Download its JSON or CSV from the history list instead.",
      );
  }
  return all.sort(
    (a, b) => Date.parse(a.ts) - Date.parse(b.ts) || a.seq - b.seq,
  );
}

/** Save text the browser built (a CSV, say) as a file. */
export function downloadText(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function download(name: string, data: unknown) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function listed(names: string[]) {
  const items = [...new Set(names)].sort();
  const shown = items.slice(0, 6);
  const text =
    shown.length > 1
      ? `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`
      : shown[0];
  return items.length > 6 ? `${text}, and ${items.length - 6} more` : text;
}

/**
 * Mirror of the server's topology rules, so the editor can warn about a broken
 * network while it is still being drawn instead of only when a run is refused.
 */
export function topologyProblems(topology: Topology | null): string[] {
  if (!topology) return [];
  const problems: string[] = [];
  const hostNames = new Set(topology.hosts.map((h) => h.name));
  const nodes = [...topology.hosts, ...topology.switches].map((n) => n.name);
  const repeated = (values: string[]) =>
    values.filter((value, index) => values.indexOf(value) !== index);

  const sameName = repeated(nodes);
  if (sameName.length)
    problems.push(
      `The name ${listed(sameName)} is used by more than one device. Give every host and switch its own name.`,
    );
  const sameAddress = repeated(topology.hosts.map((h) => h.ip.split("/")[0]));
  if (sameAddress.length)
    problems.push(
      `The address ${listed(sameAddress)} is used by more than one host. Give every host its own IPv4 address.`,
    );
  const sameDpid = repeated(topology.switches.map((s) => String(s.dpid)));
  if (sameDpid.length)
    problems.push(
      `The datapath ID (DPID) ${listed(sameDpid)} is used by more than one switch. Every switch needs its own DPID.`,
    );

  const degree = new Map(nodes.map((name) => [name, 0]));
  const parent = new Map(nodes.map((name) => [name, name]));
  const root = (name: string): string => {
    let current = name;
    while (parent.get(current) !== current) current = parent.get(current)!;
    return current;
  };
  for (const link of topology.links) {
    const missing = [link.source, link.target].filter((n) => !parent.has(n));
    if (missing.length) {
      problems.push(
        `Link ${link.id} points at ${listed(missing)}, which is not a device here. Delete the link or add the device back.`,
      );
      continue;
    }
    if (hostNames.has(link.source) && hostNames.has(link.target))
      problems.push(
        `Link ${link.id} joins two hosts (${link.source} and ${link.target}). Every host connects to a switch instead.`,
      );
    degree.set(link.source, degree.get(link.source)! + 1);
    degree.set(link.target, degree.get(link.target)! + 1);
    const [left, right] = [root(link.source), root(link.target)];
    if (left === right)
      problems.push(
        `Link ${link.id} repeats a connection or closes a loop between ${link.source} and ${link.target}. This lab needs exactly one path between any two devices.`,
      );
    else parent.set(left, right);
  }
  const alone = [...hostNames].filter((name) => degree.get(name) === 0);
  if (alone.length)
    problems.push(
      alone.length === 1
        ? `${listed(alone)} has no link yet. Drag from its handle to a switch so it can reach the network.`
        : `${listed(alone)} have no link yet. Drag from each handle to a switch so they can reach the network.`,
    );
  const crowded = [...hostNames].filter((name) => degree.get(name)! > 1);
  if (crowded.length)
    problems.push(
      `${listed(crowded)} uses more than one link. A host here has a single network interface, so keep exactly one link per host.`,
    );
  const groups = new Map(nodes.map((name) => [name, root(name)]));
  const distinct = new Set(groups.values());
  if (nodes.length && distinct.size > 1) {
    const size = (group: string) =>
      [...groups.values()].filter((value) => value === group).length;
    const largest = [...distinct].sort((a, b) => size(b) - size(a))[0];
    // A host with no link at all was already reported; do not say it twice.
    const stranded = nodes.filter(
      (name) => groups.get(name) !== largest && !alone.includes(name),
    );
    if (stranded.length)
      problems.push(
        `${listed(stranded)} cannot reach the rest of the network. Add a link so every device belongs to one connected network.`,
      );
  }
  return problems;
}

export function formatRate(value: number) {
  return value >= 1e6
    ? `${(value / 1e6).toFixed(2)} Mb/s`
    : `${(value / 1000).toFixed(1)} kb/s`;
}

export function packets(events: Observation[]) {
  return events
    .flatMap((event) =>
      event.kind === "packet"
        ? [event.data]
        : event.kind === "packets"
          ? event.data.items
          : [],
    )
    .slice(-500) as Record<string, any>[];
}
