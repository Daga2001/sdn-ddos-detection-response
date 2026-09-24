export type Position = { x: number; y: number };
export type Task = (action: () => Promise<void>) => Promise<void>;
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
export type Experiment = {
  source: string;
  target: string;
  client: string;
  rate: number;
  duration: number;
  baseline: number;
  recovery: number;
  mitigation: boolean;
  confirm_isolated_lab: boolean;
};
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
};
export type Status = {
  state: string;
  run_id: string | null;
  persistence_error?: boolean;
};

export async function api<T>(
  path: string,
  body?: unknown,
  method?: string,
): Promise<T> {
  const response = await fetch("/api" + path, {
    method: method ?? (body === undefined ? "GET" : "POST"),
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(
      typeof error.detail === "string"
        ? error.detail
        : "Please check the selected values. The server rejected this request.",
    );
  }
  return response.json();
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
