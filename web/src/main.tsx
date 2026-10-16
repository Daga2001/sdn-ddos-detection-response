import { ExperimentPanel } from "./ExperimentPanel";
import { InspectorPanel } from "./InspectorPanel";
import { HistoryPanel } from "./HistoryPanel";
import { DownloadMenu } from "./DownloadMenu";
import { DetectionPanel, DetectorSwitch } from "./DetectionPanel";
import { DetectionResults } from "./DetectionResults";
import { retainEvents } from "./detection";
import { HandIcon, PointerIcon } from "./Icons";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { TopologyCanvas } from "./TopologyCanvas";
import { Observations } from "./Observations";
import {
  api,
  download,
  formatRate,
  formatElapsed,
  activeStates,
  topologyProblems,
  legitimateClients,
  normalizeExperiment,
  emptyExperiment,
  detectionFromService,
  CONTROLLER_ID,
} from "./types";
import type {
  DetectionOptions,
  Topology,
  Observation,
  Run,
  Status,
  Experiment,
  Notice,
} from "./types";
import "./style.css";

const defaultExperiment: Experiment = emptyExperiment;

// Plain-language reasons each inspector tab exists, shown on hover.
const panelHints: Record<string, string> = {
  Experiment:
    "Set up and launch a controlled attack: choose attackers, victims, the traffic they send, and the timing, then start it and watch the impact.",
  Inspect:
    "Look at and edit whatever you have selected on the canvas — a host's address, a switch, a link's bandwidth — or read the managed controller's live stats.",
  Detection:
    "Choose how attacks are detected — an LLM or entropy — and tune it. The setup is saved with every run you start.",
  History:
    "Reopen saved networks and past runs, and replay a finished run step by step. Replay only reads records; it never sends traffic.",
};

function fileBase(name: string) {
  return (
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 50) || "topology"
  );
}

function App() {
  const [authenticated, setAuthenticated] = useState(false);
  const [token, setToken] = useState("");
  const [topology, setTopology] = useState<Topology | null>(null);
  const [presets, setPresets] = useState<Topology[]>([]);
  const [projects, setProjects] = useState<
    { id: string; topology: Topology }[]
  >([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [status, setStatus] = useState<Status>({ state: "idle", run_id: null });
  const [connected, setConnected] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busy, setBusy] = useState(false);
  const [selection, setSelection] = useState<string[]>([]);
  const [mode, setMode] = useState<"select" | "pan">("select");
  const [tab, setTab] = useState("Traffic");
  const [panel, setPanel] = useState("Experiment");
  const [events, setEvents] = useState<Observation[]>([]);
  const [experiment, setExperiment] = useState<Experiment>(defaultExperiment);
  const [detectorOptions, setDetectorOptions] = useState<DetectionOptions>({});
  const [replay, setReplay] = useState<{
    run: Run;
    events: Observation[];
  } | null>(null);
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const eventCursor = useRef({ run: "", seq: 0 });
  const seenRun = useRef("");
  const importInput = useRef<HTMLInputElement>(null);
  const [now, setNow] = useState(() => Date.now());
  const active = activeStates.includes(status.state);
  const locked = active || !!replay || busy;
  const visible = replay ? replay.events.slice(0, cursor) : events;
  const shownTopology = replay?.run.topology ?? topology;
  const problems = useMemo(
    () => (replay ? [] : topologyProblems(topology)),
    [topology, replay],
  );
  const phase = replay
    ? (visible.findLast((e) => e.kind === "phase")?.data.state ?? "ready")
    : status.state;
  const detector =
    visible.findLast((e) => e.kind === "detector")?.data.status ??
    "not observed";
  const detections = visible.filter((e) => e.kind === "detection").length;
  // The most recent failure reason, shown verbatim so a failed run is debuggable.
  const failure = visible.findLast((e) => e.kind === "error")?.data;
  const mitigationCount = visible.filter(
    (e) => e.kind === "mitigation_requested",
  ).length;
  const measurement = visible.findLast((e) => e.kind === "links");
  const controllerSample = visible.findLast(
    (e) => e.kind === "controller",
  )?.data;
  const totalRate = (measurement?.data.links ?? []).reduce(
    (sum: number, row: any) =>
      sum + (row.rates ? row.rates.rx_bps + row.rates.tx_bps : 0),
    0,
  );
  // Elapsed run time, measured from the first phase event. Live runs tick
  // against the wall clock; a replay is frozen at the last visible event.
  const runStart = visible.find((e) => e.kind === "phase")?.ts;
  const lastTs = visible.length ? visible[visible.length - 1].ts : undefined;
  const runEnd = replay
    ? lastTs
    : active
      ? new Date(now).toISOString()
      : lastTs;
  const elapsedMs =
    runStart && runEnd
      ? Math.max(0, Date.parse(runEnd) - Date.parse(runStart))
      : null;

  const task = useCallback(
    async (action: () => Promise<void>, failureTitle?: string) => {
      setBusy(true);
      setNotice(null);
      try {
        await action();
      } catch (error) {
        setNotice({
          tone: "error",
          title: failureTitle ?? "That action did not go through.",
          detail:
            error instanceof Error
              ? error.message
              : "The lab did not say what went wrong.",
        });
      } finally {
        setBusy(false);
      }
    },
    [],
  );
  const select = useCallback((ids: string[]) => {
    // The controller is inspected on its own; it is never part of a bulk edit.
    const cleaned =
      ids.length > 1 ? ids.filter((id) => id !== CONTROLLER_ID) : ids;
    setSelection(cleaned);
    if (cleaned.length) setPanel("Inspect");
  }, []);

  function loadTopology(value: Topology) {
    setTopology(structuredClone(value));
    setSelection([]);
    setReplay(null);
    setEvents([]);
    // The detector choice belongs to the user, not to the network: keep it.
    setExperiment((previous) => ({
      ...defaultExperiment,
      attackers: value.hosts[0] ? [value.hosts[0].name] : [],
      victims: value.hosts[1] ? [value.hosts[1].name] : [],
      detection: previous.detection,
      mitigation: previous.mitigation,
    }));
  }
  const loadDetectorOptions = useCallback(async () => {
    try {
      setDetectorOptions(await api<DetectionOptions>("/detection/options"));
    } catch (error) {
      setDetectorOptions({
        available: false,
        reason:
          error instanceof Error
            ? error.message
            : "The lab did not answer about its detector.",
      });
    }
  }, []);
  useEffect(() => {
    api<{ authenticated: boolean }>("/session")
      .then((s) => setAuthenticated(s.authenticated))
      .catch((error) =>
        setNotice({
          tone: "error",
          title: "The workspace cannot reach the local lab service.",
          detail: error instanceof Error ? error.message : undefined,
          hint: "Start the lab with `make lab-up`, then reload this page.",
        }),
      );
  }, []);
  useEffect(() => {
    if (!authenticated) return;
    void loadDetectorOptions();
    void task(async () => {
      const values = await api<Topology[]>("/presets");
      setPresets(values);
      if (!topology && !seenRun.current) loadTopology(values[1]);
      setProjects(await api("/projects"));
      setRuns(await api("/runs"));
    }, "The workspace could not load its saved topologies and runs.");
    const source = new EventSource("/api/events");
    source.addEventListener("status", (event) => {
      const next: Status = JSON.parse(event.data);
      setStatus(next);
      setConnected(true);
      if (next.run_id && seenRun.current !== next.run_id) {
        seenRun.current = next.run_id;
        // A reloaded browser must display the actual running topology, not a preset.
        api<Run>(`/runs/${next.run_id}`)
          .then((run) => {
            if (run.topology) {
              setTopology(run.topology);
            }
            if (run.settings) setExperiment(normalizeExperiment(run.settings));
          })
          .catch((error) =>
            setNotice({
              tone: "warning",
              title: "Could not load the topology of the run in progress.",
              detail: error instanceof Error ? error.message : undefined,
              hint: "The run keeps going. Reload the page to try again.",
            }),
          );
      }
    });
    source.addEventListener("observation", (event) => {
      const value: Observation = JSON.parse(event.data);
      if (eventCursor.current.run !== value.run_id) {
        eventCursor.current = { run: value.run_id, seq: 0 };
        setEvents([]);
      }
      if (value.seq <= eventCursor.current.seq) return;
      eventCursor.current.seq = value.seq;
      setEvents((current) => retainEvents([...current, value]));
    });
    source.addEventListener("gap", () =>
      setNotice({
        tone: "warning",
        title: "Some live events were skipped.",
        detail:
          "The browser fell behind the runner, so this live view has holes in it.",
        hint: "Nothing was lost on disk: open History and replay this run for the full recorded record.",
      }),
    );
    source.addEventListener("unavailable", () => {
      setConnected(false);
      setNotice({
        tone: "warning",
        title: "The connection to the lab runner was lost.",
        detail:
          "The numbers on screen are the last ones measured and are no longer updating.",
        hint: "Any run already started keeps its own time limits and will still stop on its own.",
      });
    });
    source.addEventListener("expired", () => {
      source.close();
      setAuthenticated(false);
    });
    source.onerror = () => setConnected(false);
    return () => source.close();
  }, [authenticated, loadDetectorOptions]);
  useEffect(() => {
    // A detector that was unreachable once (the lab restarting, a dropped tunnel) comes
    // back on its own instead of leaving the Detection tab blocked until a reload.
    if (!authenticated || detectorOptions.available) return;
    const timer = window.setInterval(() => void loadDetectorOptions(), 5000);
    return () => window.clearInterval(timer);
  }, [authenticated, detectorOptions.available, loadDetectorOptions]);
  useEffect(() => {
    // Start from whatever the detector service is set to, so nothing changes until
    // the user chooses something else.
    if (replay || experiment.detection || !detectorOptions.available) return;
    setExperiment((previous) =>
      previous.detection
        ? previous
        : {
            ...previous,
            detection: detectionFromService(detectorOptions.current),
          },
    );
  }, [detectorOptions, experiment.detection, replay]);
  useEffect(() => {
    if (!playing || !replay || cursor >= replay.events.length) {
      if (playing) setPlaying(false);
      return;
    }
    const previousTime = cursor
      ? Date.parse(replay.events[cursor - 1].ts)
      : Date.parse(replay.events[0].ts);
    const delay =
      Math.max(0, Date.parse(replay.events[cursor].ts) - previousTime) / speed;
    const timer = setTimeout(() => setCursor((value) => value + 1), delay);
    return () => clearTimeout(timer);
  }, [playing, replay, cursor, speed]);
  useEffect(() => {
    // Keep the run clock moving while a live run is in progress.
    if (replay || !active) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [replay, active]);

  async function refreshHistory() {
    setProjects(await api("/projects"));
    setRuns(await api("/runs"));
  }
  async function start(withExperiment: boolean) {
    if (!topology) return;
    await api("/runs", {
      topology,
      experiment: withExperiment ? experiment : null,
    });
    setReplay(null);
    setStatus(await api("/status"));
  }
  async function openReplay(id: string) {
    const run = await api<Run>(`/runs/${id}`);
    if (activeStates.includes(run.status))
      throw new Error(
        "This run is still going. Stop it first, then replay its completed record.",
      );
    let all: Observation[] = [];
    let after = 0;
    for (;;) {
      const page = await api<Observation[]>(
        `/runs/${id}/events?after=${after}`,
      );
      if (!page.length) break;
      all = all.concat(page);
      after = page[page.length - 1].seq;
      if (all.length > 100000)
        throw new Error(
          "This record holds more than 100,000 events, which is too much for the browser to replay. Download its JSON or CSV from the history list instead.",
        );
    }
    all.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts) || a.seq - b.seq);
    setReplay({ run, events: all });
    setCursor(0);
    setPlaying(false);
    setSelection([]);
    setPanel("History");
  }
  /** New devices join the least busy switch, so nothing is ever left stranded. */
  function add(kind: "host" | "switch") {
    if (!topology) return;
    const taken = new Set(
      [...topology.hosts, ...topology.switches].map((n) => n.name),
    );
    let index = 1;
    while (taken.has(`${kind[0]}${index}`)) index++;
    const name = `${kind[0]}${index}`;
    const load = new Map(topology.switches.map((s) => [s.name, 0]));
    for (const link of topology.links)
      for (const end of [link.source, link.target])
        if (load.has(end)) load.set(end, load.get(end)! + 1);
    const anchor = [...load.entries()].sort(
      (a, b) => a[1] - b[1] || a[0].localeCompare(b[0]),
    )[0]?.[0];
    const anchorNode = topology.switches.find((s) => s.name === anchor);
    const link = anchor
      ? [
          {
            id: `link-${crypto.randomUUID().slice(0, 8)}`,
            source: anchor,
            target: name,
            bandwidth_mbps: null,
            delay_ms: 0,
            loss_percent: 0,
          },
        ]
      : [];
    if (kind === "host") {
      const siblings = topology.links.filter(
        (l) =>
          (l.source === anchor || l.target === anchor) &&
          topology.hosts.some(
            (h) => h.name === l.source || h.name === l.target,
          ),
      ).length;
      const position = {
        x: (anchorNode?.position.x ?? 120) - 40 + (siblings % 4) * 95,
        y:
          (anchorNode?.position.y ?? 120) +
          170 +
          Math.floor(siblings / 4) * 110,
      };
      let address = 1;
      while (
        topology.hosts.some((h) => h.ip.split("/")[0] === `10.0.0.${address}`)
      )
        address++;
      setTopology({
        ...topology,
        hosts: [
          ...topology.hosts,
          { name, ip: `10.0.0.${address}/24`, position },
        ],
        links: [...topology.links, ...link],
      });
    } else {
      const position = {
        x: Math.max(...topology.switches.map((s) => s.position.x), 0) + 230,
        y: anchorNode?.position.y ?? 120,
      };
      let dpid = 1;
      while (topology.switches.some((s) => s.dpid === dpid)) dpid++;
      setTopology({
        ...topology,
        switches: [...topology.switches, { name, dpid, position }],
        links: [...topology.links, ...link],
      });
    }
    setSelection([name]);
    setPanel("Inspect");
    setNotice({
      tone: "info",
      title: anchor
        ? `Added ${name} and connected it to ${anchor}.`
        : `Added ${name}.`,
      detail: anchor
        ? "Every device needs a path to the rest of the network, so the workspace wired it up for you."
        : "Draw a link from this device to the rest of the network before starting a run.",
      hint: anchor
        ? `To move it elsewhere, select the new link and remove it, then drag from ${name}'s handle to another switch.`
        : undefined,
    });
  }
  function removeItems(ids: string[]) {
    const doomed = new Set(ids);
    setTopology((current) =>
      current
        ? {
            ...current,
            hosts: current.hosts.filter((h) => !doomed.has(h.name)),
            switches: current.switches.filter((s) => !doomed.has(s.name)),
            links: current.links.filter(
              (l) =>
                !doomed.has(l.id) &&
                !doomed.has(l.source) &&
                !doomed.has(l.target),
            ),
          }
        : current,
    );
    setSelection([]);
  }
  async function importFile(file: File) {
    if (file.size > 1024 * 1024)
      throw new Error(
        `This file is ${(file.size / 1048576).toFixed(1)} MiB. The workspace reads topology files up to 1 MiB.`,
      );
    let data: unknown;
    try {
      data = JSON.parse(await file.text());
    } catch {
      throw new Error(
        `“${file.name}” is not valid JSON, so nothing inside it could be read. Export a project from this workspace, or save a MiniEdit v2 file.`,
      );
    }
    const result = await api<{ topology: Topology; warnings: string[] }>(
      "/import",
      data,
    );
    loadTopology(result.topology);
    setNotice({
      tone: result.warnings.length ? "warning" : "success",
      title: `Imported “${result.topology.name}”.`,
      detail: result.warnings.join(" ") || undefined,
      hint: `${result.topology.hosts.length} hosts, ${result.topology.switches.length} switches and ${result.topology.links.length} links are on the canvas.`,
    });
  }
  async function exportJson() {
    if (!shownTopology) return;
    await api("/validate", shownTopology);
    download(`${fileBase(shownTopology.name)}.json`, shownTopology);
    setNotice({
      tone: "success",
      title: `Saved ${fileBase(shownTopology.name)}.json.`,
      detail: "Import it back with the Import button whenever you need it.",
    });
  }
  async function exportMiniedit() {
    if (!shownTopology) return;
    const data = await api("/export/miniedit", shownTopology);
    download(`${fileBase(shownTopology.name)}.mn`, data);
    setNotice({
      tone: "success",
      title: `Saved ${fileBase(shownTopology.name)}.mn.`,
      detail:
        "Open it in MiniEdit, or import it back here — the workspace reads its own MiniEdit files.",
    });
  }

  if (!authenticated)
    return (
      <main className="login">
        <div className="login-art">
          <span className="eyebrow">UNIVALLE / NETWORK RESEARCH</span>
          <h1>
            Understand
            <br />
            what moves
            <br />
            <i>your network.</i>
          </h1>
          <p>
            One workspace for Mininet, OpenFlow, and observable security
            experiments.
          </p>
          <div className="art-network">
            ▣ ── ⇄ ── ▣<br />
            　　 │<br />
            　　 ▣
          </div>
        </div>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void task(async () => {
              await api("/session", { token });
              setToken("");
              setAuthenticated(true);
            }, "That access token was not accepted.");
          }}
        >
          <span className="eyebrow">LOCAL LAB / 01</span>
          <h2>Open your workspace</h2>
          <p>
            Use the access token created by <code>make lab-setup</code>. It
            stays on this computer.
          </p>
          <label>
            Local access token
            <input
              autoComplete="current-password"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              required
            />
          </label>
          <button className="primary" disabled={busy}>
            Enter workspace →
          </button>
          {notice && (
            <p role="alert" className={`notice ${notice.tone}`}>
              <strong>{notice.title}</strong>
              {notice.detail && <span>{notice.detail}</span>}
              {notice.hint && <small>{notice.hint}</small>}
            </p>
          )}
          <small>Isolated experiments only. No public targets.</small>
        </form>
      </main>
    );
  const roleSettings = replay
    ? normalizeExperiment(replay.run.settings)
    : experiment;
  const roles: Record<string, string> = {};
  roleSettings.attackers.forEach((name) => (roles[name] = "source"));
  roleSettings.victims.forEach((name) => (roles[name] = "victim"));
  legitimateClients(shownTopology, roleSettings).forEach(
    (name) => (roles[name] = "client"),
  );
  return (
    <main className="workspace">
      <header className="masthead">
        <div className="brand">
          ⇄{" "}
          <strong>
            SDN<span> / LAB</span>
          </strong>
        </div>
        <span className="project-label">NETWORK SECURITY WORKSPACE</span>
        <div className={`connection ${connected ? "online" : ""}`}>
          ● {connected ? "Runner connected" : "Connection unavailable"}
        </div>
        <button
          onClick={() =>
            void task(async () => {
              await api("/session", undefined, "DELETE");
              setAuthenticated(false);
            }, "The workspace could not lock your session.")
          }
        >
          Lock
        </button>
      </header>
      <div className="workbar">
        <div>
          <span className="eyebrow">
            {replay
              ? "RECORDED REPLAY · NO TRAFFIC IS SENT"
              : "MININET + RYU / OPENFLOW 1.3"}
          </span>
          <h1>{shownTopology?.name ?? "Loading workspace…"}</h1>
        </div>
        <div className="actions">
          <DetectorSwitch
            experiment={replay ? roleSettings : experiment}
            setExperiment={setExperiment}
            options={detectorOptions}
            disabled={locked}
          />
          <span className={`phase ${phase}`}>{phase}</span>
          {elapsedMs !== null && (
            <span
              className="run-clock"
              title={
                replay
                  ? "Elapsed time of this recorded run"
                  : "Elapsed time since this run started"
              }
            >
              ⏱ {formatElapsed(elapsedMs)}
            </span>
          )}
          <button
            disabled={!topology || locked || !connected}
            onClick={() =>
              void task(
                () => start(false),
                "The lab could not start observing this network.",
              )
            }
          >
            ▷ Observe
          </button>
          <button
            className="danger"
            disabled={!active || busy}
            onClick={() =>
              void task(async () => {
                await api("/stop", undefined, "POST");
                setStatus(await api("/status"));
              }, "The lab could not be stopped.")
            }
          >
            ■ Stop lab
          </button>
        </div>
      </div>
      {notice && (
        <div
          className={`notice ${notice.tone}`}
          role={notice.tone === "error" ? "alert" : "status"}
        >
          <div>
            <strong>{notice.title}</strong>
            {notice.detail && <p>{notice.detail}</p>}
            {notice.hint && <small>{notice.hint}</small>}
          </div>
          <button aria-label="Dismiss message" onClick={() => setNotice(null)}>
            ×
          </button>
        </div>
      )}
      {status.persistence_error && (
        <div className="notice error" role="alert">
          <div>
            <strong>Recording failed, so this run was stopped.</strong>
            <p>
              The workspace could not write observations to the database, and a
              run that cannot be recorded is not evidence.
            </p>
            <small>
              Check that the database container is running and that the schema
              migration has been applied, then start the run again.
            </small>
          </div>
        </div>
      )}
      {failure && (
        <div className="notice error" role="alert">
          <div>
            <strong>This run failed.</strong>
            <p>{failure.message}</p>
            {failure.detail && (
              <pre className="error-detail">{failure.detail}</pre>
            )}
            <small>
              Open the Commands tab below for the full log of what each node ran
              and how it exited.
            </small>
          </div>
        </div>
      )}
      <div className="metrics">
        <div title="Total traffic measured across every link right now, summed. Because a packet is counted again at each hop it crosses, this is higher than true end-to-end throughput — read it as a relative pulse of how busy the network is, not an exact bandwidth figure. It rises sharply under a flood.">
          <span>Observed traffic</span>
          <strong>{measurement ? formatRate(totalRate) : "—"}</strong>
          <small>
            sum across links{" "}
            {replay
              ? "· recorded"
              : connected && active
                ? "· live"
                : "· last measurement"}
          </small>
        </div>
        <div title="Whether the machine-learning detector service is reachable and ready to classify traffic. It is separate from the lab itself: observation and experiments work with no detector, but a detector that is 'not ready' means no detection or mitigation claim can be made. The detector container is started with scripts/lab_detector.sh; without it this stays 'not observed'.">
          <span>Detector</span>
          <strong>{String(detector).replaceAll("_", " ")}</strong>
          <small>Model availability is separate from observation</small>
        </div>
        <div title="How many times the detector actually flagged traffic as an attack during this run. High traffic by itself is not a detection — only the model saying so counts here. With no detector selected (or no detector container), this stays at zero even during a heavy flood.">
          <span>Detection events</span>
          <strong>{detections}</strong>
          <small>High traffic alone is not a detection</small>
        </div>
        <div title="How many times the controller was asked to install a temporary drop rule in response to a detection. A request is not proof the rule took effect — the Timeline's mitigation_observed entries show what the switches actually hold. It stays at zero unless the response is turned on in the Detection tab; a dry run records no requests.">
          <span>Mitigation requests</span>
          <strong>{mitigationCount}</strong>
          <small>Requested rules ≠ verified delivery</small>
        </div>
      </div>
      <div className="main-grid">
        <div className="network-column">
          <section className="network">
            <div className="canvas-toolbar">
              <span className="eyebrow">TOPOLOGY</span>
              <div
                className="mode-switch"
                role="group"
                aria-label="Canvas tool"
              >
                <button
                  className={mode === "select" ? "active" : ""}
                  aria-pressed={mode === "select"}
                  title="Select tool — drag on empty canvas to select several devices at once"
                  onClick={() => setMode("select")}
                >
                  <PointerIcon />
                  Select
                </button>
                <button
                  className={mode === "pan" ? "active" : ""}
                  aria-pressed={mode === "pan"}
                  title="Pan tool — drag the canvas to move around the network"
                  onClick={() => setMode("pan")}
                >
                  <HandIcon />
                  Pan
                </button>
              </div>
              <select
                aria-label="Topology preset"
                disabled={locked}
                value=""
                onChange={(e) => {
                  if (e.target.value)
                    loadTopology(presets[Number(e.target.value) - 1]);
                }}
              >
                <option value="">Choose a preset…</option>
                {presets.map((p, i) => (
                  <option key={p.name} value={i + 1}>
                    {p.name}
                  </option>
                ))}
              </select>
              <button
                disabled={locked || (topology?.hosts.length ?? 0) >= 32}
                onClick={() => add("host")}
              >
                + Host
              </button>
              <button
                disabled={locked || (topology?.switches.length ?? 0) >= 16}
                onClick={() => add("switch")}
              >
                + Switch
              </button>
              <button
                disabled={locked}
                onClick={() => importInput.current?.click()}
              >
                Import
              </button>
              <input
                ref={importInput}
                type="file"
                accept=".json,.mn"
                hidden
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file)
                    void task(
                      () => importFile(file),
                      `“${file.name}” could not be imported.`,
                    );
                  e.target.value = "";
                }}
              />
              <DownloadMenu
                disabled={!shownTopology || busy}
                choices={[
                  {
                    label: "Project JSON",
                    note: "This workspace · re-imports exactly",
                    run: () =>
                      void task(
                        exportJson,
                        "This network cannot be saved to a file yet.",
                      ),
                  },
                  {
                    label: "MiniEdit topology",
                    note: "Opens in Mininet's MiniEdit editor",
                    run: () =>
                      void task(
                        exportMiniedit,
                        "This network cannot be exported to MiniEdit yet.",
                      ),
                  },
                ]}
              />
            </div>
            <div className="canvas">
              {shownTopology && (
                <TopologyCanvas
                  key={shownTopology.name + (replay?.run.id ?? "")}
                  topology={shownTopology}
                  onChange={setTopology}
                  selection={selection}
                  select={select}
                  locked={locked}
                  events={visible}
                  roles={roles}
                  mode={mode}
                  remove={removeItems}
                />
              )}
            </div>
            <div className="canvas-footer">
              <span>
                1 controller / {shownTopology?.switches.length ?? 0} switches /{" "}
                {shownTopology?.hosts.length ?? 0} hosts /{" "}
                {shownTopology?.links.length ?? 0} links
              </span>
              {problems.length > 0 && (
                <button
                  className="footer-problems"
                  onClick={() => {
                    setSelection([]);
                    setPanel("Inspect");
                  }}
                >
                  ⚠ {problems.length}{" "}
                  {problems.length === 1 ? "problem" : "problems"} to fix — show
                  me
                </button>
              )}
              <span>
                {locked
                  ? "Topology locked during a run or replay"
                  : mode === "select"
                    ? "Drag to select many · Shift-click to add · Delete removes"
                    : "Drag to move around · switch to Select to choose devices"}
              </span>
            </div>
          </section>
          {replay && (
            <div className="replay-bar">
              <strong>REPLAY</strong>
              <button
                onClick={() => setPlaying(!playing)}
                disabled={!replay.events.length}
              >
                {playing ? "Pause" : "Play"}
              </button>
              <button
                onClick={() => {
                  setPlaying(false);
                  setCursor((c) => Math.min(c + 1, replay.events.length));
                }}
              >
                Step →
              </button>
              <input
                aria-label="Replay position"
                type="range"
                min={0}
                max={replay.events.length}
                value={cursor}
                onChange={(e) => {
                  setPlaying(false);
                  setCursor(Number(e.target.value));
                }}
              />
              <span>
                {cursor}/{replay.events.length}
              </span>
              <select
                aria-label="Replay speed"
                value={speed}
                onChange={(e) => setSpeed(Number(e.target.value))}
              >
                {[0.5, 1, 2, 4, 10].map((s) => (
                  <option key={s} value={s}>
                    {s}×
                  </option>
                ))}
              </select>
              <button
                onClick={() => {
                  setReplay(null);
                  setPlaying(false);
                }}
              >
                Exit
              </button>
            </div>
          )}
          <Observations
            events={visible}
            tab={tab}
            setTab={setTab}
            detectionView={
              <DetectionResults
                events={visible}
                topology={shownTopology}
                experiment={roleSettings.attackers.length ? roleSettings : null}
                active={!replay && active}
              />
            }
          />
        </div>
        <aside className="inspector">
          <nav className="tabs">
            {["Experiment", "Detection", "Inspect", "History"].map((p) => (
              <button
                key={p}
                className={panel === p ? "active" : ""}
                title={panelHints[p]}
                onClick={() => {
                  setPanel(p);
                  if (p === "Detection") void loadDetectorOptions();
                  if (p === "History")
                    void task(
                      refreshHistory,
                      "The workspace could not refresh saved records.",
                    );
                }}
              >
                {p}
              </button>
            ))}
          </nav>
          {panel === "Experiment" && (
            <ExperimentPanel
              topology={topology}
              experiment={experiment}
              setExperiment={setExperiment}
              locked={locked}
              connected={connected}
              task={task}
              start={start}
            />
          )}
          {panel === "Detection" && (
            <DetectionPanel
              experiment={replay ? roleSettings : experiment}
              setExperiment={setExperiment}
              options={detectorOptions}
              locked={locked}
              readOnly={!!replay}
              reload={() => void loadDetectorOptions()}
            />
          )}
          {panel === "Inspect" && (
            <InspectorPanel
              topology={topology}
              shownTopology={shownTopology}
              setTopology={setTopology}
              selection={selection}
              select={select}
              problems={problems}
              controllerSample={controllerSample}
              locked={locked}
              status={status}
              replay={!!replay}
              busy={busy}
              task={task}
              setTab={setTab}
              setNotice={setNotice}
              removeSelected={() => removeItems(selection)}
            />
          )}
          {panel === "History" && (
            <HistoryPanel
              projects={projects}
              runs={runs}
              busy={busy}
              locked={locked}
              active={active}
              task={task}
              refreshHistory={refreshHistory}
              loadTopology={loadTopology}
              openReplay={openReplay}
            />
          )}
        </aside>
      </div>
      <footer className="page-footer">
        <span>REAL EMULATION. EXPLAINABLE OBSERVATION.</span>
        <span>
          Linux-only container lab · kernel privileges required · local use
        </span>
      </footer>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
