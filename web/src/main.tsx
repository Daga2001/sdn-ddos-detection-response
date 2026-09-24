import { ExperimentPanel } from "./ExperimentPanel";
import { InspectorPanel } from "./InspectorPanel";
import { HistoryPanel } from "./HistoryPanel";
import { useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { TopologyCanvas } from "./TopologyCanvas";
import { Observations } from "./Observations";
import { api, download, formatRate, activeStates } from "./types";
import type { Topology, Observation, Run, Status, Experiment } from "./types";
import "./style.css";

const defaultExperiment: Experiment = {
  source: "",
  target: "",
  client: "",
  rate: 100,
  duration: 20,
  baseline: 30,
  recovery: 30,
  mitigation: false,
  confirm_isolated_lab: false,
};

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
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState("");
  const [tab, setTab] = useState("Traffic");
  const [panel, setPanel] = useState("Experiment");
  const [events, setEvents] = useState<Observation[]>([]);
  const [experiment, setExperiment] = useState<Experiment>(defaultExperiment);
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
  const active = activeStates.includes(status.state);
  const locked = active || !!replay || busy;
  const visible = replay ? replay.events.slice(0, cursor) : events;
  const shownTopology = replay?.run.topology ?? topology;
  const phase = replay
    ? (visible.findLast((e) => e.kind === "phase")?.data.state ?? "ready")
    : status.state;
  const detector =
    visible.findLast((e) => e.kind === "detector")?.data.status ??
    "not observed";
  const detections = visible.filter((e) => e.kind === "detection").length;
  const mitigationCount = visible.filter(
    (e) => e.kind === "mitigation_requested",
  ).length;
  const measurement = visible.findLast((e) => e.kind === "links");
  const totalRate = (measurement?.data.links ?? []).reduce(
    (sum: number, row: any) =>
      sum + (row.rates ? row.rates.rx_bps + row.rates.tx_bps : 0),
    0,
  );

  const task = useCallback(async (action: () => Promise<void>) => {
    setBusy(true);
    setNotice("");
    try {
      await action();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  }, []);

  function loadTopology(value: Topology) {
    setTopology(structuredClone(value));
    setSelected("");
    setReplay(null);
    setEvents([]);
    setExperiment({
      ...defaultExperiment,
      source: value.hosts[0]?.name ?? "",
      target: value.hosts[1]?.name ?? "",
      client: value.hosts[2]?.name ?? "",
    });
  }
  useEffect(() => {
    api<{ authenticated: boolean }>("/session")
      .then((s) => setAuthenticated(s.authenticated))
      .catch(() => setNotice("Cannot reach the local lab API."));
  }, []);
  useEffect(() => {
    if (!authenticated) return;
    void task(async () => {
      const values = await api<Topology[]>("/presets");
      setPresets(values);
      if (!topology && !seenRun.current) loadTopology(values[1]);
      setProjects(await api("/projects"));
      setRuns(await api("/runs"));
    });
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
            if (run.settings) setExperiment(run.settings);
          })
          .catch(() => setNotice("Could not load this run’s topology."));
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
      setEvents((current) => [...current.slice(-1999), value]);
    });
    source.addEventListener("gap", () =>
      setNotice(
        "Some live events were skipped. Open recorded history for the full available record.",
      ),
    );
    source.addEventListener("unavailable", () => {
      setConnected(false);
      setNotice(
        "Runner connection lost. Measurements are stale; the runner’s time limits still apply.",
      );
    });
    source.addEventListener("expired", () => {
      source.close();
      setAuthenticated(false);
    });
    source.onerror = () => setConnected(false);
    return () => source.close();
  }, [authenticated]);
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
      throw new Error("Stop this run before replaying its completed record.");
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
          "This record is too large for browser replay. Download its JSON or CSV instead.",
        );
    }
    all.sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts) || a.seq - b.seq);
    setReplay({ run, events: all });
    setCursor(0);
    setPlaying(false);
    setSelected("");
    setPanel("History");
  }
  function add(kind: "host" | "switch") {
    if (!topology) return;
    const allNames = new Set(
      [...topology.hosts, ...topology.switches].map((n) => n.name),
    );
    let index = 1;
    while (allNames.has(`${kind[0]}${index}`)) index++;
    const position = { x: 100 + index * 30, y: 70 };
    if (kind === "host") {
      let address = 1;
      while (
        topology.hosts.some((h) => h.ip.split("/")[0] === `10.0.0.${address}`)
      )
        address++;
      setTopology({
        ...topology,
        hosts: [
          ...topology.hosts,
          { name: `h${index}`, ip: `10.0.0.${address}/24`, position },
        ],
      });
    } else {
      let dpid = 1;
      while (topology.switches.some((s) => s.dpid === dpid)) dpid++;
      setTopology({
        ...topology,
        switches: [...topology.switches, { name: `s${index}`, dpid, position }],
      });
    }
    setSelected(`${kind[0]}${index}`);
    setPanel("Inspect");
  }
  function removeSelected() {
    if (!topology) return;
    setTopology({
      ...topology,
      hosts: topology.hosts.filter((h) => h.name !== selected),
      switches: topology.switches.filter((s) => s.name !== selected),
      links: topology.links.filter(
        (l) =>
          l.id !== selected && l.source !== selected && l.target !== selected,
      ),
    });
    setSelected("");
  }
  async function importFile(file: File) {
    if (file.size > 1024 * 1024)
      throw new Error("Topology files must be smaller than 1 MiB.");
    const data = JSON.parse(await file.text());
    const result = await api<{ topology: Topology; warnings: string[] }>(
      "/import",
      data,
    );
    loadTopology(result.topology);
    setNotice(result.warnings.join(" ") || "Topology imported.");
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
            });
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
            <p role="alert" className="notice">
              {notice}
            </p>
          )}
          <small>Isolated experiments only. No public targets.</small>
        </form>
      </main>
    );
  const roleSettings = replay?.run.settings ?? experiment;
  const roles = {
    [roleSettings.source]: "source",
    [roleSettings.target]: "victim",
    [roleSettings.client]: "client",
  };
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
            })
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
          <span className={`phase ${phase}`}>{phase}</span>
          <button
            disabled={!topology || locked || !connected}
            onClick={() => void task(() => start(false))}
          >
            ▷ Observe
          </button>
          <button
            className="danger"
            disabled={!active || busy}
            onClick={() =>
              void task(async () => {
                await api("/stop");
                setStatus(await api("/status"));
              })
            }
          >
            ■ Stop lab
          </button>
        </div>
      </div>
      {notice && (
        <div className="notice" role="alert">
          {notice}
          <button aria-label="Dismiss message" onClick={() => setNotice("")}>
            ×
          </button>
        </div>
      )}
      {status.persistence_error && (
        <div className="notice">
          Recording failed. This run was stopped and its history may be
          incomplete.
        </div>
      )}
      <div className="metrics">
        <div>
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
        <div>
          <span>Detector</span>
          <strong>{String(detector).replaceAll("_", " ")}</strong>
          <small>Model availability is separate from observation</small>
        </div>
        <div>
          <span>Detection events</span>
          <strong>{detections}</strong>
          <small>High traffic alone is not a detection</small>
        </div>
        <div>
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
                  if (file) void task(() => importFile(file));
                  e.target.value = "";
                }}
              />
              <button
                disabled={!topology || busy}
                onClick={() =>
                  shownTopology && download("topology.json", shownTopology)
                }
              >
                JSON ↓
              </button>
              <button
                disabled={!topology || busy}
                onClick={() =>
                  void task(async () =>
                    download(
                      "topology.mn",
                      await api("/export/miniedit", shownTopology),
                    ),
                  )
                }
              >
                MiniEdit ↓
              </button>
            </div>
            <div className="canvas">
              {shownTopology && (
                <TopologyCanvas
                  key={shownTopology.name + (replay?.run.id ?? "")}
                  topology={shownTopology}
                  onChange={setTopology}
                  selected={selected}
                  select={(id) => {
                    setSelected(id);
                    if (id) setPanel("Inspect");
                  }}
                  locked={locked}
                  events={visible}
                  roles={roles}
                />
              )}
            </div>
            <div className="canvas-footer">
              <span>
                {shownTopology?.switches.length ?? 0} switches /{" "}
                {shownTopology?.hosts.length ?? 0} hosts /{" "}
                {shownTopology?.links.length ?? 0} links
              </span>
              <span>
                {locked
                  ? "Topology locked during a run or replay"
                  : "Drag devices · join handles · select to inspect"}
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
          <Observations events={visible} tab={tab} setTab={setTab} />
        </div>
        <aside className="inspector">
          <nav className="tabs">
            {["Experiment", "Inspect", "History"].map((p) => (
              <button
                key={p}
                className={panel === p ? "active" : ""}
                onClick={() => {
                  setPanel(p);
                  if (p === "History") void task(refreshHistory);
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
          {panel === "Inspect" && (
            <InspectorPanel
              topology={topology}
              shownTopology={shownTopology}
              setTopology={setTopology}
              selected={selected}
              locked={locked}
              status={status}
              replay={!!replay}
              busy={busy}
              task={task}
              setTab={setTab}
              setNotice={setNotice}
              removeSelected={removeSelected}
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
