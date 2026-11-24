import { CompareRuns } from "./CompareRuns";
import { describeRun } from "./detection";
import { activeStates } from "./types";
import type { Topology, Run, Task } from "./types";

export function HistoryPanel({
  projects,
  runs,
  busy,
  locked,
  active,
  task,
  refreshHistory,
  loadTopology,
  openReplay,
}: {
  projects: { id: string; topology: Topology }[];
  runs: Run[];
  busy: boolean;
  locked: boolean;
  active: boolean;
  task: Task;
  refreshHistory: () => Promise<void>;
  loadTopology: (topology: Topology) => void;
  openReplay: (id: string) => Promise<void>;
}) {
  return (
    <div className="panel-content">
      <span className="eyebrow">REPRODUCIBLE BY DESIGN</span>
      <h2>Run it. Read it back.</h2>
      <p>
        Replay uses recorded observations. It does not restart Mininet or send
        packets.
      </p>
      <button
        disabled={busy}
        onClick={() =>
          void task(
            refreshHistory,
            "The workspace could not refresh saved records.",
          )
        }
      >
        Refresh records
      </button>
      <h3>Saved topologies</h3>
      {projects.map((p) => (
        <button
          className="history-item"
          key={p.id}
          disabled={locked}
          onClick={() => loadTopology(p.topology)}
        >
          {p.topology.name}
          <small>Load saved snapshot ↗</small>
        </button>
      ))}
      {!projects.length && (
        <p className="footnote">Select the empty canvas to save a project.</p>
      )}
      <h3>Experiments & observations</h3>
      {runs.map((run) => (
        <div className="history-item" key={run.id}>
          <strong>
            {run.name ?? run.topology?.name ?? run.id.slice(0, 8)}
          </strong>
          <small>
            {run.status} · {run.started_at?.slice(0, 19)}
          </small>
          {describeRun(run) && (
            <small className="run-summary">{describeRun(run)}</small>
          )}
          <div>
            <button
              disabled={busy || active || activeStates.includes(run.status)}
              onClick={() =>
                void task(
                  () => openReplay(run.id),
                  "This record could not be opened for replay.",
                )
              }
            >
              Replay
            </button>
            <a href={`/api/runs/${run.id}/export?format=json`}>JSON ↓</a>
            <a href={`/api/runs/${run.id}/export?format=csv`}>CSV ↓</a>
          </div>
        </div>
      ))}
      {!runs.length && <p>No runs recorded yet.</p>}
      <CompareRuns runs={runs} busy={busy || active} />
    </div>
  );
}
