import type { Topology, Experiment, Task } from "./types";

export function ExperimentPanel({
  topology,
  experiment,
  setExperiment,
  locked,
  connected,
  task,
  start,
}: {
  topology: Topology | null;
  experiment: Experiment;
  setExperiment: (value: Experiment) => void;
  locked: boolean;
  connected: boolean;
  task: Task;
  start: (withExperiment: boolean) => Promise<void>;
}) {
  return (
    <div className="panel-content">
      <span className="eyebrow">CONTROLLED SCENARIO / 01</span>
      <h2>Watch the impact.</h2>
      <p>
        A bounded, single-source SYN experiment, with normal HTTP probes before,
        during, and after.
      </p>
      <div className="phase-strip">
        <span>01 Baseline</span>
        <span>02 SYN traffic</span>
        <span>03 Recovery</span>
      </div>
      <fieldset disabled={locked}>
        {(["source", "target", "client"] as const).map((key) => (
          <label key={key}>
            {key === "target"
              ? "Victim / HTTP service"
              : key === "client"
                ? "Legitimate client"
                : "Traffic source"}
            <select
              value={experiment[key]}
              onChange={(e) =>
                setExperiment({ ...experiment, [key]: e.target.value })
              }
            >
              {topology?.hosts.map((h) => (
                <option key={h.name} value={h.name}>
                  {h.name} · {h.ip}
                </option>
              ))}
            </select>
          </label>
        ))}
        <div className="field-pair">
          {(["rate", "duration", "baseline", "recovery"] as const).map(
            (key) => (
              <label key={key}>
                {
                  {
                    rate: "Rate · packets/s",
                    duration: "Attack · seconds",
                    baseline: "Baseline · seconds",
                    recovery: "Recovery · seconds",
                  }[key]
                }
                <input
                  type="number"
                  min={1}
                  max={key === "rate" ? 1000 : 300}
                  value={experiment[key]}
                  onChange={(e) =>
                    setExperiment({
                      ...experiment,
                      [key]: Number(e.target.value),
                    })
                  }
                />
              </label>
            ),
          )}
        </div>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={experiment.mitigation}
            onChange={(e) =>
              setExperiment({
                ...experiment,
                mitigation: e.target.checked,
              })
            }
          />
          Enable temporary controller mitigation
        </label>
        <small>
          Off by default. Requires a ready detector; requested blocks are shown
          separately from detections.
        </small>
        <label className="checkbox confirmation">
          <input
            type="checkbox"
            checked={experiment.confirm_isolated_lab}
            onChange={(e) =>
              setExperiment({
                ...experiment,
                confirm_isolated_lab: e.target.checked,
              })
            }
          />
          I confirm these hosts belong to my isolated lab.
        </label>
        <button
          className="primary full"
          disabled={!experiment.confirm_isolated_lab || !connected}
          onClick={() => void task(() => start(true))}
        >
          Start experiment →
        </button>
      </fieldset>
      <p className="footnote">
        This scenario is not a distributed attack or a guaranteed outage. A
        missing model allows observation, but no valid detection or mitigation
        claim.
      </p>
    </div>
  );
}
