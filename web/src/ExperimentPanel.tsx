import { useState } from "react";
import type { ReactNode } from "react";
import { Field, CheckField, Hint } from "./Field";
import { HostPicker } from "./HostPicker";
import { legitimateClients, trafficKinds } from "./types";
import type { Topology, Experiment, Task, TrafficKind } from "./types";

const numberFields = {
  rate: {
    label: "Rate · packets/s",
    max: 1000,
    hint: "How many packets per second each attacker sends to each victim. Raise it and the impact becomes obvious but the emulated network works much harder; lower it and the service may barely notice. Allowed: 1 to 1000 per flow.",
  },
  duration: {
    label: "Attack · seconds",
    max: 300,
    hint: "How long the flood lasts. Longer gives more samples and a clearer chart; shorter keeps the run quick. Allowed: 1 to 300.",
  },
  baseline: {
    label: "Baseline · seconds",
    max: 300,
    hint: "Quiet time recorded before the flood. This is the “normal” your results are compared against, so too short leaves you nothing to compare with. Allowed: 1 to 300.",
  },
  recovery: {
    label: "Recovery · seconds",
    max: 300,
    hint: "Quiet time recorded after the flood stops. It shows whether the service returns to normal, and how long that takes. Allowed: 1 to 300.",
  },
} as const;

function toggle<T>(list: T[], value: T): T[] {
  return list.includes(value)
    ? list.filter((item) => item !== value)
    : [...list, value];
}

/** A labelled block with an explain button, for content that is not a single input. */
function Group({
  label,
  hint,
  children,
}: {
  label: string;
  hint: string;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <div className="field-label">{label}</div>
      <Hint text={hint} />
      {children}
    </div>
  );
}

/** Selected hosts as removable chips, or a quiet placeholder when none. */
function ChosenChips({
  names,
  empty,
  onRemove,
}: {
  names: string[];
  empty: string;
  onRemove: (name: string) => void;
}) {
  if (!names.length) return <p className="role-empty">{empty}</p>;
  return (
    <div className="client-chips">
      {names.map((name) => (
        <button
          type="button"
          key={name}
          className="client-chip removable"
          title={`Remove ${name}`}
          onClick={() => onRemove(name)}
        >
          {name} ×
        </button>
      ))}
    </div>
  );
}

export function ExperimentPanel({
  topology,
  experiment,
  setExperiment,
  locked,
  connected,
  task,
  start,
  forwardingChosen,
}: {
  topology: Topology | null;
  experiment: Experiment;
  setExperiment: (value: Experiment) => void;
  locked: boolean;
  connected: boolean;
  task: Task;
  start: (withExperiment: boolean) => Promise<void>;
  forwardingChosen: boolean;
}) {
  const [picker, setPicker] = useState<null | "attackers" | "victims">(null);
  const clients = legitimateClients(topology, experiment);
  const ready =
    forwardingChosen &&
    experiment.attackers.length > 0 &&
    experiment.victims.length > 0 &&
    experiment.traffic.length > 0 &&
    clients.length > 0 &&
    experiment.confirm_isolated_lab;

  return (
    <div className="panel-content">
      <span className="eyebrow">CONTROLLED SCENARIO / 01</span>
      <h2>Watch the impact.</h2>
      <p>
        A bounded, multi-source experiment. Choose one or more attackers and
        victims and the flows they send — TCP SYN, UDP, or ICMP — with normal
        HTTP probes before, during, and after.
      </p>
      <div className="phase-strip">
        <span>01 Baseline</span>
        <span>02 Attack traffic</span>
        <span>03 Recovery</span>
      </div>
      <fieldset disabled={locked}>
        <Group
          label="Attackers"
          hint="The hosts that generate the flood. Pick one for a single-source run, or several for a coordinated, multi-source attack. Each attacker sends its traffic to every victim."
        >
          <ChosenChips
            names={experiment.attackers}
            empty="No attackers chosen yet."
            onRemove={(name) =>
              setExperiment({
                ...experiment,
                attackers: experiment.attackers.filter((n) => n !== name),
              })
            }
          />
          <button
            type="button"
            className="picker-open"
            onClick={() => setPicker("attackers")}
          >
            Select attackers…
          </button>
        </Group>
        <Group
          label="Victims / HTTP service"
          hint="The hosts running the small web service under test. Every number you read afterwards — latency, failed requests — is measured against these hosts. Pick several to study a multi-target attack."
        >
          <ChosenChips
            names={experiment.victims}
            empty="No victims chosen yet."
            onRemove={(name) =>
              setExperiment({
                ...experiment,
                victims: experiment.victims.filter((n) => n !== name),
              })
            }
          />
          <button
            type="button"
            className="picker-open"
            onClick={() => setPicker("victims")}
          >
            Select victims…
          </button>
        </Group>
        <Group
          label="Legitimate clients"
          hint="Not chosen — inferred. Every remaining host in the victims' subnet keeps requesting the service from start to finish, answering the real question: could normal traffic still get through while the flood ran?"
        >
          {clients.length ? (
            <div className="client-chips">
              {clients.map((name) => (
                <span key={name} className="client-chip">
                  {name}
                </span>
              ))}
            </div>
          ) : (
            <p className="role-empty warn">
              No host is left over to act as a legitimate client. Leave at least
              one host in the victims' subnet unassigned.
            </p>
          )}
        </Group>
        <Group
          label="Traffic kind"
          hint="Which flows the attackers send. Choose more than one and the kinds are shared out across the attackers, reproducing a mixed-signature assault such as SYN together with UDP."
        >
          <div className="traffic-kinds" role="group">
            {trafficKinds.map((kind) => (
              <label
                key={kind.id}
                className={`traffic-choice ${
                  experiment.traffic.includes(kind.id) ? "on" : ""
                }`}
                title={kind.hint}
              >
                <input
                  type="checkbox"
                  checked={experiment.traffic.includes(kind.id)}
                  onChange={() =>
                    setExperiment({
                      ...experiment,
                      traffic: toggle(
                        experiment.traffic,
                        kind.id,
                      ) as TrafficKind[],
                    })
                  }
                />
                <span>{kind.label}</span>
              </label>
            ))}
          </div>
        </Group>
        <div className="field-pair">
          {(["rate", "duration", "baseline", "recovery"] as const).map(
            (key) => (
              <Field
                key={key}
                label={numberFields[key].label}
                hint={numberFields[key].hint}
              >
                <input
                  type="number"
                  min={1}
                  max={numberFields[key].max}
                  value={experiment[key]}
                  onChange={(e) =>
                    setExperiment({
                      ...experiment,
                      [key]: Number(e.target.value),
                    })
                  }
                />
              </Field>
            ),
          )}
        </div>
        <CheckField
          className="confirmation"
          label="I confirm these hosts belong to my isolated lab."
          hint="Traffic is generated for real inside Mininet. This box is your statement that the addresses above are your own emulated lab and not equipment anyone else depends on."
          checked={experiment.confirm_isolated_lab}
          onChange={(value) =>
            setExperiment({ ...experiment, confirm_isolated_lab: value })
          }
        />
        <button
          className="primary full"
          disabled={!ready || !connected}
          onClick={() => void task(() => start(true))}
        >
          Start experiment →
        </button>
      </fieldset>
      <p className="footnote">
        Not a guaranteed outage. Attacker × victim flows are capped so the run
        stays bounded, and a missing model allows observation but no valid
        detection or mitigation claim.
      </p>
      <HostPicker
        title="Select attackers"
        open={picker === "attackers"}
        topology={topology}
        selected={experiment.attackers}
        blocked={experiment.victims}
        blockedLabel="victim"
        onToggle={(name) =>
          setExperiment({
            ...experiment,
            attackers: toggle(experiment.attackers, name),
          })
        }
        onClose={() => setPicker(null)}
      />
      <HostPicker
        title="Select victims"
        open={picker === "victims"}
        topology={topology}
        selected={experiment.victims}
        blocked={experiment.attackers}
        blockedLabel="attacker"
        onToggle={(name) =>
          setExperiment({
            ...experiment,
            victims: toggle(experiment.victims, name),
          })
        }
        onClose={() => setPicker(null)}
      />
    </div>
  );
}
