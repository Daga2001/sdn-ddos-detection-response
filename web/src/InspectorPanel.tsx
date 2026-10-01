import { useState } from "react";
import { Field } from "./Field";
import { api, CONTROLLER_ID } from "./types";
import type { Topology, Status, Task, Notice, Link } from "./types";

const linkFields = {
  bandwidth_mbps: {
    label: "Bandwidth · Mb/s",
    hint: "Caps how fast this link may carry traffic. A lower cap congests sooner, so a flood shows its effect earlier and more sharply. Leave it empty for an uncapped link.",
  },
  delay_ms: {
    label: "Delay · ms",
    hint: "Extra one-way latency added to this link. Raise it to imitate a distant or busy path, which makes every request slower; 0 keeps the link instant.",
  },
  loss_percent: {
    label: "Loss · %",
    hint: "Share of packets this link drops at random. Even 1–2% noticeably slows TCP because of retransmissions; 0 is a clean link.",
  },
} as const;

function counted(total: number | undefined, one: string, many: string) {
  return total ? `${total} ${total === 1 ? one : many}` : "";
}

export function InspectorPanel({
  topology,
  shownTopology,
  setTopology,
  selection,
  select,
  problems,
  controllerSample,
  locked,
  status,
  replay,
  busy,
  task,
  setTab,
  setNotice,
  removeSelected,
}: {
  topology: Topology | null;
  shownTopology: Topology | null;
  setTopology: (value: Topology) => void;
  selection: string[];
  select: (ids: string[]) => void;
  problems: string[];
  controllerSample?: Record<string, unknown>;
  locked: boolean;
  status: Status;
  replay: boolean;
  busy: boolean;
  task: Task;
  setTab: (tab: string) => void;
  setNotice: (notice: Notice | null) => void;
  removeSelected: () => void;
}) {
  const selected = selection.length === 1 ? selection[0] : "";
  const controller = selected === CONTROLLER_ID;
  const host = shownTopology?.hosts.find((h) => h.name === selected);
  const deviceSwitch = shownTopology?.switches.find((s) => s.name === selected);
  const link = shownTopology?.links.find((l) => l.id === selected);
  const many = selection.length > 1;
  const chosenHosts = shownTopology?.hosts.filter((h) =>
    selection.includes(h.name),
  );
  const chosenSwitches = shownTopology?.switches.filter((s) =>
    selection.includes(s.name),
  );
  const chosenLinks = shownTopology?.links.filter((l) =>
    selection.includes(l.id),
  );
  const [capture, setCapture] = useState({
    protocol: "all",
    duration: 20,
    packets: 500,
  });
  const [bulk, setBulk] = useState({ bandwidth: "", delay: "", loss: "" });

  function applyToLinks() {
    if (!topology || !chosenLinks?.length) return;
    const patch: Partial<Link> = {};
    if (bulk.bandwidth.trim())
      patch.bandwidth_mbps =
        bulk.bandwidth.trim().toLowerCase() === "none"
          ? null
          : Number(bulk.bandwidth);
    if (bulk.delay.trim()) patch.delay_ms = Number(bulk.delay);
    if (bulk.loss.trim()) patch.loss_percent = Number(bulk.loss);
    if (!Object.keys(patch).length) {
      setNotice({
        tone: "info",
        title: "Nothing to apply yet.",
        detail:
          "Fill in at least one of bandwidth, delay, or loss. Empty fields leave that setting untouched on every selected link.",
      });
      return;
    }
    setTopology({
      ...topology,
      links: topology.links.map((item) =>
        selection.includes(item.id) ? { ...item, ...patch } : item,
      ),
    });
    setBulk({ bandwidth: "", delay: "", loss: "" });
    setNotice({
      tone: "success",
      title: `Updated ${chosenLinks.length} links.`,
      detail: "The change applies the next time the lab starts.",
    });
  }

  return (
    <div className="panel-content">
      <span className="eyebrow">
        SELECTION /{" "}
        {many
          ? `${selection.length} ITEMS`
          : controller
            ? "CONTROLLER"
            : host
              ? "HOST"
              : deviceSwitch
                ? "SWITCH"
                : link
                  ? "LINK"
                  : "NETWORK"}
      </span>
      <h2>
        {many
          ? `${selection.length} selected`
          : controller
            ? "c0"
            : selected || "Your topology"}
      </h2>

      {controller && (
        <>
          <p>
            The lab runs one Ryu controller for the whole network. Every switch
            opens an OpenFlow 1.3 session to it on 127.0.0.1:6653 — those are
            the dashed lines on the canvas.
          </p>
          <dl className="readout">
            <div>
              <dt>Controller</dt>
              <dd>Ryu · OpenFlow 1.3</dd>
            </div>
            <div>
              <dt>Listening on</dt>
              <dd>127.0.0.1:6653</dd>
            </div>
            <div>
              <dt>Switches attached</dt>
              <dd>{shownTopology?.switches.length ?? 0}</dd>
            </div>
            <div>
              <dt>CPU · memory</dt>
              <dd>
                {controllerSample
                  ? `${Number(controllerSample.cpu_percent).toFixed(1)}% · ${(
                      Number(controllerSample.rss_bytes) / 1048576
                    ).toFixed(1)} MiB`
                  : "no sample yet"}
              </dd>
            </div>
          </dl>
          <p className="footnote">
            The controller is created and removed with the lab, so there is
            nothing to configure here. Dashed control links carry OpenFlow
            messages, not the traffic you measure, and they are never counted in
            the link totals or written to an exported file.
          </p>
        </>
      )}

      {many && (
        <>
          <p>
            {[
              counted(chosenHosts?.length, "host", "hosts"),
              counted(chosenSwitches?.length, "switch", "switches"),
              counted(chosenLinks?.length, "link", "links"),
            ]
              .filter(Boolean)
              .join(" · ")}
          </p>
          <div className="chips">
            {selection.map((id) => (
              <button
                key={id}
                className="chip"
                title={`Show only ${id}`}
                onClick={() => select([id])}
              >
                {id}
              </button>
            ))}
          </div>
          <button onClick={() => select([])}>Clear selection</button>
          {!!chosenLinks?.length && (
            <>
              <hr />
              <h3>Apply to {chosenLinks.length} selected links</h3>
              <p className="footnote">
                Leave a box empty to keep that setting as it is on each link.
              </p>
              <fieldset disabled={locked}>
                <Field
                  label={linkFields.bandwidth_mbps.label}
                  hint={`${linkFields.bandwidth_mbps.hint} Type “none” to remove the cap from every selected link.`}
                >
                  <input
                    value={bulk.bandwidth}
                    placeholder="unchanged"
                    onChange={(e) =>
                      setBulk({ ...bulk, bandwidth: e.target.value })
                    }
                  />
                </Field>
                <div className="field-pair">
                  <Field
                    label={linkFields.delay_ms.label}
                    hint={linkFields.delay_ms.hint}
                  >
                    <input
                      type="number"
                      min={0}
                      max={1000}
                      value={bulk.delay}
                      placeholder="unchanged"
                      onChange={(e) =>
                        setBulk({ ...bulk, delay: e.target.value })
                      }
                    />
                  </Field>
                  <Field
                    label={linkFields.loss_percent.label}
                    hint={linkFields.loss_percent.hint}
                  >
                    <input
                      type="number"
                      min={0}
                      max={100}
                      value={bulk.loss}
                      placeholder="unchanged"
                      onChange={(e) =>
                        setBulk({ ...bulk, loss: e.target.value })
                      }
                    />
                  </Field>
                </div>
                <button className="full" onClick={applyToLinks}>
                  Apply to {chosenLinks.length} links
                </button>
              </fieldset>
            </>
          )}
        </>
      )}

      {!many && !selected && topology && (
        <>
          <p>{shownTopology?.description}</p>
          <Field
            label="Project name"
            hint="The name saved with this topology and shown on every run it produces. Use something you will recognise in the history list."
          >
            <input
              disabled={locked}
              value={topology.name}
              maxLength={80}
              onChange={(e) =>
                setTopology({ ...topology, name: e.target.value })
              }
            />
          </Field>
          {problems.length > 0 && (
            <div className="problem-list">
              <strong>
                {problems.length === 1
                  ? "One thing to fix before this network can run"
                  : `${problems.length} things to fix before this network can run`}
              </strong>
              <ul>
                {problems.map((problem) => (
                  <li key={problem}>{problem}</li>
                ))}
              </ul>
            </div>
          )}
          <button
            disabled={locked}
            onClick={() =>
              void task(async () => {
                await api("/validate", topology);
                setNotice({
                  tone: "success",
                  title: "This topology is ready to run.",
                  detail:
                    "Every device is connected, names and addresses are unique, and all hosts sit inside the networks this lab may touch.",
                });
              })
            }
          >
            Validate topology
          </button>
          <button
            disabled={locked}
            onClick={() =>
              void task(async () => {
                await api("/projects", topology);
                setNotice({
                  tone: "success",
                  title: "Saved a topology snapshot.",
                  detail: "Find it again under History › Saved topologies.",
                });
              })
            }
          >
            Save project
          </button>
          <p>
            One managed Ryu controller. Loop-free switching only. No external
            interfaces or startup scripts.
          </p>
        </>
      )}

      {!many && host && topology && (
        <>
          <Field
            label="IPv4 address / prefix"
            hint="This host's address inside the lab. It must be private (10.x, 172.16–31.x or 192.168.x) and unique. The /24 suffix sets the subnet: two hosts can only talk to each other when they share one, because this lab has no router."
          >
            <input
              disabled={locked}
              value={host.ip}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  hosts: topology.hosts.map((h) =>
                    h.name === host.name ? { ...h, ip: e.target.value } : h,
                  ),
                })
              }
            />
          </Field>
          <p>One network interface. Host names are fixed when created.</p>
          <button
            disabled={status.state !== "running" || !!replay || busy}
            onClick={() =>
              void task(async () => {
                await api("/diagnostic", {
                  action: "interfaces",
                  node: host.name,
                });
                setTab("Commands");
              })
            }
          >
            Show interfaces
          </button>
          <Field
            label="Ping another host"
            hint="Sends three ICMP echo requests from this host and prints the replies under Commands. It is the quickest way to prove two hosts can actually reach each other."
          >
            <select id="ping-target" defaultValue="">
              <option value="">Choose host…</option>
              {shownTopology?.hosts
                .filter((h) => h.name !== host.name)
                .map((h) => (
                  <option key={h.name}>{h.name}</option>
                ))}
            </select>
          </Field>
          <button
            disabled={status.state !== "running" || !!replay || busy}
            onClick={() =>
              void task(async () => {
                await api("/diagnostic", {
                  action: "ping",
                  node: host.name,
                  target: (
                    document.getElementById("ping-target") as HTMLSelectElement
                  ).value,
                });
                setTab("Commands");
              })
            }
          >
            Send 3 pings
          </button>
        </>
      )}

      {!many && deviceSwitch && topology && (
        <>
          <Field
            label="Datapath ID"
            hint="The number that identifies this switch to the Ryu controller. Any unique whole number works; you will see it again in controller logs and flow tables, so keep it memorable."
          >
            <input
              type="number"
              min={1}
              max={Number.MAX_SAFE_INTEGER}
              disabled={locked}
              value={deviceSwitch.dpid}
              onChange={(e) =>
                setTopology({
                  ...topology,
                  switches: topology.switches.map((s) =>
                    s.name === deviceSwitch.name
                      ? { ...s, dpid: Number(e.target.value) }
                      : s,
                  ),
                })
              }
            />
          </Field>
          <p>
            Open vSwitch / OpenFlow 1.3
            <br />
            Managed Ryu controller on port 6653
          </p>
          <button
            disabled={status.state !== "running" || !!replay || busy}
            onClick={() =>
              void task(async () => {
                await api("/diagnostic", {
                  action: "flows",
                  node: deviceSwitch.name,
                });
                setTab("Commands");
              })
            }
          >
            Show switch flow table
          </button>
        </>
      )}

      {!many && link && topology && (
        <>
          <p>
            {link.source} ↔ {link.target}
          </p>
          {(["bandwidth_mbps", "delay_ms", "loss_percent"] as const).map(
            (key) => (
              <Field
                key={key}
                label={
                  key === "bandwidth_mbps"
                    ? "Bandwidth · Mb/s (empty = no cap)"
                    : linkFields[key].label
                }
                hint={linkFields[key].hint}
              >
                <input
                  type="number"
                  min={0}
                  disabled={locked}
                  value={link[key] ?? ""}
                  onChange={(e) =>
                    setTopology({
                      ...topology,
                      links: topology.links.map((l) =>
                        l.id === link.id
                          ? {
                              ...l,
                              [key]:
                                key === "bandwidth_mbps" && !e.target.value
                                  ? null
                                  : Number(e.target.value),
                            }
                          : l,
                      ),
                    })
                  }
                />
              </Field>
            ),
          )}
          <hr />
          <h3>Packet headers</h3>
          <Field
            label="Protocol"
            hint="Limits the capture to one kind of traffic. Choose tcp to watch the SYN flood itself, icmp to follow pings, or all to see everything crossing this link."
          >
            <select
              value={capture.protocol}
              onChange={(e) =>
                setCapture({ ...capture, protocol: e.target.value })
              }
            >
              {["all", "tcp", "udp", "icmp", "arp"].map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </Field>
          <div className="field-pair">
            <Field
              label="Seconds"
              hint="How long the capture listens. Longer catches more of a slow conversation; shorter finishes quickly and keeps the table readable. Allowed: 1 to 60."
            >
              <input
                type="number"
                min={1}
                max={60}
                value={capture.duration}
                onChange={(e) =>
                  setCapture({
                    ...capture,
                    duration: Number(e.target.value),
                  })
                }
              />
            </Field>
            <Field
              label="Packet limit"
              hint="Stops the capture once this many packets are stored, even if time remains. A low limit keeps a flood from burying the interesting first packets. Allowed: 1 to 2000."
            >
              <input
                type="number"
                min={1}
                max={2000}
                value={capture.packets}
                onChange={(e) =>
                  setCapture({
                    ...capture,
                    packets: Number(e.target.value),
                  })
                }
              />
            </Field>
          </div>
          <button
            disabled={
              !["running", "baseline", "attack", "recovery"].includes(
                status.state,
              ) ||
              !!replay ||
              busy
            }
            onClick={() =>
              void task(async () => {
                await api("/capture", { link_id: link.id, ...capture });
                setTab("Packets");
              })
            }
          >
            Capture headers
          </button>
          <p className="footnote">
            Switch-side capture, 256-byte snap length. Only listed header fields
            are stored. The live view shows the last 500 packets.
          </p>
        </>
      )}

      {selection.length > 0 && !controller && (
        <button className="delete" disabled={locked} onClick={removeSelected}>
          {many
            ? `Remove ${selection.length} selected items`
            : `Remove ${host || deviceSwitch ? "device and its links" : "link"}`}
        </button>
      )}
    </div>
  );
}
