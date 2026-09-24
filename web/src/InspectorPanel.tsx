import { useState } from "react";
import { api } from "./types";
import type { Topology, Status, Task } from "./types";

export function InspectorPanel({
  topology,
  shownTopology,
  setTopology,
  selected,
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
  selected: string;
  locked: boolean;
  status: Status;
  replay: boolean;
  busy: boolean;
  task: Task;
  setTab: (tab: string) => void;
  setNotice: (message: string) => void;
  removeSelected: () => void;
}) {
  const host = shownTopology?.hosts.find((h) => h.name === selected);
  const deviceSwitch = shownTopology?.switches.find((s) => s.name === selected);
  const link = shownTopology?.links.find((l) => l.id === selected);
  const [capture, setCapture] = useState({
    protocol: "all",
    duration: 20,
    packets: 500,
  });
  return (
    <div className="panel-content">
      <span className="eyebrow">
        SELECTION /{" "}
        {host ? "HOST" : deviceSwitch ? "SWITCH" : link ? "LINK" : "NETWORK"}
      </span>
      <h2>{selected || "Your topology"}</h2>
      {!selected && topology && (
        <>
          <p>{shownTopology?.description}</p>
          <label>
            Project name
            <input
              disabled={locked}
              value={topology.name}
              maxLength={80}
              onChange={(e) =>
                setTopology({ ...topology, name: e.target.value })
              }
            />
          </label>
          <button
            disabled={locked}
            onClick={() =>
              void task(async () => {
                await api("/validate", topology);
                setNotice(
                  "Topology is valid and stays inside the configured lab networks.",
                );
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
                setNotice("Saved a topology snapshot.");
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
      {host && topology && (
        <>
          <label>
            IPv4 address / prefix
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
          </label>
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
          <label>
            Ping another host
            <select id="ping-target" defaultValue="">
              <option value="">Choose host…</option>
              {shownTopology?.hosts
                .filter((h) => h.name !== host.name)
                .map((h) => (
                  <option key={h.name}>{h.name}</option>
                ))}
            </select>
          </label>
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
      {deviceSwitch && topology && (
        <>
          <label>
            Datapath ID
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
          </label>
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
      {link && topology && (
        <>
          <p>
            {link.source} ↔ {link.target}
          </p>
          {(["bandwidth_mbps", "delay_ms", "loss_percent"] as const).map(
            (key) => (
              <label key={key}>
                {
                  {
                    bandwidth_mbps: "Bandwidth · Mb/s (empty = no cap)",
                    delay_ms: "Delay · ms",
                    loss_percent: "Loss · %",
                  }[key]
                }
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
              </label>
            ),
          )}
          <hr />
          <h3>Packet headers</h3>
          <label>
            Protocol
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
          </label>
          <div className="field-pair">
            <label>
              Seconds
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
            </label>
            <label>
              Packet limit
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
            </label>
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
      {selected && (
        <button className="delete" disabled={locked} onClick={removeSelected}>
          Remove {host || deviceSwitch ? "device and its links" : "link"}
        </button>
      )}
    </div>
  );
}
