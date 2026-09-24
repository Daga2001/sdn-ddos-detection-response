import { useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  ConnectionMode,
} from "@xyflow/react";
import type { Connection, Node, NodeProps } from "@xyflow/react";
import type { Topology, Observation } from "./types";
import { formatRate } from "./types";
import "@xyflow/react/dist/style.css";

function Device({
  data,
  selected,
}: NodeProps<
  Node<{ label: string; detail: string; kind: string; role: string }>
>) {
  return (
    <div
      className={`device ${data.kind} ${selected ? "selected" : ""} ${data.role}`}
    >
      <Handle type="source" position={Position.Bottom} />
      <span className="device-symbol">
        {data.kind === "switch" ? "⇄" : "▣"}
      </span>
      <div>
        <strong>{data.label}</strong>
        <small>{data.detail}</small>
      </div>
      {data.role && <em>{data.role}</em>}
      <Handle type="target" position={Position.Top} />
    </div>
  );
}
const nodeTypes = { device: Device };

export function TopologyCanvas({
  topology,
  onChange,
  selected,
  select,
  locked,
  events,
  roles,
}: {
  topology: Topology;
  onChange: (value: Topology) => void;
  selected: string;
  select: (id: string) => void;
  locked: boolean;
  events: Observation[];
  roles: Record<string, string>;
}) {
  const [dimensions, setDimensions] = useState<
    Record<string, { width: number; height: number }>
  >({});
  const latest = events.findLast((e) => e.kind === "links");
  const rates = Object.fromEntries(
    (latest?.data.links ?? []).map((row: any) => [row.link_id, row.rates]),
  );
  const nodes = useMemo(
    () => [
      ...topology.switches.map((s) => ({
        id: s.name,
        position: s.position,
        measured: dimensions[s.name],
        type: "device",
        selected: selected === s.name,
        data: {
          label: s.name,
          detail: `OF 1.3 · DPID ${s.dpid}`,
          kind: "switch",
          role: "",
        },
      })),
      ...topology.hosts.map((h) => ({
        id: h.name,
        position: h.position,
        measured: dimensions[h.name],
        type: "device",
        selected: selected === h.name,
        data: {
          label: h.name,
          detail: h.ip,
          kind: "host",
          role: roles[h.name] ?? "",
        },
      })),
    ],
    [topology, selected, roles, dimensions],
  );
  const edges = topology.links.map((link) => {
    const rate = rates[link.id];
    const total = rate ? rate.rx_bps + rate.tx_bps : 0;
    return {
      id: link.id,
      source: link.source,
      target: link.target,
      selected: selected === link.id,
      label: rate ? formatRate(total) : undefined,
      animated: total > 0,
      style: {
        stroke: total > 1000000 ? "#ce643f" : "#4b8585",
        strokeWidth: total
          ? Math.min(7, 1 + Math.log10(1 + total / 1000))
          : 1.5,
      },
      labelStyle: { fontSize: 10, fill: "#305759" },
      labelBgStyle: { fill: "#f4f6ef" },
    };
  });
  function connect(connection: Connection) {
    if (locked || !connection.source || !connection.target) return;
    onChange({
      ...topology,
      links: [
        ...topology.links,
        {
          id: `link-${crypto.randomUUID().slice(0, 8)}`,
          source: connection.source,
          target: connection.target,
          bandwidth_mbps: null,
          delay_ms: 0,
          loss_percent: 0,
        },
      ],
    });
  }
  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.22 }}
      minZoom={0.25}
      maxZoom={2}
      connectionMode={ConnectionMode.Loose}
      onConnect={connect}
      nodesDraggable={!locked}
      onNodesChange={(changes) => {
        const measured = changes.flatMap((change) =>
          change.type === "dimensions" && change.dimensions
            ? [[change.id, change.dimensions] as const]
            : [],
        );
        if (measured.length)
          setDimensions((current) => ({
            ...current,
            ...Object.fromEntries(measured),
          }));
        if (locked) return;
        const positions = new Map(
          changes.flatMap((change) =>
            change.type === "position" && change.position
              ? [[change.id, change.position] as const]
              : [],
          ),
        );
        if (positions.size)
          onChange({
            ...topology,
            hosts: topology.hosts.map((h) =>
              positions.has(h.name)
                ? { ...h, position: positions.get(h.name)! }
                : h,
            ),
            switches: topology.switches.map((s) =>
              positions.has(s.name)
                ? { ...s, position: positions.get(s.name)! }
                : s,
            ),
          });
      }}
      nodesConnectable={!locked}
      deleteKeyCode={null}
      onNodeClick={(_, node) => select(node.id)}
      onEdgeClick={(_, edge) => select(edge.id)}
      onPaneClick={() => select("")}
      onNodeDragStop={(_, node) =>
        onChange({
          ...topology,
          hosts: topology.hosts.map((h) =>
            h.name === node.id ? { ...h, position: node.position } : h,
          ),
          switches: topology.switches.map((s) =>
            s.name === node.id ? { ...s, position: node.position } : s,
          ),
        })
      }
    >
      <Background color="#bcc8bd" gap={24} size={1} />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}
