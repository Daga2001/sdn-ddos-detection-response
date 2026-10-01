import { useMemo, useRef } from "react";
import {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  ConnectionMode,
} from "@xyflow/react";
import type { Connection, Node, NodeProps } from "@xyflow/react";

type FlowNode = Node<Record<string, unknown>>;
import type { Topology, Observation } from "./types";
import { formatRate, CONTROLLER_ID } from "./types";
import { DeviceIcon } from "./Icons";
import "@xyflow/react/dist/style.css";

const roleLabels: Record<string, string> = {
  source: "attacker",
  victim: "victim",
  client: "client",
};

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
      <span className="device-icon">
        <DeviceIcon kind={data.kind} role={data.role} />
      </span>
      <strong>{data.label}</strong>
      <small>{data.detail}</small>
      {data.role && <em>{roleLabels[data.role] ?? data.role}</em>}
      <Handle type="target" position={Position.Top} />
    </div>
  );
}
const nodeTypes = { device: Device };

/**
 * React Flow keeps a node's handle bounds only while the object it was handed
 * stays referentially identical: `adoptUserNodes` compares `userNode ===
 * internals.userNode`, and otherwise recomputes the bounds from a `measured`
 * size it may not have yet. Nodes here are derived from the topology on every
 * render, so an unchanged node is handed back as the very same object. Without
 * this, a render arriving between React Flow's measurement and ours left nodes
 * with no handle bounds, and React Flow draws no edge at all between those.
 */
function reuseUnchanged<T extends { id: string }>(
  built: T[],
  cache: { current: Map<string, { signature: string; node: T }> },
): T[] {
  const previous = cache.current;
  const next = new Map<string, { signature: string; node: T }>();
  const stable = built.map((node) => {
    const signature = JSON.stringify(node);
    const seen = previous.get(node.id);
    const kept = seen && seen.signature === signature ? seen.node : node;
    next.set(node.id, { signature, node: kept });
    return kept;
  });
  cache.current = next;
  return stable;
}

export function TopologyCanvas({
  topology,
  onChange,
  selection,
  select,
  locked,
  events,
  roles,
  mode,
  remove,
}: {
  topology: Topology;
  onChange: (value: Topology) => void;
  selection: string[];
  select: (ids: string[]) => void;
  locked: boolean;
  events: Observation[];
  roles: Record<string, string>;
  mode: "select" | "pan";
  remove: (ids: string[]) => void;
}) {
  /**
   * React Flow clears a node's handle bounds whenever the node object it is
   * handed has no `measured`, and only recomputes them when that element
   * resizes. Nodes here are rebuilt on every render, so a render landing
   * between React Flow's measurement and ours used to strip every edge from
   * the canvas for good. Sizes are therefore recorded synchronously and handed
   * straight back, with no state round-trip to race against.
   */
  const measured = useRef<Record<string, { width: number; height: number }>>(
    {},
  );
  const adopted = useRef(
    new Map<string, { signature: string; node: FlowNode }>(),
  );
  const latest = events.findLast((e) => e.kind === "links");
  const rates = Object.fromEntries(
    (latest?.data.links ?? []).map((row: any) => [row.link_id, row.rates]),
  );
  const chosen = useMemo(() => new Set(selection), [selection]);
  // The managed controller is drawn, never stored: it belongs to the lab, not
  // to the topology the user edits, exports, or validates.
  const controller = useMemo(() => {
    const xs = topology.switches.map((s) => s.position.x);
    const ys = topology.switches.map((s) => s.position.y);
    return {
      id: CONTROLLER_ID,
      type: "device",
      measured: measured.current[CONTROLLER_ID],
      draggable: false,
      deletable: false,
      position: {
        x: xs.length ? Math.round((Math.min(...xs) + Math.max(...xs)) / 2) : 0,
        y: (ys.length ? Math.min(...ys) : 0) - 135,
      },
      selected: chosen.has(CONTROLLER_ID),
      data: {
        label: "c0",
        detail: "Ryu · 6653",
        kind: "controller",
        role: "managed",
      },
    };
  }, [topology.switches, chosen]);
  const nodes = useMemo(
    () =>
      reuseUnchanged(
        [
          controller,
          ...topology.switches.map((s) => ({
            id: s.name,
            position: s.position,
            measured: measured.current[s.name],
            type: "device",
            selected: chosen.has(s.name),
            data: {
              label: s.name,
              detail: `DPID ${s.dpid}`,
              kind: "switch",
              role: "",
            },
          })),
          ...topology.hosts.map((h) => ({
            id: h.name,
            position: h.position,
            measured: measured.current[h.name],
            type: "device",
            selected: chosen.has(h.name),
            data: {
              label: h.name,
              detail: h.ip,
              kind: "host",
              role: roles[h.name] ?? "",
            },
          })),
        ] as FlowNode[],
        adopted,
      ),
    [topology, chosen, roles, controller],
  );
  // Dashed control plane: every switch answers to the one managed controller.
  const controlEdges = topology.switches.map((s) => ({
    id: `__control-${s.name}`,
    source: CONTROLLER_ID,
    target: s.name,
    selectable: false,
    deletable: false,
    focusable: false,
    className: "control-edge",
    style: { stroke: "#93a79e", strokeWidth: 1.1, strokeDasharray: "5 4" },
  }));
  const edges = topology.links.map((link) => {
    const rate = rates[link.id];
    const total = rate ? rate.rx_bps + rate.tx_bps : 0;
    return {
      id: link.id,
      source: link.source,
      target: link.target,
      selected: chosen.has(link.id),
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
  /** React Flow reports selection as changes; the workspace owns the result. */
  function applySelection(
    changes: { type: string; id?: string; selected?: boolean }[],
  ) {
    const picks = changes.filter((change) => change.type === "select");
    if (!picks.length) return false;
    const next = new Set(selection);
    for (const pick of picks) {
      if (!pick.id) continue;
      if (pick.selected) next.add(pick.id);
      else next.delete(pick.id);
    }
    if (next.size !== selection.length || selection.some((id) => !next.has(id)))
      select([...next]);
    return true;
  }
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
      edges={[...controlEdges, ...edges]}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.22 }}
      minZoom={0.25}
      maxZoom={2}
      connectionMode={ConnectionMode.Loose}
      onConnect={connect}
      nodesDraggable={!locked}
      selectionOnDrag={mode === "select"}
      panOnDrag={mode === "select" ? [1, 2] : true}
      selectionKeyCode="Shift"
      multiSelectionKeyCode={["Shift", "Meta", "Control"]}
      onNodesChange={(changes) => {
        for (const change of changes)
          if (change.type === "dimensions" && change.dimensions)
            measured.current[change.id] = change.dimensions;
        applySelection(changes);
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
      onEdgesChange={applySelection}
      nodesConnectable={!locked}
      deleteKeyCode={locked ? null : "Delete"}
      onNodesDelete={(deleted) => remove(deleted.map((node) => node.id))}
      onEdgesDelete={(deleted) => remove(deleted.map((edge) => edge.id))}
      onPaneClick={() => select([])}
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
