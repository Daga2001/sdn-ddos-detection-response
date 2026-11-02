import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { LineChart, ScatterChart } from "echarts/charts";
import {
  GridComponent,
  LegendComponent,
  MarkLineComponent,
  TooltipComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import {
  answeredShare,
  checkSeries,
  controllerSeries,
  cpuSeries,
  panelHints,
  phaseTable,
  pingSeries,
  trafficMarkers,
  trafficSeries,
} from "./traffic.ts";
import type { Experiment, Observation, PhaseSpan, Topology } from "./types.ts";

echarts.use([
  LineChart,
  ScatterChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  MarkLineComponent,
  CanvasRenderer,
]);

const GROUP = "traffic-panels";
const bandColor: Record<string, string> = {
  baseline: "rgba(8, 126, 131, 0.06)",
  attack: "rgba(193, 107, 65, 0.12)",
  recovery: "rgba(90, 120, 150, 0.08)",
};

function bands(spans: PhaseSpan[]) {
  return {
    silent: true,
    data: spans.map((span) => [
      {
        xAxis: span.start,
        itemStyle: { color: bandColor[span.state] ?? "transparent" },
      },
      { xAxis: span.end },
    ]),
  };
}

function marks(markers: { t: number; label: string }[]) {
  return {
    silent: true,
    symbol: "none",
    label: { show: true, formatter: "{b}", fontSize: 10, color: "#5b6b60" },
    lineStyle: { color: "#8a6a4a", type: "dashed" as const },
    data: markers.map((marker) => ({ xAxis: marker.t, name: marker.label })),
  };
}

function Panel({
  title,
  hint,
  note,
  option,
}: {
  title: string;
  hint: string;
  note: string | null;
  option: echarts.EChartsCoreOption | null;
}) {
  const element = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.EChartsType | null>(null);
  useEffect(() => {
    if (!element.current || !option) return;
    const instance = echarts.init(element.current);
    instance.group = GROUP;
    chart.current = instance;
    echarts.connect(GROUP);
    const observer = new ResizeObserver(() => instance.resize());
    observer.observe(element.current);
    return () => {
      observer.disconnect();
      instance.dispose();
    };
  }, [option]);
  useEffect(() => {
    if (option) chart.current?.setOption(option, true);
  }, [option]);
  return (
    <section className="traffic-panel" title={hint}>
      <h3>{title}</h3>
      {note ? (
        <p className="panel-note">{note}</p>
      ) : (
        <div className="traffic-chart" ref={element} aria-label={title} />
      )}
    </section>
  );
}

export function TrafficView({
  events,
  spans,
  topology,
  experiment,
}: {
  events: Observation[];
  spans: PhaseSpan[];
  topology: Topology | null;
  experiment: Experiment | null;
}) {
  const runEnd = events.length
    ? Date.parse(events[events.length - 1].ts)
    : Date.now();
  const traffic = trafficSeries(events, topology, experiment);
  const checks = checkSeries(events);
  const share = answeredShare(checks);
  const pings = pingSeries(events);
  const controller = controllerSeries(events);
  const cpu = cpuSeries(events);
  const markers = trafficMarkers(events, topology, experiment, runEnd);
  const table = phaseTable(events, topology, experiment, runEnd);
  const start = events.length ? Date.parse(events[0].ts) : runEnd;
  const axis = { type: "time" as const, min: start, max: runEnd };
  const failed = checks.filter((check) => !check.answered);
  const top = Math.max(1, ...checks.map((check) => check.total ?? 0));

  const trafficOption: echarts.EChartsCoreOption | null = traffic.points.some(
    (point) =>
      point.attackers !== null ||
      point.victim !== null ||
      point.clients !== null ||
      point.all !== null,
  )
    ? {
        animation: false,
        tooltip: {
          trigger: "axis",
          formatter: (params: unknown) => {
            const rows = Array.isArray(params) ? params : [params];
            return rows
              .map((row) => {
                const data = (row as { data?: unknown[] }).data ?? [];
                const kbps = data[2];
                const rate =
                  typeof kbps === "number" ? `${kbps.toFixed(1)} kb/s` : "—";
                return `${(row as { seriesName?: string }).seriesName ?? ""}: ${data[1] ?? "—"} packets/s (${rate})`;
              })
              .join("\n");
          },
        },
        legend: { textStyle: { fontSize: 11 } },
        grid: { left: 56, right: 24, top: 28, bottom: 24 },
        xAxis: axis,
        yAxis: { type: "value", name: "packets/s" },
        series: traffic.observation
          ? [
              {
                name: "sent by all hosts",
                type: "line",
                showSymbol: false,
                data: traffic.points.map((point) => [
                  point.t,
                  point.all,
                  point.allKbps,
                ]),
                markArea: bands(spans),
                markLine: marks(markers),
              },
            ]
          : [
              ["sent by attackers", "attackers", "attackersKbps"],
              ["delivered to victim", "victim", "victimKbps"],
              ["sent by normal clients", "clients", "clientsKbps"],
            ].map(([name, field, kbps], index) => ({
              name,
              type: "line",
              showSymbol: false,
              data: traffic.points.map((point) => [
                point.t,
                point[field as "attackers"],
                point[kbps as "attackersKbps"],
              ]),
              markArea: index === 0 ? bands(spans) : undefined,
              markLine: index === 0 ? marks(markers) : undefined,
            })),
      }
    : null;

  const checkOption: echarts.EChartsCoreOption | null = checks.length
    ? {
        animation: false,
        tooltip: { trigger: "axis" },
        legend: { textStyle: { fontSize: 11 } },
        grid: { left: 56, right: 48, top: 28, bottom: 24 },
        xAxis: axis,
        yAxis: [
          { type: "value", name: "ms" },
          {
            type: "value",
            name: "%",
            min: 0,
            max: 100,
            splitLine: { show: false },
          },
        ],
        series: [
          {
            name: "total time",
            type: "line",
            showSymbol: true,
            itemStyle: { color: "#2e7d4f" },
            data: checks.map((check) => [
              check.t,
              check.answered ? check.total : null,
            ]),
            markArea: bands(spans),
            markLine: marks(markers),
          },
          {
            name: "connection time",
            type: "line",
            showSymbol: true,
            data: checks.map((check) => [
              check.t,
              check.answered ? check.connect : null,
            ]),
          },
          {
            name: "failed check",
            type: "scatter",
            symbol: "none",
            data: failed.map((check) => [check.t, top]),
            label: {
              show: true,
              formatter: "✗",
              color: "#b23b2a",
              fontSize: 14,
            },
          },
          {
            name: "% of the last 10 checks answered",
            type: "line",
            yAxisIndex: 1,
            showSymbol: false,
            data: share.map((point) => [point.t, point.pct]),
          },
        ],
      }
    : null;

  const pingOption: echarts.EChartsCoreOption | null =
    pings.rtt.length || pings.lost.length
      ? {
          animation: false,
          tooltip: { trigger: "axis" },
          grid: { left: 56, right: 24, top: 28, bottom: 24 },
          xAxis: axis,
          yAxis: { type: "value", name: "ms" },
          series: [
            {
              name: "RTT",
              type: "line",
              showSymbol: true,
              data: pings.rtt.map((point) => [point.t, point.rtt]),
              markArea: bands(spans),
              markLine: marks(markers),
            },
            {
              name: "lost ping",
              type: "scatter",
              symbol: "none",
              data: pings.lost.map((point) => [point.t, 0]),
              label: { show: true, formatter: "✗", color: "#b23b2a" },
            },
          ],
        }
      : null;

  const controllerOption: echarts.EChartsCoreOption | null =
    controller.handled.length ||
    controller.sent.length ||
    controller.rules.length
      ? {
          animation: false,
          tooltip: { trigger: "axis" },
          legend: { textStyle: { fontSize: 11 } },
          grid: { left: 56, right: 48, top: 28, bottom: 24 },
          xAxis: axis,
          yAxis: [
            { type: "value", name: "Packet-Ins/s" },
            { type: "value", name: "rules", splitLine: { show: false } },
          ],
          series: [
            {
              name: "sent by switches",
              type: "line",
              data: controller.sent.map((point) => [point.t, point.rate]),
              markArea: bands(spans),
              markLine: marks(markers),
            },
            {
              name: "handled by Ryu",
              type: "line",
              data: controller.handled.map((point) => [point.t, point.rate]),
            },
            {
              name: "flow rules",
              type: "line",
              yAxisIndex: 1,
              data: controller.rules.map((point) => [point.t, point.count]),
            },
          ],
        }
      : null;

  const cpuOption: echarts.EChartsCoreOption | null =
    cpu.ryu.length || cpu.ovs.length || cpu.machine.length
      ? {
          animation: false,
          tooltip: {
            trigger: "axis",
            formatter: (params: any) => {
              const rows = Array.isArray(params) ? params : [params];
              const ram = cpu.ryu.find((point) =>
                rows.some((row) => row.axisValue === point.t),
              );
              const lines = rows.map(
                (row) =>
                  `${row.marker ?? ""}${row.seriesName}: ${row.data?.[1] ?? "—"}`,
              );
              if (ram?.ram != null)
                lines.push(`Ryu RAM: ${(ram.ram / 1048576).toFixed(1)} MiB`);
              return lines.join("\n");
            },
          },
          legend: { textStyle: { fontSize: 11 } },
          grid: { left: 56, right: 24, top: 28, bottom: 24 },
          xAxis: axis,
          yAxis: { type: "value", name: "%" },
          series: [
            {
              name: "Ryu",
              type: "line",
              data: cpu.ryu.map((point) => [point.t, point.cpu, point.ram]),
              markArea: bands(spans),
              markLine: marks(markers),
            },
            {
              name: "Open vSwitch",
              type: "line",
              data: cpu.ovs.map((point) => [point.t, point.cpu]),
            },
            {
              name: "whole machine",
              type: "line",
              data: cpu.machine.map((point) => [point.t, point.cpu]),
            },
          ],
        }
      : null;

  return (
    <div className="traffic-stack">
      <Panel
        title="Traffic (packets/s)"
        hint={panelHints.traffic}
        note={trafficOption ? null : "No packet counts recorded for this run."}
        option={trafficOption}
      />
      <Panel
        title="Website checks (ms)"
        hint={panelHints.checks}
        note={checkOption ? null : "No website checks recorded for this run."}
        option={checkOption}
      />
      <Panel
        title="Ping (ms)"
        hint={panelHints.ping}
        note={pingOption ? null : "No pings recorded for this run."}
        option={pingOption}
      />
      <Panel
        title="Controller"
        hint={panelHints.controller}
        note={
          controllerOption
            ? null
            : "No Packet-In or flow-rule samples recorded."
        }
        option={controllerOption}
      />
      <Panel
        title="CPU (%)"
        hint={panelHints.cpu}
        note={cpuOption ? null : "No CPU samples recorded for this run."}
        option={cpuOption}
      />
      {table && (
        <table className="detection-table" title={table.hint}>
          <caption>Phase summary</caption>
          <thead>
            <tr>
              <th>Measure</th>
              <th>baseline</th>
              <th>attack</th>
              <th>recovery</th>
              <th>attack vs baseline</th>
              <th>recovery vs baseline</th>
            </tr>
          </thead>
          <tbody>
            {table.rows.map((row) => (
              <tr key={row.label}>
                <td>{row.label}</td>
                <td>{row.baseline}</td>
                <td>{row.attack}</td>
                <td>{row.recovery}</td>
                <td>{row.attackVs}</td>
                <td>{row.recoveryVs}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {table && (
        <ul className="criteria">
          {table.below.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
