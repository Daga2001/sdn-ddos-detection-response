import { useEffect, useRef, useState } from "react";
import * as echarts from "echarts/core";
import { LineChart } from "echarts/charts";
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { Observation } from "./types";
import { packets } from "./types";
echarts.use([
  LineChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  CanvasRenderer,
]);

function Chart({ events }: { events: Observation[] }) {
  const element = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.EChartsType | null>(null);
  useEffect(() => {
    if (!element.current) return;
    chart.current = echarts.init(element.current);
    const observer = new ResizeObserver(() => chart.current?.resize());
    observer.observe(element.current);
    return () => {
      observer.disconnect();
      chart.current?.dispose();
    };
  }, []);
  useEffect(() => {
    const traffic = events.filter((e) => e.kind === "links").slice(-300);
    const service = events.filter((e) => e.kind === "service").slice(-300);
    chart.current?.setOption({
      animation: false,
      color: ["#087e83", "#c16b41"],
      grid: { left: 60, right: 62, top: 40, bottom: 30 },
      legend: {
        data: ["Summed link traffic (kb/s)", "Service latency (ms)"],
        textStyle: { fontSize: 11 },
      },
      tooltip: { trigger: "axis", renderMode: "richText" },
      xAxis: { type: "time" },
      yAxis: [
        {
          type: "value",
          name: "kb/s",
          splitLine: { lineStyle: { color: "#e4e7df" } },
        },
        { type: "value", name: "ms", splitLine: { show: false } },
      ],
      series: [
        {
          name: "Summed link traffic (kb/s)",
          type: "line",
          showSymbol: false,
          areaStyle: { opacity: 0.09 },
          data: traffic.map((e) => [
            Date.parse(e.ts),
            e.data.links.reduce(
              (sum: number, row: any) =>
                sum + (row.rates ? row.rates.rx_bps + row.rates.tx_bps : 0),
              0,
            ) / 1000,
          ]),
        },
        {
          name: "Service latency (ms)",
          type: "line",
          yAxisIndex: 1,
          showSymbol: true,
          connectNulls: false,
          data: service.map((e) => [
            Date.parse(e.ts),
            e.data.success ? e.data.latency_ms : null,
          ]),
        },
      ],
    });
  }, [events]);
  return (
    <div
      className="traffic-chart"
      ref={element}
      aria-label="Measured traffic and service latency chart"
    />
  );
}

export function Observations({
  events,
  tab,
  setTab,
}: {
  events: Observation[];
  tab: string;
  setTab: (value: string) => void;
}) {
  const [expanded, setExpanded] = useState(-1);
  const packetRows = packets(events);
  const controller = events.findLast((e) => e.kind === "controller")?.data;
  const meaningful = events.filter(
    (e) =>
      ![
        "links",
        "flows",
        "controller",
        "packet",
        "packets",
        "command_output",
      ].includes(e.kind),
  );
  const commands = events.filter((e) =>
    [
      "command",
      "command_output",
      "command_exit",
      "output_truncated",
      "capture_message",
    ].includes(e.kind),
  );
  return (
    <section className="observations">
      <div className="controller-readout">
        Controller CPU{" "}
        {controller ? `${Number(controller.cpu_percent).toFixed(1)}%` : "—"}{" "}
        <span> / </span> RAM{" "}
        {controller
          ? `${(Number(controller.rss_bytes) / 1048576).toFixed(1)} MiB`
          : "—"}{" "}
        · latest recorded sample
      </div>
      <nav className="tabs" aria-label="Observations">
        {["Traffic", "Packets", "Commands", "Timeline", "Flows"].map(
          (value) => (
            <button
              key={value}
              className={tab === value ? "active" : ""}
              onClick={() => setTab(value)}
            >
              {value}
              {value === "Packets" && packetRows.length > 0
                ? ` · ${packetRows.length}`
                : ""}
            </button>
          ),
        )}
        <span>Measured evidence · UTC</span>
      </nav>
      <div className="observation-body">
        {tab === "Traffic" &&
          (events.some((e) => e.kind === "links") ? (
            <>
              <Chart events={events} />
              <p className="footnote">
                Traffic is summed across measured links, not unique end-to-end
                throughput. A missing latency point means the service probe
                failed.
              </p>
            </>
          ) : (
            <div className="empty">
              <span>↗</span>
              <strong>Your network, made visible.</strong>
              <p>
                Start an observation or an experiment to see measured traffic
                here.
              </p>
            </div>
          ))}
        {tab === "Packets" &&
          (packetRows.length ? (
            <table>
              <thead>
                <tr>
                  <th>Link</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Bytes</th>
                </tr>
              </thead>
              <tbody>
                {packetRows.map((p, i) => (
                  <tr key={i}>
                    <td colSpan={5}>
                      <button
                        className="packet-row"
                        aria-expanded={expanded === i}
                        onClick={() => setExpanded(expanded === i ? -1 : i)}
                      >
                        <span>{p.link_id}</span>
                        <span>
                          {p.headers["ip.src"] || p.headers["eth.src"]}
                        </span>
                        <span>
                          {p.headers["ip.dst"] || p.headers["eth.dst"]}
                        </span>
                        <span>
                          {p.headers["tcp.srcport"]
                            ? "TCP"
                            : p.headers["udp.srcport"]
                              ? "UDP"
                              : p.headers["arp.opcode"]
                                ? "ARP"
                                : p.headers["ip.proto"]}
                        </span>
                        <span>{p.headers["frame.len"]}</span>
                      </button>
                      {expanded === i && (
                        <pre>{JSON.stringify(p.headers, null, 2)}</pre>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty">
              <strong>No packet headers captured.</strong>
              <p>
                Select a link, then start a bounded capture. Payloads are not
                retained.
              </p>
            </div>
          ))}
        {tab === "Commands" && (
          <div className="terminal">
            <p>Guided commands only. No unrestricted shell.</p>
            {commands.map((e) => (
              <pre key={e.seq}>
                <span>{new Date(e.ts).toISOString().slice(11, 19)} </span>
                {e.kind === "command"
                  ? `${e.data.node} $ ${(e.data.argv ?? []).join(" ")}`
                  : (e.data.text ?? JSON.stringify(e.data))}
              </pre>
            ))}
            {!commands.length && (
              <p>Commands and output appear when the lab starts.</p>
            )}
          </div>
        )}
        {tab === "Timeline" && (
          <div className="timeline">
            {meaningful
              .slice(-300)
              .reverse()
              .map((e) => (
                <div key={e.seq}>
                  <time>{new Date(e.ts).toISOString().slice(11, 19)}</time>
                  <strong>{e.kind.replaceAll("_", " ")}</strong>
                  <code>{JSON.stringify(e.data)}</code>
                </div>
              ))}
            {!meaningful.length && <p>No recorded events yet.</p>}
          </div>
        )}
        {tab === "Flows" && (
          <div className="flow-view">
            <p>
              Latest controller flow-statistics batch. Polling stays at the
              existing inference interval; this is not a packet capture.
            </p>
            <pre>
              {JSON.stringify(
                events.findLast((e) => e.kind === "flows")?.data ?? {
                  message: "No flow observations yet",
                },
                null,
                2,
              )}
            </pre>
          </div>
        )}
      </div>
    </section>
  );
}
