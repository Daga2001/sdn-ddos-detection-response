import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import * as echarts from "echarts/core";
import { LineChart } from "echarts/charts";
import {
  GridComponent,
  TooltipComponent,
  LegendComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { Observation, PhaseSpan } from "./types";
import { packets, phaseSpans } from "./types";
import { EntropyView } from "./EntropyView";
echarts.use([
  LineChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  CanvasRenderer,
]);

// Plain-language reasons each observation view exists, shown on hover. Each
// answers: what you see here, how to read it, and why it is useful.
const tabHints: Record<string, string> = {
  Detection:
    "WHAT: how the detector did on this run — a confusion matrix (true/false positives and negatives per host), precision and recall, how fast it reacted, the measured network and service data around it, and a live chart of the attack against the detections. HOW TO READ: attackers named are true positives, legitimate clients named are false positives; the chart shows the flood reaching the victim and the detections stacking up. WHY: it answers “did the detector work, and at what cost?” without reading event logs.",
  Threshold:
    "WHAT: a window-by-window log of the entropy detector — the entropy it computes for source IPs, destination IPs (and ports or protocols if you turned them on), the band of normal values it learned, where the centre of that band sits, and the network it measured (packet rate, flow rules, busiest talkers). HOW TO READ: dots inside the shaded band are normal, outside it they are suspicious; the dashed line is the learned centre (the mean or the median, as chosen in the Detection tab). WHY: it shows in real time why the detector alarmed or stayed quiet, and how its threshold moves as the traffic changes.",
  Traffic:
    "WHAT: a live time chart — the teal line is how much data is crossing the links each second, the orange line is how long the web service takes to answer a normal request, and the shaded bands mark the baseline, attack and recovery phases. HOW TO READ: during an attack the traffic line climbs and the latency line rises or its points drop out when a probe fails. WHY: it is the headline picture of an attack's impact building up and fading away.",
  Packets:
    "WHAT: a sample of individual packets — source, destination and protocol — captured from one link you pick. HOW TO READ: each row is one packet; click it for its header fields. WHY: it confirms what kind of traffic is really flowing (SYN vs UDP vs ICMP). It is empty until you start a capture: the experiment does not record packets on its own. Pick a link in the Inspect tab and start a bounded capture; payloads are never kept.",
  Commands:
    "WHAT: every command the lab ran on your behalf, with a timestamp and its output. HOW TO READ: each line is one real command on one node (the controller, a host running traffic, the victim's web service). WHY: nothing runs on a hidden shell, so you can see and trust exactly what happened — and when a run fails, this is where the underlying error appears.",
  Timeline:
    "WHAT: a plain, time-ordered log of the notable moments in a run. HOW TO READ: top is most recent; each entry names an event — a phase change, the attack starting or stopping, a detection, an error. WHY: it is the quick answer to “what happened, and in what order?” without reading every command.",
  Flows:
    "WHAT: the switches' OpenFlow forwarding tables as the controller last polled them (every few seconds), one row per flow with its packet and byte counters. HOW TO READ: high packet/byte counts on a flow toward the victim are the flood; a drop rule would appear here too. WHY: it shows how the network is actually forwarding — or dropping — traffic underneath the chart. It is not a packet capture.",
};

const bandColor: Record<string, string> = {
  baseline: "rgba(8, 126, 131, 0.06)",
  attack: "rgba(193, 107, 65, 0.12)",
  recovery: "rgba(90, 120, 150, 0.08)",
};

function Chart({
  events,
  spans,
}: {
  events: Observation[];
  spans: PhaseSpan[];
}) {
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
          markArea: {
            silent: true,
            data: spans.map((span) => [
              {
                xAxis: span.start,
                itemStyle: { color: bandColor[span.state] ?? "transparent" },
                label: {
                  show: true,
                  position: "insideTop",
                  distance: 4,
                  fontSize: 10,
                  color: "#5b6b60",
                  formatter: `${span.state} · ${Math.round(
                    (span.end - span.start) / 1000,
                  )}s`,
                },
              },
              { xAxis: span.end },
            ]),
          },
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
  }, [events, spans]);
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
  detectionView,
}: {
  events: Observation[];
  tab: string;
  setTab: (value: string) => void;
  detectionView?: ReactNode;
}) {
  const [expanded, setExpanded] = useState(-1);
  const packetRows = packets(events);
  const endMs = events.length
    ? Date.parse(events[events.length - 1].ts)
    : Date.now();
  const spans = phaseSpans(events, endMs);
  const controller = events.findLast((e) => e.kind === "controller")?.data;
  // Entropy windows come every few seconds and have their own tab; the Timeline keeps
  // only the ones that mattered.
  const meaningful = events.filter(
    (e) =>
      ![
        "links",
        "flows",
        "controller",
        "packet",
        "packets",
        "command_output",
      ].includes(e.kind) &&
      (e.kind !== "entropy_window" ||
        ["suspicious", "alarm"].includes(e.data.state)),
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
      <div
        className="controller-readout"
        title="CPU and memory used by the Ryu controller process alone — the ryu-manager program that runs the network's control logic. This is NOT your whole computer, the Docker container, or Mininet: just that one process, measured with psutil. CPU is a percentage of a single core, so brief spikes above 100% are possible on a multi-core machine. It is sampled every few seconds; the number shown is the latest sample. Watch it climb when the controller is under load."
      >
        Ryu controller process · CPU{" "}
        {controller ? `${Number(controller.cpu_percent).toFixed(1)}%` : "—"}{" "}
        <span> / </span> RAM{" "}
        {controller
          ? `${(Number(controller.rss_bytes) / 1048576).toFixed(1)} MiB`
          : "—"}{" "}
        · latest recorded sample
      </div>
      <nav className="tabs" aria-label="Observations">
        {[
          "Traffic",
          "Detection",
          "Threshold",
          "Packets",
          "Commands",
          "Timeline",
          "Flows",
        ].map((value) => (
          <button
            key={value}
            className={tab === value ? "active" : ""}
            title={tabHints[value]}
            onClick={() => setTab(value)}
          >
            {value}
            {value === "Packets" && packetRows.length > 0
              ? ` · ${packetRows.length}`
              : ""}
          </button>
        ))}
        <span>Measured evidence · UTC</span>
      </nav>
      <div
        className={`observation-body${["Detection", "Threshold"].includes(tab) ? " tall" : ""}`}
      >
        {tab === "Traffic" &&
          (events.some((e) => e.kind === "links") ? (
            <>
              <Chart events={events} spans={spans} />
              {spans.length > 0 && (
                <div
                  className="phase-legend"
                  aria-label="Measured phase durations"
                >
                  {spans.map((span, i) => (
                    <span key={i} className={`phase-band ${span.state}`}>
                      {span.state} ·{" "}
                      {Math.round((span.end - span.start) / 1000)}s
                    </span>
                  ))}
                </div>
              )}
              <p className="footnote">
                Shaded bands mark the measured baseline, attack, and recovery
                phases against the clock. Traffic is summed across measured
                links, not unique end-to-end throughput. A missing latency point
                means the service probe failed.
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
        {tab === "Detection" && detectionView}
        {tab === "Threshold" && <EntropyView events={events} spans={spans} />}
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
              <strong>No packets captured yet.</strong>
              <p>
                Capturing packets is a separate, on-demand step — an experiment
                does not record them on its own, so this stays empty until you
                ask for a capture (even while a run is in progress).
              </p>
              <p>
                Open the <b>Inspect</b> tab, select a link, and start a bounded
                capture. A sample of packet headers then appears here; payloads
                are never retained.
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
