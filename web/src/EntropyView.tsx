/**
 * The Threshold tab: what the entropy detector sees, window after window.
 *
 * A live chart of the value it computes for one distribution (source IPs, destination
 * IPs, ports…) against the band it learned (centre ± k × spread), so the centre and the
 * band can be watched moving; below it, one line per window with the measured network
 * (rate, flow rules, busiest talkers) and the verdict.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import * as echarts from "echarts/core";
import { LineChart } from "echarts/charts";
import {
  GridComponent,
  LegendComponent,
  MarkAreaComponent,
  TooltipComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import {
  describeEntropyConfig,
  entropyWindows,
  formatSignal,
  panelMeasures,
} from "./detection";
import type { EntropyState, EntropyWindow } from "./detection";
import { download } from "./types";
import type { Observation, PhaseSpan } from "./types";

echarts.use([
  LineChart,
  GridComponent,
  LegendComponent,
  MarkAreaComponent,
  TooltipComponent,
  CanvasRenderer,
]);

const stateColor: Record<EntropyState, string> = {
  alarm: "#b3261e",
  suspicious: "#c16b41",
  normal: "#087e83",
  warmup: "#8a8f98",
  idle: "#c9cdd3",
};
const stateNote: Record<EntropyState, string> = {
  alarm: "alarm confirmed",
  suspicious: "outside the band",
  normal: "inside the band",
  warmup: "still learning",
  idle: "too quiet to judge",
};
const phaseColor: Record<string, string> = {
  baseline: "rgba(8, 126, 131, 0.06)",
  attack: "rgba(193, 107, 65, 0.12)",
  recovery: "rgba(90, 120, 150, 0.08)",
};
const featureNames: Record<string, string> = {
  src: "Source IPs",
  dst: "Destination IPs",
  dport: "Destination ports",
  proto: "Protocols",
};

function EntropyChart({
  windows,
  feature,
  show,
  spans,
}: {
  windows: EntropyWindow[];
  feature: string;
  show: string;
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
    const decision = show === "decision";
    const rows = windows.slice(-400);
    const byTime = new Map(rows.map((row) => [row.at, row]));
    const valueOf = (row: EntropyWindow): number | null =>
      decision
        ? (row.signals[feature]?.value ?? null)
        : (row.panel[feature]?.[show] ?? null);
    const banded = decision
      ? rows.filter(
          (row) =>
            row.signals[feature]?.lower != null &&
            row.signals[feature]?.upper != null,
        )
      : [];
    const label = decision
      ? `${featureNames[feature] ?? feature} entropy`
      : (panelMeasures.find(([id]) => id === show)?.[1] ?? show);
    const series: any[] = [];
    if (decision) {
      series.push(
        {
          name: "band floor",
          type: "line",
          stack: "band",
          symbol: "none",
          silent: true,
          lineStyle: { opacity: 0 },
          data: banded.map((row) => [row.at, row.signals[feature].lower]),
        },
        {
          name: "normal band",
          type: "line",
          stack: "band",
          symbol: "none",
          silent: true,
          lineStyle: { opacity: 0 },
          areaStyle: { opacity: 0.16, color: "#087e83" },
          data: banded.map((row) => [
            row.at,
            (row.signals[feature].upper as number) -
              (row.signals[feature].lower as number),
          ]),
        },
        {
          name: "centre",
          type: "line",
          symbol: "none",
          lineStyle: { type: "dashed", width: 1.5, color: "#5b6b60" },
          data: banded.map((row) => [row.at, row.signals[feature].center]),
        },
      );
    }
    series.push({
      name: label,
      type: "line",
      showSymbol: true,
      symbolSize: 7,
      connectNulls: false,
      lineStyle: { width: 2, color: "#087e83" },
      data: rows.map((row) => ({
        value: [row.at, valueOf(row)],
        itemStyle: { color: stateColor[row.state] },
      })),
      markArea: {
        silent: true,
        data: spans.map((span) => [
          {
            xAxis: span.start,
            itemStyle: { color: phaseColor[span.state] ?? "transparent" },
            label: {
              show: true,
              position: "insideTop",
              fontSize: 10,
              color: "#5b6b60",
              formatter: span.state,
            },
          },
          { xAxis: span.end },
        ]),
      },
    });
    chart.current?.setOption(
      {
        animation: false,
        grid: { left: 56, right: 24, top: 44, bottom: 30 },
        legend: {
          top: 4,
          data: decision ? ["normal band", "centre", label] : [label],
          textStyle: { fontSize: 11 },
        },
        tooltip: {
          trigger: "axis",
          renderMode: "richText",
          formatter: (params: any) => {
            const first = Array.isArray(params)
              ? params[params.length - 1]
              : params;
            const row = byTime.get(first.value[0]);
            if (!row) return "";
            const time = new Date(row.at).toISOString().slice(11, 19);
            const signal = row.signals[feature];
            return [
              `${time} · window ${row.window} · ${row.state}`,
              decision
                ? `${label}: ${formatSignal(signal)}`
                : `${label}: ${valueOf(row)?.toFixed(3) ?? "—"}`,
              decision && signal?.center != null
                ? `centre ${signal.center.toFixed(3)}`
                : "",
            ]
              .filter(Boolean)
              .join("\n");
          },
        },
        xAxis: { type: "time" },
        yAxis: {
          type: "value",
          name: label,
          scale: true,
          splitLine: { lineStyle: { color: "#e4e7df" } },
        },
        series,
      },
      true,
    );
  }, [windows, feature, show, spans]);
  return (
    <div
      className="traffic-chart entropy-chart"
      ref={element}
      aria-label="Entropy against its learned band"
    />
  );
}

function topLine(items: [string, number][]): string {
  return items
    .slice(0, 2)
    .map(([name, rate]) => `${name} ${Number(rate).toFixed(0)}`)
    .join(" · ");
}

export function EntropyView({
  events,
  spans,
}: {
  events: Observation[];
  spans: PhaseSpan[];
}) {
  const windows = useMemo(() => entropyWindows(events), [events]);
  const [feature, setFeature] = useState("src");
  const [show, setShow] = useState("decision");
  const last = windows[windows.length - 1];
  const features = useMemo(() => {
    const found = new Set<string>(["src", "dst"]);
    for (const row of windows)
      for (const name of Object.keys(row.signals)) found.add(name);
    return ["src", "dst", "dport", "proto"].filter((name) => found.has(name));
  }, [windows]);
  if (!windows.length)
    return (
      <div className="empty">
        <span>≈</span>
        <strong>The entropy detector has not reported yet.</strong>
        <p>
          Choose <b>Entropy</b> in the Detection tab and run an experiment:
          every window the detector measures, its normal band and what it
          concluded show up in the Threshold tab, as they happen.
        </p>
      </div>
    );
  const shownFeatures = features.filter((name) =>
    windows.some((row) => row.signals[name]),
  );
  const counts = windows.reduce(
    (total, row) => ({ ...total, [row.state]: (total[row.state] ?? 0) + 1 }),
    {} as Record<string, number>,
  );
  return (
    <div className="entropy-view">
      <p className="entropy-summary">
        {describeEntropyConfig(last.config) || `Measure: ${last.measure}`}
      </p>
      <div className="entropy-controls">
        <label>
          Distribution
          <select
            value={shownFeatures.includes(feature) ? feature : "src"}
            onChange={(event) => setFeature(event.target.value)}
          >
            {shownFeatures.map((name) => (
              <option key={name} value={name}>
                {featureNames[name] ?? name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Show
          <select
            value={show}
            onChange={(event) => setShow(event.target.value)}
          >
            <option value="decision">What decides (with its band)</option>
            {panelMeasures.map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <button
          type="button"
          onClick={() => download("entropy-windows.json", windows)}
        >
          Download windows
        </button>
      </div>
      <EntropyChart
        windows={windows}
        feature={shownFeatures.includes(feature) ? feature : "src"}
        show={show}
        spans={spans}
      />
      <div className="phase-legend" aria-label="Window states">
        {(Object.keys(stateColor) as EntropyState[]).map((state) => (
          <span key={state} className="state-chip">
            <i style={{ background: stateColor[state] }} />
            {state} · {counts[state] ?? 0}
          </span>
        ))}
      </div>
      <p className="footnote">
        Each dot is one window, coloured by what the detector concluded. The
        shaded area is the band it learned as normal and the dashed line is its
        centre; a dot outside the band is suspicious, and the alarm is confirmed
        after several in a row. “What decides” is the entropy the detector
        compares; the other choices show the same traffic through another
        entropy for comparison.
      </p>
      <div className="entropy-log-wrap">
        <table className="detection-table compact entropy-log">
          <thead>
            <tr>
              <th>Time</th>
              <th>#</th>
              <th>State</th>
              <th>pkt/s</th>
              <th>Rules</th>
              {shownFeatures.map((name) => (
                <th key={name}>{featureNames[name] ?? name}</th>
              ))}
              <th>Streak</th>
              <th>Busiest sources</th>
              <th>Busiest destinations</th>
              {last.topPorts.length > 0 && <th>Busiest ports</th>}
            </tr>
          </thead>
          <tbody>
            {windows
              .slice(-150)
              .reverse()
              .map((row) => (
                <tr key={row.window} className={`state-${row.state}`}>
                  <td>{new Date(row.at).toISOString().slice(11, 19)}</td>
                  <td>{row.window}</td>
                  <td title={stateNote[row.state]}>
                    <span className="state-badge" data-state={row.state}>
                      {row.state}
                    </span>
                  </td>
                  <td>{row.rate.toFixed(0)}</td>
                  <td>{row.rules}</td>
                  {shownFeatures.map((name) => (
                    <td
                      key={name}
                      className={row.signals[name]?.out ? "outside" : undefined}
                    >
                      {formatSignal(row.signals[name])}
                    </td>
                  ))}
                  <td>
                    {row.streak}/{row.needed}
                  </td>
                  <td>{topLine(row.topSrc)}</td>
                  <td>{topLine(row.topDst)}</td>
                  {last.topPorts.length > 0 && <td>{topLine(row.topPorts)}</td>}
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      <h4 className="subsection">The latest window through every entropy</h4>
      <table className="detection-table compact">
        <thead>
          <tr>
            <th>Entropy</th>
            {shownFeatures.map((name) => (
              <th key={name}>{featureNames[name] ?? name}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {panelMeasures.map(([id, label]) => (
            <tr key={id}>
              <td>{label}</td>
              {shownFeatures.map((name) => (
                <td key={name}>
                  {last.panel[name]?.[id] !== undefined
                    ? last.panel[name][id].toFixed(3)
                    : "—"}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
