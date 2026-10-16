/**
 * The Detection results tab: what the detector concluded about this run, scored against
 * the experiment's own ground truth, next to the network measurements around it.
 * It reads only recorded events, so it works live, in a replay and on old runs.
 */
import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { LineChart } from "echarts/charts";
import {
  GridComponent,
  LegendComponent,
  MarkAreaComponent,
  MarkLineComponent,
  TooltipComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { Hint } from "./Field";
import {
  analyzeDetection,
  detectionSteps,
  loadSeries,
  percent,
} from "./detection";
import type { Analysis, HostRow, Verdict } from "./detection";
import { entropyWarmupSeconds } from "./DetectionPanel";
import { phaseSpans } from "./types";
import type { Experiment, Observation, PhaseSpan, Topology } from "./types";

echarts.use([
  LineChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  MarkAreaComponent,
  MarkLineComponent,
  CanvasRenderer,
]);

const bandColor: Record<string, string> = {
  baseline: "rgba(8, 126, 131, 0.06)",
  attack: "rgba(193, 107, 65, 0.12)",
  recovery: "rgba(90, 120, 150, 0.08)",
};

function DetectionChart({
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
    const victims = new Set(experiment?.victims ?? []);
    const links = new Set(
      (topology?.links ?? [])
        .filter((l) => victims.has(l.source) !== victims.has(l.target))
        .map((l) => l.id),
    );
    const load = loadSeries(events, links).slice(-400);
    const steps = detectionSteps(events, topology, experiment);
    const first = events.length ? Date.parse(events[0].ts) : Date.now();
    const last = events.length
      ? Date.parse(events[events.length - 1].ts)
      : Date.now();
    const stepData = (points: [number, number][]) => [
      [first, 0],
      ...points,
      [last, points.length ? points[points.length - 1][1] : 0],
    ];
    const responses = events
      .filter((e) => e.kind === "mitigation_requested")
      .map((e) => ({
        xAxis: Date.parse(e.ts),
        label: {
          formatter: String(e.data.action ?? "block").replace("_", " "),
          fontSize: 10,
        },
      }));
    chart.current?.setOption({
      animation: false,
      color: ["#087e83", "#2e8b57", "#c0392b"],
      grid: { left: 60, right: 62, top: 44, bottom: 30 },
      legend: {
        data: [
          "Traffic toward the victim (kb/s)",
          "Attackers detected",
          "False positives",
        ],
        top: 4,
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
        {
          type: "value",
          name: "hosts",
          minInterval: 1,
          min: 0,
          splitLine: { show: false },
        },
      ],
      series: [
        {
          name: "Traffic toward the victim (kb/s)",
          type: "line",
          showSymbol: false,
          areaStyle: { opacity: 0.09 },
          data: load,
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
                  formatter: span.state,
                },
              },
              { xAxis: span.end },
            ]),
          },
          markLine: {
            silent: true,
            symbol: "none",
            lineStyle: { color: "#8e44ad", type: "dashed" },
            data: responses,
          },
        },
        {
          name: "Attackers detected",
          type: "line",
          yAxisIndex: 1,
          step: "end",
          showSymbol: true,
          data: stepData(steps.detected),
        },
        {
          name: "False positives",
          type: "line",
          yAxisIndex: 1,
          step: "end",
          showSymbol: true,
          data: stepData(steps.falsePositives),
        },
      ],
    });
  }, [events, spans, topology, experiment]);
  return (
    <div
      className="traffic-chart"
      ref={element}
      aria-label="Detection timeline chart"
    />
  );
}

const verdictText: Record<Verdict, string> = {
  VP: "True positive",
  FN: "False negative",
  FP: "False positive",
  VN: "True negative",
};

function Cell({
  code,
  count,
  tone,
}: {
  code: Verdict;
  count: number;
  tone: "good" | "bad";
}) {
  return (
    <div
      className={`matrix-cell ${tone}`}
      aria-label={`${verdictText[code]} ${count}`}
    >
      <strong>{count}</strong>
      <span>{code}</span>
      <small>{verdictText[code]}</small>
    </div>
  );
}

function seconds(value: number | null) {
  return value === null ? "—" : `${value >= 0 ? "+" : ""}${value.toFixed(1)} s`;
}

function criteria(config: Record<string, any> | null): string[] {
  if (!config) return [];
  if (config.mode === "off") return ["No detection: nothing was judged."];
  const lines: string[] = [];
  if (config.mode === "llm") {
    lines.push(
      `LLM ${config.model}, prompt profile “${config.prompt}”.`,
      `A flow is an attack when the model's probability ≥ ${config.threshold ?? 0.8}; up to ${config.llm_max_samples ?? "?"} flows per switch poll are judged.`,
    );
  } else if (config.mode === "entropy") {
    const e = config.entropy ?? {};
    lines.push(
      `Shannon entropy of sources and destinations, ${e.window_seconds}-second windows (${e.window_mode}).`,
      `Normal band: learned over ${e.warmup_windows} windows (${entropyWarmupSeconds(e)} s), width k = ${e.k}; alarm after ${e.consecutive_windows} windows in a row outside it.`,
      `A source is named only above ${e.candidate_min_rate} pkt/s and ${Math.round((e.candidate_share ?? 0) * 100)} % of the traffic.`,
    );
  } else {
    lines.push(
      `Detector in service: ${config.mode}${config.model ? ` · ${config.model}` : ""}.`,
    );
  }
  if (config.mitigation) {
    const r = config.response ?? {};
    lines.push(
      r.dry_run
        ? `Response simulated (dry run): policy ${r.policy ?? config.response}.`
        : `Response applied: policy ${r.policy ?? config.response}.`,
    );
  }
  return lines;
}

function HostTable({ rows }: { rows: HostRow[] }) {
  const order = { attacker: 0, legit: 1, victim: 2 } as const;
  const sorted = [...rows].sort(
    (a, b) => order[a.role] - order[b.role] || a.name.localeCompare(b.name),
  );
  return (
    <table className="detection-table">
      <thead>
        <tr>
          <th>Host</th>
          <th>Role</th>
          <th>Result</th>
          <th>Detections</th>
          <th>First detected</th>
          <th>Peak probability</th>
          <th>Response</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((row) => (
          <tr key={row.name} className={row.verdict ?? "open"}>
            <td>
              {row.name}
              <small> {row.ip}</small>
            </td>
            <td>{row.role === "legit" ? "legitimate client" : row.role}</td>
            <td>
              {row.role === "victim"
                ? row.flagged
                  ? "named as a source"
                  : "not scored"
                : row.verdict
                  ? `${row.verdict} · ${verdictText[row.verdict]}`
                  : "pending"}
            </td>
            <td>
              {row.detections}
              {row.fromResponse && (
                <small title="Its detection event was not recorded, but the controller acted on it, which only happens after a detection.">
                  {" "}
                  (seen via response)
                </small>
              )}
            </td>
            <td>{seconds(row.firstOffsetS)}</td>
            <td>
              {row.maxProbability === null
                ? "—"
                : row.maxProbability.toFixed(2)}
            </td>
            <td>{row.actions.length ? row.actions.join(", ") : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function kbps(value: number | null) {
  return value === null ? "—" : `${value.toFixed(1)} kb/s`;
}

function Phases({ result }: { result: Analysis }) {
  const names = ["baseline", "attack", "recovery"].filter(
    (name) => result.service[name],
  );
  if (!names.length)
    return <p className="field-note">No service probes yet.</p>;
  return (
    <table className="detection-table compact">
      <thead>
        <tr>
          <th>Phase</th>
          <th>Probes that got through</th>
          <th>Average latency</th>
        </tr>
      </thead>
      <tbody>
        {names.map((name) => {
          const row = result.service[name];
          return (
            <tr key={name}>
              <td>{name}</td>
              <td>
                {row.ok} / {row.probes} ({percent(row.ok / row.probes)})
              </td>
              <td>
                {row.meanLatencyMs === null
                  ? "—"
                  : `${row.meanLatencyMs.toFixed(0)} ms`}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export function DetectionResults({
  events,
  topology,
  experiment,
  active,
}: {
  events: Observation[];
  topology: Topology | null;
  experiment: Experiment | null;
  active: boolean;
}) {
  const result = analyzeDetection(events, topology, experiment, active);
  const endMs = events.length
    ? Date.parse(events[events.length - 1].ts)
    : Date.now();
  const spans = phaseSpans(events, endMs);

  if (!result.hasExperiment)
    return (
      <div className="empty">
        <span>◎</span>
        <strong>Detection results appear with an experiment.</strong>
        <p>
          Run an experiment from the Experiment tab. Its attackers and victims
          are the ground truth the detector is scored against.
        </p>
      </div>
    );

  const { confusion: c, metrics: m } = result;
  const lines = criteria(result.config);
  return (
    <div className="detection-results">
      <div className="detection-head">
        <div>
          <span className="eyebrow">
            {result.attackOver ? "FINAL RESULT" : "LIVE · RESULT SO FAR"}
          </span>
          <ul className="criteria">
            {lines.length ? (
              lines.map((line) => <li key={line}>{line}</li>)
            ) : (
              <li>The detector setup of this run was not recorded.</li>
            )}
          </ul>
        </div>
      </div>

      <div className="detection-grid">
        <div>
          <h3>
            Confusion matrix
            <Hint text="Each host is one case. An attacker the detector named at least once is a true positive (VP); one it never named is a false negative (FN). A legitimate client it named is a false positive (FP); one it never named is a true negative (VN). The victim is not scored." />
          </h3>
          <div
            className="confusion"
            role="table"
            aria-label="Confusion matrix by host"
          >
            <span className="axis top">Detected</span>
            <span className="axis top">Not detected</span>
            <Cell code="VP" count={c.vp} tone="good" />
            <Cell code="FN" count={c.fn} tone="bad" />
            <Cell code="FP" count={c.fp} tone="bad" />
            <Cell code="VN" count={c.vn} tone="good" />
            <span className="axis side attackers">Attackers</span>
            <span className="axis side legit">Legitimate</span>
          </div>
          {!result.attackOver && (
            <p className="field-note">
              Still running: an attacker not detected yet only becomes a false
              negative when the attack ends, and a legitimate client can still
              be flagged.
            </p>
          )}
        </div>
        <div>
          <h3>
            Detection quality
            <Hint text="Precision: of the hosts named, how many were attackers. Recall: of the attackers, how many were named. False-positive rate: of the legitimate clients, how many were named. All are measured per host, per run, so with few hosts they move in large steps." />
          </h3>
          <dl className="metric-list">
            <div>
              <dt>Precision</dt>
              <dd>{percent(m.precision)}</dd>
            </div>
            <div>
              <dt>Recall (detection rate)</dt>
              <dd>{percent(m.recall)}</dd>
            </div>
            <div>
              <dt>False-positive rate</dt>
              <dd>{percent(m.falsePositiveRate)}</dd>
            </div>
            <div>
              <dt>Specificity</dt>
              <dd>{percent(m.specificity)}</dd>
            </div>
            <div>
              <dt>Accuracy</dt>
              <dd>{percent(m.accuracy)}</dd>
            </div>
            <div>
              <dt>F1</dt>
              <dd>{percent(m.f1)}</dd>
            </div>
            <div>
              <dt>First attacker detected</dt>
              <dd>{seconds(result.firstDetectionS)}</dd>
            </div>
            <div>
              <dt>All attackers detected</dt>
              <dd>{seconds(result.allDetectedS)}</dd>
            </div>
          </dl>
        </div>
      </div>

      {result.droppedEvents > 0 && (
        <p className="role-empty warn">
          The lab dropped {result.droppedEvents} telemetry events while it was
          busy during this run, so a detection or response event can be missing
          here. A host counted as not detected may have been named; read the
          detections as a lower bound. Hosts the controller acted on are counted
          even when their detection event was lost.
        </p>
      )}
      {(result.victimFlagged.length > 0 ||
        result.unknownFlagged.length > 0) && (
        <p className="role-empty warn">
          {result.victimFlagged.length > 0 &&
            `The detector also named the victim (${result.victimFlagged.join(", ")}) as a source. `}
          {result.unknownFlagged.length > 0 &&
            `It named addresses that belong to no host here: ${result.unknownFlagged.join(", ")}.`}
        </p>
      )}

      <h3>Attack behaviour in real time</h3>
      <DetectionChart
        events={events}
        spans={spans}
        topology={topology}
        experiment={experiment}
      />
      <p className="footnote">
        Teal: traffic the switches send toward the victim. Green and red steps:
        attackers detected and legitimate hosts wrongly flagged so far. Dashed
        lines: the moments the controller requested a response.
      </p>

      <h3>Per host</h3>
      <HostTable rows={result.hosts} />

      <div className="detection-grid">
        <div>
          <h3>Network and service</h3>
          <dl className="metric-list">
            <div>
              <dt>Topology</dt>
              <dd>
                {topology?.switches.length ?? 0} switches ·{" "}
                {topology?.hosts.length ?? 0} hosts ·{" "}
                {topology?.links.length ?? 0} links
              </dd>
            </div>
            <div>
              <dt>Attack</dt>
              <dd>
                {experiment?.attackers.length} attacker(s) →{" "}
                {experiment?.victims.join(", ")} ·{" "}
                {experiment?.traffic.join("+").toUpperCase()} ·{" "}
                {experiment?.rate} pkt/s each
              </dd>
            </div>
            <div>
              <dt>Traffic toward the victim</dt>
              <dd>
                before {kbps(result.load.baselineKbps)} · attack mean{" "}
                {kbps(result.load.attackMeanKbps)} · peak{" "}
                {kbps(result.load.attackPeakKbps)}
              </dd>
            </div>
            <div>
              <dt>After the first response (+10 s)</dt>
              <dd>{kbps(result.load.afterResponseKbps)}</dd>
            </div>
            <div>
              <dt>Controller</dt>
              <dd>
                CPU peak{" "}
                {result.controller.cpuMax === null
                  ? "—"
                  : `${result.controller.cpuMax.toFixed(1)} %`}{" "}
                · RAM peak{" "}
                {result.controller.ramMaxMiB === null
                  ? "—"
                  : `${result.controller.ramMaxMiB.toFixed(0)} MiB`}
              </dd>
            </div>
            <div>
              <dt>Detection events</dt>
              <dd>
                {result.detectionEvents}
                {result.threshold !== null &&
                  ` · probability threshold ${result.threshold}`}
              </dd>
            </div>
          </dl>
          <Phases result={result} />
        </div>
        <div>
          <h3>Response</h3>
          {result.responses.length === 0 ? (
            <p className="field-note">
              No response was requested.{" "}
              {result.config?.mitigation && result.config?.response?.dry_run
                ? "The response was a simulation, so nothing is recorded as a request."
                : "Turn on the response in the Detection tab to see it here."}
            </p>
          ) : (
            <table className="detection-table compact">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Host</th>
                  <th>Action</th>
                  <th>Target</th>
                </tr>
              </thead>
              <tbody>
                {result.responses.map((row, index) => (
                  <tr key={index} className={row.onAttacker ? "VP" : "FP"}>
                    <td>{seconds(row.offsetS)}</td>
                    <td>{row.host ?? row.source}</td>
                    <td>{row.action}</td>
                    <td>{row.onAttacker ? "attacker" : "legitimate client"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {result.collateral.length > 0 && (
            <p className="role-empty warn">
              Legitimate clients hit by the response:{" "}
              {result.collateral.join(", ")}.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
