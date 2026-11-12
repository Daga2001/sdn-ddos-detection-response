/**
 * The Results tab: every number the final report needs from one run, in one place,
 * for every detector (LLM, entropy, or none). It scores the detector against the
 * experiment's own ground truth and puts its cost, the service impact, the response
 * and the recovery next to it. Once a run is over it reads the full record from the
 * lab, so the numbers and the downloads are final; while the run goes on it shows
 * the result so far. Replays use their full record too.
 */
import { useEffect, useRef, useState } from "react";
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
import { detectionSteps, loadSeries, describeBand } from "./detection";
import type { HostRow, Verdict } from "./detection";
import { entropyWarmupSeconds } from "./DetectionPanel";
import {
  NOT_MEASURED,
  PHASES,
  doesNotApply,
  formatChange,
  formatValue,
  metricsTableCsv,
  resultRowCsv,
  runResults,
} from "./results";
import type { Group, Metric, RunResults } from "./results";
import {
  api,
  downloadText,
  fetchRunEvents,
  normalizeExperiment,
  phaseSpans,
} from "./types";
import type {
  Experiment,
  Observation,
  PhaseSpan,
  Run,
  Topology,
} from "./types";

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
      `${measureName(e)} of sources and destinations${e.watch_ports ? ", destination ports" : ""}${e.watch_protocols ? ", protocols" : ""}, ${e.window_seconds}-second windows (${e.window_mode}).`,
      `Normal band: ${describeBand(e)}; warm-up ${e.warmup_windows} windows (${entropyWarmupSeconds(e)} s); alarm after ${e.consecutive_windows} windows in a row outside it.`,
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
  const forwarding =
    config.forwarding === "port_free" ||
    (config.mode === "entropy" && config.entropy?.match_ports === false)
      ? "Port-free rules (Experiment B)"
      : "Per-port rules (Experiment A)";
  lines.push(`Forwarding: ${forwarding}.`);
  return lines;
}

const measureNames: Record<string, string> = {
  shannon: "Shannon entropy",
  norm: "Normalised Shannon entropy",
  renyi: "Rényi entropy",
  tsallis: "Tsallis entropy",
  min: "Min-entropy",
};
function measureName(e: Record<string, any>): string {
  const base = measureNames[e.measure ?? "shannon"] ?? "Entropy";
  return e.measure === "renyi" || e.measure === "tsallis"
    ? `${base} (order ${e.order})`
    : base;
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

function Value({ metric }: { metric: Metric }) {
  const empty = metric.value === null || metric.value === undefined;
  return empty && metric.note ? (
    <span className="not-applicable">{metric.note}</span>
  ) : (
    <>
      {formatValue(metric.value, metric.unit)}
      {metric.note && <small> · {metric.note}</small>}
    </>
  );
}

/** Single-value metrics as a list: label (with its definition) and value. */
function MetricList({ metrics }: { metrics: Metric[] }) {
  if (!metrics.length) return null;
  return (
    <dl className="metric-list">
      {metrics.map((metric) => (
        <div key={metric.key} data-metric={metric.key}>
          <dt>
            {metric.label}
            <Hint text={metric.definition} />
          </dt>
          <dd>
            <Value metric={metric} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** Per-phase metrics: baseline, attack, recovery, and how the attack compares. */
function PhaseTable({ metrics }: { metrics: Metric[] }) {
  if (!metrics.length) return null;
  return (
    <table className="detection-table phase-results">
      <thead>
        <tr>
          <th>Metric</th>
          {PHASES.map((phase) => (
            <th key={phase} className="phase-name">
              {phase}
            </th>
          ))}
          <th>Attack vs baseline</th>
        </tr>
      </thead>
      <tbody>
        {metrics.map((metric) => (
          <tr key={metric.key} data-metric={metric.key}>
            <td>
              {metric.label}
              <Hint text={metric.definition} />
            </td>
            {metric.phases ? (
              <>
                {PHASES.map((phase) => (
                  <td key={phase}>
                    {formatValue(metric.phases?.[phase] ?? null, metric.unit)}
                  </td>
                ))}
                <td>{formatChange(metric)}</td>
              </>
            ) : (
              <td colSpan={4} className="not-applicable">
                {metric.note ?? "—"}
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Section({
  title,
  hint,
  metrics,
  group,
  children,
}: {
  title: string;
  hint: string;
  metrics: Metric[];
  group: Group;
  children?: React.ReactNode;
}) {
  const ours = metrics.filter((metric) => metric.group === group);
  // Metrics that cannot exist for this detector are listed once, not row by row;
  // the downloads keep their (empty) columns.
  const missing = ours.filter(doesNotApply);
  const mine = ours.filter((metric) => !doesNotApply(metric));
  return (
    <section className="results-section" aria-label={title}>
      <h3>
        {title}
        <Hint text={hint} />
      </h3>
      {children}
      <MetricList metrics={mine.filter((metric) => !metric.phased)} />
      <PhaseTable metrics={mine.filter((metric) => metric.phased)} />
      {missing.length > 0 && (
        <p className="field-note results-missing">
          Does not apply to this run: {missing.map((m) => m.label).join(", ")}.
        </p>
      )}
    </section>
  );
}

function fileName(results: RunResults, kind: string) {
  const id = String(
    results.metrics.find((m) => m.key === "run_id")?.value ?? "run",
  ).slice(0, 8);
  return `results-${results.detector}-${id}-${kind}.csv`;
}

/** The full record of a finished run, read once from the lab. */
function useFullRecord(runId: string | null, wanted: boolean) {
  const [record, setRecord] = useState<{
    id: string;
    run: Run | null;
    events: Observation[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!wanted || !runId) return;
    let cancelled = false;
    setError(null);
    (async () => {
      try {
        const [run, events] = await Promise.all([
          api<Run>(`/runs/${runId}`),
          fetchRunEvents(runId),
        ]);
        if (!cancelled) setRecord({ id: runId, run, events });
      } catch (failure) {
        if (!cancelled)
          setError(
            failure instanceof Error
              ? failure.message
              : "The lab did not return the record of this run.",
          );
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [runId, wanted]);
  return { record: record?.id === runId ? record : null, error };
}

export function ResultsView({
  events,
  topology,
  experiment,
  active,
  runId,
  replay,
}: {
  events: Observation[];
  topology: Topology | null;
  experiment: Experiment | null;
  active: boolean;
  /** The live run this view follows; null in a replay or before any run. */
  runId: string | null;
  /** A replay's run and its complete record. */
  replay: { run: Run; events: Observation[] } | null;
}) {
  // A finished live run is read again from the lab: the browser keeps only the
  // most recent events, and the report needs every one of them.
  const { record, error } = useFullRecord(runId, !replay && !active);
  const source = replay ?? record;
  const shown = source?.events ?? events;
  // Score a finished run against what it recorded, not against the form, which
  // may have been edited since.
  const truth = record?.run?.settings
    ? normalizeExperiment(record.run.settings)
    : experiment;
  const network = record?.run?.topology ?? topology;
  const results = runResults({
    events: shown,
    topology: network,
    experiment: truth?.attackers.length ? truth : null,
    run: source?.run ?? (runId ? { id: runId } : null),
    active,
  });
  const endMs = shown.length
    ? Date.parse(shown[shown.length - 1].ts)
    : Date.now();
  const spans = phaseSpans(shown, endMs);

  if (!results)
    return (
      <div className="empty">
        <span>◎</span>
        <strong>Results appear once an experiment's attack starts.</strong>
        <p>
          Run an experiment from the Experiment tab. Its attackers and victims
          are the ground truth every detector is scored against, and this tab
          then gathers every number of the run in one place.
        </p>
      </div>
    );

  const { analysis, metrics } = results;
  const c = analysis.confusion;
  const lines = criteria(analysis.config);
  const finalLabel = replay
    ? "RECORDED RUN · FULL RECORD"
    : results.final && record
      ? "FINAL RESULT · FULL RECORD"
      : active
        ? "LIVE · RESULT SO FAR"
        : "READING THE FULL RECORD…";
  const off = results.detector === "off";
  return (
    <div className="detection-results results-view">
      <div className="results-head">
        <div>
          <span className="eyebrow">{finalLabel}</span>
          <ul className="criteria">
            {lines.length ? (
              lines.map((line) => <li key={line}>{line}</li>)
            ) : (
              <li>The detector setup of this run was not recorded.</li>
            )}
          </ul>
        </div>
        <div className="results-actions">
          <button
            type="button"
            disabled={active}
            title="One row with a fixed set of columns for this run. Download it for every run and paste the rows under one header to build the results tables."
            onClick={() =>
              downloadText(
                fileName(results, "row"),
                resultRowCsv(results),
                "text/csv",
              )
            }
          >
            Download results row (CSV)
          </button>
          <button
            type="button"
            disabled={active}
            title="Every metric on its own line, with the value as shown here and its definition, for writing the methodology."
            onClick={() =>
              downloadText(
                fileName(results, "metrics"),
                metricsTableCsv(results),
                "text/csv",
              )
            }
          >
            Download all metrics (CSV)
          </button>
        </div>
      </div>
      {error && (
        <p className="role-empty warn">
          The full record could not be read, so these numbers come from the
          events this page kept: {error}
        </p>
      )}
      {!active &&
        (results.problems.length ? (
          <div className="results-validity warn" role="status">
            <strong>Do not count this run in the results.</strong>
            <ul>
              {results.problems.map((problem) => (
                <li key={problem}>{problem}</li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="results-validity ok" role="status">
            Valid run: it completed, the attack has a start and an end, and no
            telemetry was lost.
          </p>
        ))}

      <Section
        title="How well it detected"
        hint="Unit: one host per run. An attacker named at least once is a true positive (TP), one never named a false negative (FN); a legitimate client named is a false positive (FP), one never named a true negative (TN). The victim is not scored. The per-flow rows below are a second unit, for the LLM only."
        metrics={metrics.filter(
          (m) => !["tp", "fn", "fp", "tn"].includes(m.key),
        )}
        group="Detection"
      >
        {off ? (
          <p className="field-note">
            No detector ran: this is a no-defense run. Use it as the reference
            for the service, network and recovery numbers.
          </p>
        ) : (
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
        )}
        {!analysis.attackOver && (
          <p className="field-note">
            Still running: an attacker not detected yet only becomes a false
            negative when the attack ends, and a legitimate client can still be
            flagged.
          </p>
        )}
        {(analysis.victimFlagged.length > 0 ||
          analysis.unknownFlagged.length > 0) && (
          <p className="role-empty warn">
            {analysis.victimFlagged.length > 0 &&
              `The detector also named the victim (${analysis.victimFlagged.join(", ")}) as a source. `}
            {analysis.unknownFlagged.length > 0 &&
              `It named addresses that belong to no host here: ${analysis.unknownFlagged.join(", ")}.`}
          </p>
        )}
      </Section>

      <Section
        title="What each decision cost"
        hint="Measured inside the lab. Time per decision is what the controller waited for the detector (round trip, model call included). CPU and memory are the detector service's and Ryu's own processes. GPU use on the computer that runs the language model is not measured."
        metrics={metrics}
        group="Cost"
      />

      <Section
        title="Effect on legitimate users"
        hint="What the legitimate clients experienced in each phase: website checks and pings toward the victims. Shares change in points, times and rates in percent."
        metrics={metrics}
        group="Service"
      />

      <Section
        title="Network and control plane"
        hint="Traffic on the hosts' links, Packet-In messages between the switches and the controller, and the rules the switches hold."
        metrics={metrics}
        group="Network"
      />

      <Section
        title="Response"
        hint="What the controller did after a detection, and how much attack traffic still reached the victims."
        metrics={metrics}
        group="Response"
      >
        {analysis.responses.length > 0 && (
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
              {analysis.responses.map((row, index) => (
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
      </Section>

      <Section
        title="Recovery"
        hint="How long after the attack stopped the service and the controller were back to their baseline, following equations 8 and 9 of the proposal. The rule is fixed before looking at any result."
        metrics={metrics}
        group="Recovery"
      />

      <section className="results-section" aria-label="Over time">
        <h3>Attack and detections over time</h3>
        <DetectionChart
          events={shown}
          spans={spans}
          topology={network}
          experiment={truth}
        />
        <p className="footnote">
          Teal: traffic the switches send toward the victim. Green and red
          steps: attackers detected and legitimate hosts wrongly flagged so far.
          Dashed lines: the moments the controller requested a response.
        </p>
      </section>

      <section className="results-section" aria-label="Per host">
        <h3>Per host</h3>
        <HostTable rows={analysis.hosts} />
      </section>

      <Section
        title="What was tested"
        hint="The setup recorded with this run. The results row repeats it, so every row says which setup it measured."
        metrics={metrics}
        group="Run"
      />

      <details className="advanced results-not-measured">
        <summary>Not measured by this lab</summary>
        <ul>
          {NOT_MEASURED.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </details>
      <p className="footnote">
        One run is one sample. For the report, repeat each setup (the evaluation
        protocol asks for at least 10 runs), download each run's results row,
        and report the mean with a confidence interval.
      </p>
    </div>
  );
}
