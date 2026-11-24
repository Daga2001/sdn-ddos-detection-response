import { useState } from "react";
import {
  formatP,
  mergeRows,
  rowFromRecord,
  rowsCsv,
  rowsFromCsv,
  slim,
} from "./compare";
import type { Comparison, ResultRow } from "./compare";
import { api, fetchRunEvents } from "./types";
import type { Observation, Run } from "./types";

function save(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

const MEASURES: Record<string, string> = {
  detection_rate: "Detection rate",
  false_alarm_rate: "False-alarm rate",
  mean_detection_s: "Detection time (s)",
  availability_attack_pct: "Availability (%)",
};

/**
 * History > Compare runs: the acceptance criteria and every test behind them, for the
 * runs the user picks. Rows are scored here with the Results tab's code; the
 * statistics come from the lab service, the same code as scripts/compare_runs.py.
 */
export function CompareRuns({ runs, busy }: { runs: Run[]; busy: boolean }) {
  const [rows, setRows] = useState<ResultRow[]>([]);
  const [report, setReport] = useState<Comparison | null>(null);
  const [note, setNote] = useState("");
  const [working, setWorking] = useState(false);

  async function step(action: () => Promise<void>) {
    setWorking(true);
    try {
      await action();
    } catch (error) {
      setNote(error instanceof Error ? error.message : String(error));
    } finally {
      setWorking(false);
    }
  }

  async function addFiles(files: FileList | null) {
    if (!files?.length) return;
    const added: ResultRow[] = [];
    let skipped = 0;
    for (const [index, file] of [...files].entries()) {
      setNote(`Reading ${file.name} (${index + 1} of ${files.length})…`);
      const text = await file.text();
      if (file.name.toLowerCase().endsWith(".csv")) {
        added.push(...rowsFromCsv(text, file.name));
        continue;
      }
      let record: { run?: Run; events?: Observation[] };
      try {
        record = JSON.parse(text);
      } catch {
        throw new Error(
          `${file.name} is not a run record. Use a record from the history list (JSON ↓) or a results-row CSV.`,
        );
      }
      if (!Array.isArray(record.events))
        throw new Error(
          `${file.name} has no events. Use a record from the history list (JSON ↓) or a results-row CSV.`,
        );
      const row = rowFromRecord(record.run, record.events);
      if (row) added.push(row);
      else skipped++;
    }
    setRows((current) => mergeRows(current, added));
    setReport(null);
    setNote(
      `${added.length} run(s) added.` +
        (skipped ? ` ${skipped} record(s) had no attack and give no row.` : ""),
    );
  }

  async function addLabRuns() {
    const done = runs.filter((run) => run.status === "completed");
    const added: ResultRow[] = [];
    for (const [index, listed] of done.entries()) {
      setNote(`Scoring run ${index + 1} of ${done.length}…`);
      const run = await api<Run>(`/runs/${listed.id}`);
      const row = rowFromRecord(run, await fetchRunEvents(listed.id));
      if (row) added.push(row);
    }
    setRows((current) => mergeRows(current, added));
    setReport(null);
    setNote(`${added.length} completed run(s) of this lab added.`);
  }

  async function compare() {
    setNote("Comparing…");
    const result = await api<Comparison>("/compare", { rows: rows.map(slim) });
    setReport(result);
    setNote(
      `${result.runs} run(s) in ${result.cells} cell(s) compared; ${result.excluded.length} left out.`,
    );
  }

  const locked = busy || working;
  return (
    <section className="compare-runs">
      <h3>Compare runs</h3>
      <p className="footnote">
        Acceptance criteria of the evaluation: each detector against the
        packet-rate rule of the same scenario (detection and false-alarm rates
        with Fisher's exact test, detection time with Mann–Whitney U) and
        against no defense (availability, Mann–Whitney U), Holm-adjusted per
        scenario. Only valid held-out runs are used, and a cell with mixed
        settings is refused. No test draws random numbers: the same runs always
        give the same report.
      </p>
      <label className="file-button">
        Add records or result rows
        <input
          type="file"
          accept=".json,.csv"
          multiple
          disabled={locked}
          onChange={(event) => {
            const files = event.target.files;
            void step(() => addFiles(files));
            event.target.value = "";
          }}
        />
      </label>
      <button
        disabled={locked || !runs.length}
        onClick={() => void step(addLabRuns)}
      >
        Add this lab's completed runs
      </button>
      <button
        disabled={locked || !rows.length}
        onClick={() => void step(compare)}
      >
        Compare {rows.length} run(s)
      </button>
      <button
        disabled={locked || !rows.length}
        onClick={() => {
          setRows([]);
          setReport(null);
          setNote("");
        }}
      >
        Clear
      </button>
      {note && <p className="footnote">{note}</p>}
      {report && (
        <>
          <table className="compare-table">
            <caption>
              yes = met · no = not met · better = significantly better than the
              rule · -- = the rule is the reference · n.a. = not testable (α ={" "}
              {report.alpha})
            </caption>
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Detector</th>
                <th>DR ≥ rule</th>
                <th>FAR ≤ rule</th>
                <th>Det. ≤ {report.detection_limit_s} s</th>
                <th>Avail. &gt; none</th>
              </tr>
            </thead>
            <tbody>
              {report.verdicts.map((v) => (
                <tr key={v.scenario + v.detector}>
                  <td>{v.scenario}</td>
                  <td>{v.detector}</td>
                  <td>{v.detection_rate_vs_rule}</td>
                  <td>{v.false_alarm_rate_vs_rule}</td>
                  <td>
                    {v.detection_within_limit}
                    {v.mean_detection_s === null
                      ? ""
                      : ` (${v.mean_detection_s.toFixed(1)})`}
                  </td>
                  <td>{v.availability_vs_no_defense}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <table className="compare-table">
            <caption>Tests (two-sided p, Holm-adjusted per scenario)</caption>
            <thead>
              <tr>
                <th>Scenario</th>
                <th>Detector</th>
                <th>Measure</th>
                <th>Detector / reference</th>
                <th>Adjusted p</th>
              </tr>
            </thead>
            <tbody>
              {report.tests.map((t) => (
                <tr key={t.scenario + t.detector + t.measure}>
                  <td>{t.scenario}</td>
                  <td>{t.detector}</td>
                  <td>{MEASURES[t.measure] ?? t.measure}</td>
                  <td>
                    {t.value} / {t.reference}
                  </td>
                  <td>{formatP(t.p_holm)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {report.problems.map((problem) => (
            <p className="footnote" key={problem}>
              ⚠ {problem}
            </p>
          ))}
          <button
            onClick={() =>
              save("comparison.md", report.markdown, "text/markdown")
            }
          >
            Report (Markdown) ↓
          </button>
          <button
            onClick={() => save("result_rows.csv", rowsCsv(rows), "text/csv")}
          >
            Rows (CSV) ↓
          </button>
        </>
      )}
    </section>
  );
}
