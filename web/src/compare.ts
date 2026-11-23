// Many-run comparison in the workspace: the rows come from the Results tab's code, the
// statistics from the lab service (sdn_ddos.analysis.compare, the code behind
// scripts/compare_runs.py), so the browser and the command line give the same report.
import { resultRow, runResults } from "./results.ts";
import { normalizeExperiment } from "./types.ts";
import type { Observation, Run } from "./types.ts";

/** A Results-tab row as column name -> value. */
export type ResultRow = Record<string, string>;

/**
 * The columns the comparison reads (scripts/compare_runs.py). Only these are sent to
 * the lab service, which keeps 180 runs far below its 1 MiB request limit.
 */
export const COMPARE_COLUMNS = [
  "run_id",
  "purpose",
  "valid",
  "validity_notes",
  "started_utc",
  "settings_fingerprint",
  "scenario",
  "forwarding",
  "detector",
  "response",
  "traffic",
  "attackers",
  "rate_per_s",
  "tp",
  "fn",
  "fp",
  "tn",
  "first_detection_s",
  "mean_detection_s",
  "early_detection_rate_pct",
  "time_per_decision_median_ms",
  "time_per_decision_p95_ms",
  "detector_cpu_per_decision_ms",
  "decisions_per_s_attack_per_s",
  "detector_ram_peak_mib",
  "ryu_cpu_attack_pct",
  "availability_attack_pct",
  "request_time_median_attack_ms",
  "ping_loss_attack_pct",
  "time_to_first_failure_s",
  "packet_in_handled_attack_per_s",
  "flow_rules_peak_attack",
  "response_time_s",
  "service_recovery_s",
  "controller_recovery_s",
] as const;

/**
 * The row the Results tab would download for one recorded run, or null when the run
 * has no attack (nothing to score). Same steps as web/scripts/result_rows.ts.
 */
export function rowFromRecord(
  run: Run | null | undefined,
  events: Observation[],
): ResultRow | null {
  const sorted = [...events].sort(
    (a, b) => Date.parse(a.ts) - Date.parse(b.ts) || a.seq - b.seq,
  );
  const experiment = run?.settings ? normalizeExperiment(run.settings) : null;
  const results = runResults({
    events: sorted,
    topology: run?.topology ?? null,
    experiment: experiment?.attackers.length ? experiment : null,
    run: run ?? undefined,
    active: false,
  });
  if (!results) return null;
  return Object.fromEntries(resultRow(results));
}

/** Only the columns the comparison reads; a missing column becomes "". */
export function slim(row: ResultRow): ResultRow {
  return Object.fromEntries(
    COMPARE_COLUMNS.map((name) => [name, row[name] ?? ""]),
  );
}

/** RFC 4180 records (quoted fields, doubled quotes, CR LF or LF line ends). */
export function parseCsv(text: string): string[][] {
  const records: string[][] = [];
  let record: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ",") {
      record.push(field);
      field = "";
    } else if (char === "\n" || char === "\r") {
      if (char === "\r" && text[i + 1] === "\n") i++;
      record.push(field);
      records.push(record);
      record = [];
      field = "";
    } else field += char;
  }
  if (quoted) throw new Error("The CSV file ends inside a quoted field.");
  if (field !== "" || record.length) {
    record.push(field);
    records.push(record);
  }
  return records;
}

/**
 * Results-row CSV (one file from the Results tab, or several stacked: a header line
 * starting with run_id may repeat) to rows.
 */
export function rowsFromCsv(text: string, name = "file"): ResultRow[] {
  const rows: ResultRow[] = [];
  let header: string[] | null = null;
  for (const record of parseCsv(text)) {
    if (!record.length || record.every((cell) => cell === "")) continue;
    if (record[0] === "run_id") {
      header = record;
      continue;
    }
    if (!header)
      throw new Error(
        `${name}: this is not a results-row CSV (its first line must start with run_id). Download it with the Results tab's “results row” button.`,
      );
    rows.push(
      Object.fromEntries(header.map((column, i) => [column, record[i] ?? ""])),
    );
  }
  return rows;
}

/** Later rows replace earlier ones with the same run_id: a run is counted once. */
export function mergeRows(...groups: ResultRow[][]): ResultRow[] {
  const byId = new Map<string, ResultRow>();
  for (const group of groups)
    for (const row of group) byId.set(row.run_id, row);
  return [...byId.values()];
}

export type Verdict = {
  scenario: string;
  detector: string;
  detection_rate_vs_rule: string;
  false_alarm_rate_vs_rule: string;
  mean_detection_s: number | null;
  detection_within_limit: string;
  availability_vs_no_defense: string;
};

export type CriteriaTest = {
  scenario: string;
  detector: string;
  measure: string;
  value: string;
  reference: string;
  p_value: number;
  p_holm: number;
  significant: boolean;
};

export type Comparison = {
  markdown: string;
  verdicts: Verdict[];
  tests: CriteriaTest[];
  cells: number;
  runs: number;
  excluded: [string, string][];
  problems: string[];
  alpha: number;
  detection_limit_s: number;
};

/** `p` as the report prints it: below 0.001 as "<0.001", otherwise 3 significant digits. */
export function formatP(p: number): string {
  if (p < 0.001) return "<0.001";
  return Number(p.toPrecision(3)).toString();
}

/** The rows as one CSV, ready for scripts/compare_runs.py. */
export function rowsCsv(rows: ResultRow[]): string {
  const quote = (text: string) =>
    /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  const lines = [COMPARE_COLUMNS.join(",")];
  for (const row of rows)
    lines.push(COMPARE_COLUMNS.map((name) => quote(row[name] ?? "")).join(","));
  return lines.join("\n") + "\n";
}
