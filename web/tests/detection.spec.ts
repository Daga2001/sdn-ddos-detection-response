import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

// A small network with three attackers' worth of room: h1..h5 on one switch.

async function chooseForwarding(
  page: Page,
  which: "per_port" | "port_free" = "per_port",
) {
  const name = which === "per_port" ? /Per-port rules/ : /Port-free rules/;
  await page.getByRole("radio", { name }).check();
}

const topology = {
  version: 1,
  name: "Detection test network",
  description: "Five hosts and one switch.",
  switches: [{ name: "s1", dpid: 1, position: { x: 270, y: 40 } }],
  hosts: [1, 2, 3, 4, 5].map((i) => ({
    name: `h${i}`,
    ip: `10.0.0.${i}/24`,
    position: { x: 30 + (i - 1) * 140, y: 260 },
  })),
  links: [1, 2, 3, 4, 5].map((i) => ({
    id: `link-h${i}`,
    source: "s1",
    target: `h${i}`,
    bandwidth_mbps: null,
    delay_ms: 0,
    loss_percent: 0,
  })),
};

const settings = {
  attackers: ["h1", "h2"],
  victims: ["h3"],
  traffic: ["syn"],
  rate: 300,
  duration: 60,
  baseline: 30,
  recovery: 20,
  mitigation: true,
  confirm_isolated_lab: true,
  detection: {
    mode: "llm",
    model: "gemma2:2b",
    prompt: "lab",
    llm_max_samples: 1,
    threshold: 0.8,
    response: { policy: "escalate", dry_run: false },
  },
};

let seq = 0;
const at = (second: number) =>
  new Date(Date.UTC(2026, 9, 9, 1, 0, second)).toISOString();
const event = (
  second: number,
  kind: string,
  data: Record<string, unknown>,
) => ({
  run_id: "record",
  seq: ++seq,
  ts: at(second),
  kind,
  data,
});
function recordedEvents() {
  seq = 0;
  return [
    event(0, "phase", { state: "baseline" }),
    event(30, "phase", { state: "attack" }),
    event(30, "attack_started", {}),
    event(38, "detection", { ipv4_src: "10.0.0.1", probability: 0.98 }),
    event(50, "detection", { ipv4_src: "10.0.0.4", probability: 0.9 }),
    event(40, "mitigation_requested", {
      ipv4_src: "10.0.0.1",
      action: "rate_limit_50pps",
    }),
    event(90, "attack_stopped", {}),
    event(90, "phase", { state: "recovery" }),
    event(110, "phase", { state: "completed" }),
    ...entropyWindows(),
  ];
}

// What the entropy detector reported while it learned, saw normal traffic, then a flood.
const entropyConfig = {
  measure: "shannon",
  order: 2,
  center: "median",
  spread: "mad",
  history: 0,
  context: "all",
  k: 2.5,
};
const panel = (shannon: number) => ({
  src: {
    shannon,
    norm: 0.9,
    renyi2: 1.3,
    renyi10: 1.1,
    tsallis2: 0.6,
    min: 1,
    distinct: 3,
  },
  dst: {
    shannon: 0.2,
    norm: 0.1,
    renyi2: 0.1,
    renyi10: 0.1,
    tsallis2: 0.05,
    min: 0.1,
    distinct: 1,
  },
});
const signal = (value: number, band: number[] | null, out = false) => ({
  value,
  lower: band ? band[0] : null,
  upper: band ? band[1] : null,
  center: band ? (band[0] + band[1]) / 2 : null,
  spread: band ? 0.1 : null,
  out,
});
function entropyWindows() {
  const window = (
    second: number,
    n: number,
    state: string,
    value: number,
    band: number[] | null,
    streak: number,
  ) =>
    event(second, "entropy_window", {
      window: n,
      state,
      total_rate: state === "alarm" ? 1520 : 31,
      pairs: 4,
      flow_rules: 30 + n,
      switches: 1,
      streak,
      needed: 2,
      measure: "shannon",
      center_kind: "median",
      config: entropyConfig,
      signals: {
        src: signal(value, band, state === "suspicious" || state === "alarm"),
        dst: signal(0.2, band && [0, 1]),
      },
      panel: panel(value),
      top_src: [["10.0.0.1", 900]],
      top_dst: [["10.0.0.3", 910]],
      top_dport: [],
    });
  return [
    window(111, 1, "warmup", 1.5, null, 0),
    window(112, 2, "normal", 1.52, [1.2, 1.8], 0),
    window(113, 3, "suspicious", 0.4, [1.2, 1.8], 1),
    window(114, 4, "alarm", 0.3, [1.2, 1.8], 2),
  ];
}

const options = {
  available: true,
  current: {
    mode: "llm",
    model: "llama3.2:3b",
    prompt: "lab",
    response: "block",
    dry_run: true,
    entropy: { k: 3, warmup_windows: 8, consecutive_windows: 2 },
  },
  models: ["llama3.2:3b", "gemma2:2b", "qwen2.5:3b"],
};

async function mockLab(
  page: Page,
  detector: unknown = options,
  failFirst = false,
  status: Record<string, unknown> = { state: "idle", run_id: null },
): Promise<{ started: unknown[] }> {
  const captured: { started: unknown[] } = { started: [] };
  let optionRequests = 0;
  // A live event stream that stays open, so the workspace reports "Runner connected".
  await page.addInitScript((initial) => {
    class OpenStream {
      listeners: Record<string, ((event: { data: string }) => void)[]> = {};
      onerror: (() => void) | null = null;
      constructor() {
        setTimeout(() => {
          for (const listener of this.listeners["status"] ?? [])
            listener({ data: JSON.stringify(initial) });
        }, 0);
      }
      addEventListener(
        type: string,
        listener: (event: { data: string }) => void,
      ) {
        (this.listeners[type] ??= []).push(listener);
      }
      close() {}
    }
    (window as unknown as { EventSource: unknown }).EventSource = OpenStream;
  }, status);
  await page.routeWebSocket("**/api/ownership", (socket) => {
    socket.send(
      JSON.stringify({ owner_id: "12345678-1234-4234-8234-123456789abc" }),
    );
  });
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.slice(4);
    const method = route.request().method();
    let response: unknown = {};
    if (path === "/session")
      response = { authenticated: method === "POST" || true };
    else if (path === "/presets")
      response = [{ ...topology, name: "Other" }, topology];
    else if (path === "/projects") response = [];
    else if (path === "/runs" && method === "POST") {
      captured.started.push(route.request().postDataJSON());
      response = { run_id: "record" };
    } else if (path === "/runs")
      response = [
        {
          id: "record",
          name: topology.name,
          status: "completed",
          started_at: at(0),
          detector_mode: "llm",
          detector_model: "gemma2:2b",
          attackers: 2,
          mitigation: "true",
          policy: "escalate",
          dry_run: "false",
        },
      ];
    else if (path === "/runs/record")
      response = { id: "record", topology, status: "completed", settings };
    else if (path === "/runs/record/events")
      response = url.searchParams.get("after") === "0" ? recordedEvents() : [];
    else if (path === "/status") response = { state: "idle", run_id: null };
    else if (path === "/detection/options") {
      if (failFirst && ++optionRequests === 1) {
        await route.fulfill({ status: 502, json: { detail: "restarting" } });
        return;
      }
      response = detector;
    } else if (path === "/events") {
      await route.fulfill({
        contentType: "text/event-stream",
        body:
          "event: status\ndata: " +
          JSON.stringify({ state: "idle", run_id: null }) +
          "\n\n",
      });
      return;
    }
    await route.fulfill({ json: response });
  });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: topology.name }),
  ).toBeVisible();
  return captured;
}

const inspectorTab = (page: Page, name: string) =>
  page
    .locator("aside.inspector nav.tabs")
    .getByRole("button", { name, exact: true });
const observationTab = (page: Page, name: string) =>
  page
    .locator("section.observations nav.tabs")
    .getByRole("button", { name, exact: true });

test("the detector can be switched from the top bar and from the Detection tab", async ({
  page,
}) => {
  await mockLab(page);
  const quick = page.getByLabel("Detector", { exact: true });
  // It starts from what the detector service is set to.
  await expect(quick).toHaveValue("llm:llama3.2:3b");
  await observationTab(page, "Results").click();
  await quick.selectOption("llm:gemma2:2b");
  await inspectorTab(page, "Detection").click();
  await expect(page.getByRole("combobox", { name: /^Model/ })).toHaveValue(
    "gemma2:2b",
  );
  await page.getByRole("button", { name: /^Entropy/ }).click();
  await expect(quick).toHaveValue("entropy");
  await expect(quick.locator("option:checked")).toHaveText("Entropy · Shannon");
  // Results is one tab for every detector: switching does not hide it.
  await expect(observationTab(page, "Results")).toHaveClass("active");
  for (const [measure, name] of [
    ["renyi", "Rényi"],
    ["tsallis", "Tsallis"],
    ["norm", "Normalised Shannon"],
    ["min", "Min-entropy"],
  ]) {
    await page
      .getByRole("combobox", { name: /^Entropy measure/ })
      .selectOption(measure);
    await expect(quick.locator("option:checked")).toHaveText(
      `Entropy · ${name}`,
    );
  }
  await expect(
    page.getByRole("spinbutton", { name: /^Band width/ }),
  ).toBeVisible();
  // The baseline is shorter than the warm-up: the tab says so.
  await expect(page.getByText(/needs about 40 s of baseline/)).toBeVisible();
  await page.getByRole("button", { name: /^No detection/ }).click();
  await expect(quick).toHaveValue("off");
  await expect(observationTab(page, "Results")).toHaveClass("active");
  await expect(
    page.getByRole("spinbutton", { name: /^Band width/ }),
  ).toHaveCount(0);
  await quick.selectOption("llm:gemma2:2b");
  await expect(observationTab(page, "Results")).toHaveClass("active");
  await expect(observationTab(page, "Detection")).toHaveCount(0);
});

test("the detection setup is sent with the experiment so it is saved with the run", async ({
  page,
}) => {
  const lab = await mockLab(page);
  await inspectorTab(page, "Detection").click();
  await page
    .getByRole("combobox", { name: /^Model/ })
    .selectOption("qwen2.5:3b");
  await page.getByRole("spinbutton", { name: /^Samples per poll/ }).fill("2");
  await page.getByRole("checkbox", { name: /Apply a response/ }).check();
  // A simulation first: no warning about real rules.
  await expect(page.getByText("Real rules will be installed")).toHaveCount(0);
  await page.getByRole("checkbox", { name: /Simulation only/ }).uncheck();
  await expect(page.getByText("Real rules will be installed")).toBeVisible();
  // Acting only on a source flagged twice shows its time window.
  await page.getByRole("spinbutton", { name: /^Detections needed/ }).fill("2");
  await page.getByRole("spinbutton", { name: /^Poll every/ }).fill("2");
  await expect(page.getByRole("spinbutton", { name: /^Within/ })).toBeVisible();
  await inspectorTab(page, "Experiment").click();
  await page.getByLabel(/I confirm these hosts/).check();
  await chooseForwarding(page);
  await page.getByRole("button", { name: "Start experiment" }).click();
  await expect.poll(() => lab.started.length).toBe(1);
  const sent = lab.started[0] as {
    experiment: {
      mitigation: boolean;
      detection: {
        mode: string;
        model: string;
        llm_max_samples: number;
        poll_seconds: number;
        response: { dry_run: boolean; confirm_hits: number };
      };
    };
  };
  expect(sent.experiment.mitigation).toBe(true);
  expect(sent.experiment.detection).toMatchObject({
    mode: "llm",
    model: "qwen2.5:3b",
    llm_max_samples: 2,
    poll_seconds: 2,
    response: { dry_run: false, confirm_hits: 2 },
  });
});

test("turning detection off also turns the response off", async ({ page }) => {
  await mockLab(page);
  await inspectorTab(page, "Detection").click();
  await page.getByRole("checkbox", { name: /Apply a response/ }).check();
  await page.getByRole("button", { name: /^No detection/ }).click();
  await expect(
    page.getByRole("checkbox", { name: /Apply a response/ }),
  ).toHaveCount(0);
  // Back on an LLM, the response is still off: nothing is applied by accident.
  await page.getByRole("button", { name: /^LLM/ }).click();
  await expect(
    page.getByRole("checkbox", { name: /Apply a response/ }),
  ).not.toBeChecked();
});

test("without a detector service the choice is unavailable and says why", async ({
  page,
}) => {
  await mockLab(page, {
    available: false,
    reason: "this lab was started without a detector service",
  });
  await expect(page.getByLabel("Detector", { exact: true })).toBeDisabled();
  await inspectorTab(page, "Detection").click();
  await expect(
    page.getByText("This lab has no detector service to configure."),
  ).toBeVisible();
});

test("a detector that was unreachable at load comes back without a reload", async ({
  page,
}) => {
  await mockLab(page, options, true);
  // Nothing is clicked: the workspace asks again by itself.
  await expect(page.getByLabel("Detector", { exact: true })).toBeDisabled();
  await expect(page.getByLabel("Detector", { exact: true })).toBeEnabled({
    timeout: 15000,
  });
});

test("a replay scores the detector against the experiment's ground truth", async ({
  page,
}) => {
  await mockLab(page);
  await page.getByLabel("Detector", { exact: true }).selectOption("off");
  await inspectorTab(page, "History").click();
  await expect(
    page.getByText("LLM gemma2:2b · 2 attackers · escalate (real rules)"),
  ).toBeVisible();
  await page.getByRole("button", { name: "Replay" }).click();
  await page.getByLabel("Replay position", { exact: true }).fill("9");
  await observationTab(page, "Results").click();
  // h1 detected (VP), h2 missed (FN), h4 wrongly flagged (FP), h5 untouched (VN).
  await expect(
    page.getByLabel("True positive 1", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByLabel("False negative 1", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByLabel("False positive 1", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByLabel("True negative 1", { exact: true }),
  ).toBeVisible();
  await expect(page.locator(".criteria")).toContainText("gemma2:2b");
  await expect(page.getByText("rate_limit_50pps").first()).toBeVisible();
  // The setup recorded with the run is shown, read-only, in the Detection tab.
  await inspectorTab(page, "Detection").click();
  await expect(page.getByRole("combobox", { name: /^Model/ })).toBeDisabled();
  // Nothing in a recorded setup can be toggled, checkboxes included.
  await expect(
    page.getByRole("checkbox", { name: /Apply a response/ }),
  ).toBeDisabled();
});

const metricValue = (page: Page, key: string) =>
  page.locator(`[data-metric="${key}"] dd`);

for (const mode of ["llm", "entropy", "off"]) {
  test(`the Results tab gathers a replay's numbers in one place (${mode})`, async ({
    page,
  }) => {
    await mockLab(page);
    await page.route("**/api/runs/record", (route) =>
      route.fulfill({
        json: {
          id: "record",
          topology,
          status: "completed",
          settings: {
            ...settings,
            detection: { ...settings.detection, mode },
          },
        },
      }),
    );
    await inspectorTab(page, "History").click();
    await page.getByRole("button", { name: "Replay" }).click();
    // A replay's results use its full record, wherever the replay cursor is.
    await page.getByLabel("Replay position", { exact: true }).fill("2");
    await observationTab(page, "Results").click();
    const results = page.locator(".results-view");
    await expect(results.getByText("RECORDED RUN · FULL RECORD")).toBeVisible();
    for (const title of [
      "How well it detected",
      "What each decision cost",
      "Effect on legitimate users",
      "Network and control plane",
      "Response",
      "Recovery",
      "What was tested",
    ])
      await expect(
        results.getByRole("region", { name: title, exact: true }),
      ).toBeVisible();
    if (mode === "off") {
      await expect(results.getByText(/No detector ran/)).toBeVisible();
      // Metrics that cannot exist without a detector are listed once.
      await expect(
        results.getByRole("region", { name: "How well it detected" }),
      ).toContainText("Does not apply to this run: Detection rate (recall)");
    } else {
      // h1 named 8 s into the attack, h2 never; h4 (legitimate) named once.
      await expect(metricValue(page, "detection_rate")).toHaveText("50 %");
      await expect(metricValue(page, "false_alarm_rate")).toHaveText("50 %");
      await expect(metricValue(page, "mean_detection")).toHaveText("8 s");
      if (mode === "entropy")
        await expect(
          results.getByRole("region", { name: "How well it detected" }),
        ).toContainText(/Does not apply to this run: .*Brier score/);
      else
        await expect(metricValue(page, "brier")).toContainText(
          "no judged flows",
        );
    }
    await expect(metricValue(page, "response_time")).toHaveText("10 s");
    await expect(metricValue(page, "detector")).toHaveText(mode);
    // This record has no cost data: it says so instead of a zero.
    if (mode !== "off")
      await expect(metricValue(page, "decisions")).toContainText(
        "no cost data reached the lab",
      );
    const download = page.waitForEvent("download");
    await results
      .getByRole("button", { name: "Download results row (CSV)" })
      .click();
    const file = await download;
    expect(file.suggestedFilename()).toBe(`results-${mode}-record-row.csv`);
    const text = await (await file.createReadStream()).toArray();
    const [header, row] = Buffer.concat(text).toString().split("\n");
    expect(header.startsWith("run_id,started_utc,topology,detector,")).toBe(
      true,
    );
    expect(header.split(",")).toContain("detection_rate_pct");
    expect(row.split(",")[0]).toBe("record");
  });
}

test("a finished run's results are read again from its full record", async ({
  page,
}) => {
  await mockLab(page, options, false, {
    state: "idle",
    run_id: "record",
    runner_instance_id: "runner",
  });
  // Registered last, so it sees the requests first and passes them on.
  let reads = 0;
  await page.route("**/api/runs/record/events**", (route) => {
    reads += 1;
    return route.fallback();
  });
  await observationTab(page, "Results").click();
  await expect(page.getByText("FINAL RESULT · FULL RECORD")).toBeVisible();
  await expect(metricValue(page, "detection_rate")).toHaveText("50 %");
  // This old record has no website checks, so the tab warns against counting it.
  await expect(
    page.getByText("Do not count this run in the results."),
  ).toBeVisible();
  await expect(
    page.getByText("No website checks were recorded during the attack."),
  ).toBeVisible();
  expect(reads).toBeGreaterThan(0);
});

test("results are not invented before anything has run", async ({ page }) => {
  await mockLab(page);
  await observationTab(page, "Results").click();
  await expect(
    page.getByText("Results appear once an experiment's attack starts."),
  ).toBeVisible();
  await expect(
    page.getByLabel("False negative 1", { exact: true }),
  ).toHaveCount(0);
});

test("the entropy measure and the threshold model are sent with the experiment", async ({
  page,
}) => {
  const lab = await mockLab(page);
  await inspectorTab(page, "Detection").click();
  await page.getByRole("button", { name: /^Entropy/ }).click();
  await page
    .getByRole("combobox", { name: /^Entropy measure/ })
    .selectOption("renyi");
  await page.getByRole("spinbutton", { name: /^Order/ }).fill("10");
  await page
    .getByRole("combobox", { name: /^Threshold centre/ })
    .selectOption("median");
  await page.getByRole("combobox", { name: /^Spread/ }).selectOption("mad");
  await page.getByRole("spinbutton", { name: /^History/ }).fill("40");
  await page.getByRole("combobox", { name: /^Learn from/ }).selectOption("all");
  await page
    .getByRole("checkbox", { name: /Also watch destination ports/ })
    .check();
  await inspectorTab(page, "Experiment").click();
  await page.getByLabel(/I confirm these hosts/).check();
  await chooseForwarding(page);
  await page.getByRole("button", { name: "Start experiment" }).click();
  await expect.poll(() => lab.started.length).toBe(1);
  const sent = lab.started[0] as {
    experiment: {
      detection: { mode: string; entropy: Record<string, unknown> };
    };
  };
  expect(sent.experiment.detection.mode).toBe("entropy");
  expect(sent.experiment.detection.entropy).toMatchObject({
    measure: "renyi",
    order: 10,
    center: "median",
    spread: "mad",
    history: 40,
    context: "all",
    watch_ports: true,
    watch_protocols: false,
  });
});

test("the spread and history only apply to the models that use them", async ({
  page,
}) => {
  await mockLab(page);
  await inspectorTab(page, "Detection").click();
  await page.getByRole("button", { name: /^Entropy/ }).click();
  // The original EWMA has neither a history nor a choice of spread.
  await expect(
    page.getByRole("spinbutton", { name: /^History/ }),
  ).toBeDisabled();
  await expect(page.getByRole("combobox", { name: /^Spread/ })).toBeDisabled();
  await expect(page.getByRole("spinbutton", { name: /^Order/ })).toHaveCount(0);
  await page
    .getByRole("combobox", { name: /^Threshold centre/ })
    .selectOption("mean");
  await expect(
    page.getByRole("spinbutton", { name: /^History/ }),
  ).toBeEnabled();
  await expect(page.getByRole("combobox", { name: /^Spread/ })).toBeEnabled();
  await page
    .getByRole("combobox", { name: /^Threshold centre/ })
    .selectOption("yu");
  await expect(page.getByRole("combobox", { name: /^Spread/ })).toBeDisabled();
});

test("the Threshold tab shows every window, its band and the verdict", async ({
  page,
}) => {
  await mockLab(page);
  await inspectorTab(page, "History").click();
  await page.getByRole("button", { name: "Replay" }).click();
  await page.getByLabel("Replay position", { exact: true }).fill("13");
  await observationTab(page, "Threshold").click();
  await expect(page.locator(".entropy-summary")).toContainText(
    "Centre: rolling median",
  );
  await expect(page.locator(".entropy-summary")).toContainText(
    "Learns from: every window",
  );
  await expect(page.locator(".entropy-chart canvas")).toBeVisible();
  const rows = page.locator(".entropy-log tbody tr");
  await expect(rows).toHaveCount(4);
  // Latest first: the alarm; its value is outside the band.
  await expect(rows.first().locator(".state-badge")).toHaveText("alarm");
  await expect(rows.first()).toContainText("0.300 [1.20 – 1.80]");
  await expect(rows.first().locator("td.outside")).toHaveCount(1);
  await expect(rows.last().locator(".state-badge")).toHaveText("warmup");
  await expect(rows.first()).toContainText("10.0.0.1 900");
  // The other entropies of the same window, for comparison.
  await expect(
    page.getByRole("row", { name: /Rényi α=10/ }).first(),
  ).toContainText("1.100");
  await page.locator(".entropy-controls select").nth(1).selectOption("renyi10");
  await expect(page.locator(".entropy-chart canvas")).toBeVisible();
  // The Timeline keeps only the windows that mattered.
  await observationTab(page, "Timeline").click();
  await expect(
    page.locator(".timeline strong", { hasText: "entropy window" }),
  ).toHaveCount(2);
});

test("the Threshold tab says what to do before the detector has reported", async ({
  page,
}) => {
  await mockLab(page);
  await observationTab(page, "Threshold").click();
  await expect(
    page.getByText("The entropy detector has not reported yet."),
  ).toBeVisible();
});

test("forwarding rules can stop matching ports, and the choice is sent with the run", async ({
  page,
}) => {
  const lab = await mockLab(page);
  await inspectorTab(page, "Detection").click();
  await page.getByRole("button", { name: /^Entropy/ }).click();
  await expect(
    page.getByRole("checkbox", { name: /Match ports in forwarding rules/ }),
  ).toHaveCount(0);
  await chooseForwarding(page, "port_free");
  await inspectorTab(page, "Experiment").click();
  await page.getByLabel(/I confirm these hosts/).check();
  await page.getByRole("button", { name: "Start experiment" }).click();
  await expect.poll(() => lab.started.length).toBe(1);
  const sent = lab.started[0] as { forwarding: string };
  expect(sent.forwarding).toBe("port_free");
  expect(JSON.stringify(sent)).not.toContain("match_ports");
});

test("the fast-reaction preset sets the whole setup in one click, and Original undoes it", async ({
  page,
}) => {
  await mockLab(page);
  await inspectorTab(page, "Detection").click();
  await page.getByRole("button", { name: /^Entropy/ }).click();
  await page
    .getByRole("button", { name: "Fast reaction", exact: true })
    .click();
  const field = (name: RegExp) => page.getByRole("spinbutton", { name });
  await expect(field(/^Window · seconds/)).toHaveValue("1");
  await expect(field(/^Poll every/)).toHaveValue("0.5");
  await expect(field(/^Warm-up windows/)).toHaveValue("30");
  await expect(
    page.getByRole("combobox", { name: /^Entropy measure/ }),
  ).toHaveValue("norm");
  await page.getByRole("button", { name: "Original", exact: true }).click();
  await expect(field(/^Window · seconds/)).toHaveValue("5");
  await expect(field(/^Poll every/)).toHaveValue("5");
  await expect(field(/^Warm-up windows/)).toHaveValue("16");
});

test("the destination-entropy and pair-entropy presets are one click away and their settings are sent with the run", async ({
  page,
}) => {
  const lab = await mockLab(page);
  await inspectorTab(page, "Detection").click();
  await page.getByRole("button", { name: /^Entropy/ }).click();
  const decided = page.getByRole("combobox", { name: /^Alarm decided by/ });
  const pairs = page.getByRole("checkbox", {
    name: /Also watch source–destination pairs/,
  });
  await expect(decided).toHaveValue("all");
  await expect(pairs).not.toBeChecked();
  await expect(page.getByRole("spinbutton", { name: /^Margin/ })).toHaveCount(
    0,
  );

  await page
    .getByRole("button", { name: "Destination entropy", exact: true })
    .click();
  await expect(
    page.getByRole("combobox", { name: /^Threshold centre/ }),
  ).toHaveValue("ewma_margin");
  await expect(decided).toHaveValue("dst");
  await expect(page.getByRole("spinbutton", { name: /^Margin/ })).toHaveValue(
    "0.01",
  );
  await expect(
    page.getByRole("spinbutton", { name: /^Consecutive windows/ }),
  ).toHaveValue("1");

  await page.getByRole("button", { name: "Pair entropy", exact: true }).click();
  await expect(
    page.getByRole("combobox", { name: /^Threshold centre/ }),
  ).toHaveValue("ewma2");
  await expect(decided).toHaveValue("pair");
  await expect(pairs).toBeChecked();
  await expect(
    page.getByRole("spinbutton", { name: /^No-decrease rate/ }),
  ).toHaveValue("800");
  await expect(
    page.getByRole("spinbutton", { name: /^Band width/ }),
  ).toHaveValue("4");
  // Pairs cannot decide when they are not watched.
  await pairs.uncheck();
  await expect(decided).toHaveValue("all");

  await pairs.check();
  await decided.selectOption("pair");
  await inspectorTab(page, "Experiment").click();
  await page.getByLabel(/I confirm these hosts/).check();
  await chooseForwarding(page);
  await page.getByRole("button", { name: "Start experiment" }).click();
  await expect.poll(() => lab.started.length).toBe(1);
  const sent = lab.started[0] as {
    experiment: { detection: { entropy: Record<string, unknown> } };
  };
  expect(sent.experiment.detection.entropy).toMatchObject({
    measure: "norm",
    center: "ewma2",
    alpha: 0.1,
    k: 4,
    watch_pairs: true,
    decide: ["pair"],
    rate_threshold: 800,
  });
});

test("the calibrated destination-entropy preset sets the values chosen by replay", async ({
  page,
}) => {
  const lab = await mockLab(page);
  await inspectorTab(page, "Detection").click();
  await page.getByRole("button", { name: /^Entropy/ }).click();
  await page
    .getByRole("button", {
      name: "Destination entropy (calibrated)",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("combobox", { name: /^Threshold centre/ }),
  ).toHaveValue("median");
  await expect(
    page.getByRole("combobox", { name: /^Alarm decided by/ }),
  ).toHaveValue("dst");
  await expect(
    page.getByRole("spinbutton", { name: /^Consecutive windows/ }),
  ).toHaveValue("1");
  await inspectorTab(page, "Experiment").click();
  await page.getByLabel(/I confirm these hosts/).check();
  await chooseForwarding(page);
  await page.getByRole("button", { name: "Start experiment" }).click();
  await expect.poll(() => lab.started.length).toBe(1);
  const sent = lab.started[0] as {
    experiment: {
      detection: { poll_seconds: number; entropy: Record<string, unknown> };
    };
  };
  expect(sent.experiment.detection.poll_seconds).toBe(0.5);
  expect(sent.experiment.detection.entropy).toMatchObject({
    measure: "min",
    center: "median",
    spread: "mad",
    k: 5,
    context: "normal",
    window_seconds: 1,
    warmup_windows: 30,
    consecutive_windows: 1,
    candidate_min_rate: 50,
    candidate_share: 0.3,
    decide: ["dst"],
  });
});
