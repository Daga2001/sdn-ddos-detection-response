import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

// A small network with three attackers' worth of room: h1..h5 on one switch.
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
): Promise<{ started: unknown[] }> {
  const captured: { started: unknown[] } = { started: [] };
  let optionRequests = 0;
  // A live event stream that stays open, so the workspace reports "Runner connected".
  await page.addInitScript(() => {
    class OpenStream {
      listeners: Record<string, ((event: { data: string }) => void)[]> = {};
      onerror: (() => void) | null = null;
      constructor() {
        setTimeout(() => {
          for (const listener of this.listeners["status"] ?? [])
            listener({ data: JSON.stringify({ state: "idle", run_id: null }) });
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
  await quick.selectOption("llm:gemma2:2b");
  await inspectorTab(page, "Detection").click();
  await expect(page.getByRole("combobox", { name: /^Model/ })).toHaveValue(
    "gemma2:2b",
  );
  await page.getByRole("button", { name: /^Entropy/ }).click();
  await expect(quick).toHaveValue("entropy");
  await expect(
    page.getByRole("spinbutton", { name: /^Band width/ }),
  ).toBeVisible();
  // The baseline is shorter than the warm-up: the tab says so.
  await expect(page.getByText(/needs about 40 s of baseline/)).toBeVisible();
  await page.getByRole("button", { name: /^No detection/ }).click();
  await expect(quick).toHaveValue("off");
  await expect(
    page.getByRole("spinbutton", { name: /^Band width/ }),
  ).toHaveCount(0);
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
  await inspectorTab(page, "History").click();
  await expect(
    page.getByText("LLM gemma2:2b · 2 attackers · escalate (real rules)"),
  ).toBeVisible();
  await page.getByRole("button", { name: "Replay" }).click();
  await page.getByLabel("Replay position", { exact: true }).fill("9");
  await observationTab(page, "Detection").click();
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

test("results are not invented before anything has run", async ({ page }) => {
  await mockLab(page);
  await observationTab(page, "Detection").click();
  await expect(
    page.getByText("Detection results appear with an experiment."),
  ).toBeVisible();
  await expect(
    page.getByLabel("False negative 1", { exact: true }),
  ).toHaveCount(0);
});
