import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

const topology = {
  version: 1,
  name: "Small teaching network",
  description: "Three hosts and one switch.",
  switches: [{ name: "s1", dpid: 1, position: { x: 270, y: 40 } }],
  hosts: [1, 2, 3].map((i) => ({
    name: `h${i}`,
    ip: `10.0.0.${i}/24`,
    position: { x: 30 + (i - 1) * 240, y: 260 },
  })),
  links: [1, 2, 3].map((i) => ({
    id: `link-${i}`,
    source: "s1",
    target: `h${i}`,
    bandwidth_mbps: null,
    delay_ms: 0,
    loss_percent: 0,
  })),
};
const recorded = [
  {
    run_id: "record",
    seq: 1,
    ts: "2026-09-24T10:00:00Z",
    kind: "phase",
    data: { state: "baseline" },
  },
  {
    run_id: "record",
    seq: 2,
    ts: "2026-09-24T10:00:01Z",
    kind: "links",
    data: {
      links: [{ link_id: "link-1", rates: { rx_bps: 12000, tx_bps: 500 } }],
    },
  },
  {
    run_id: "record",
    seq: 3,
    ts: "2026-09-24T09:59:59Z",
    kind: "packets",
    data: {
      items: [
        {
          link_id: "link-1",
          headers: {
            "frame.len": "64",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "tcp.srcport": "1000",
            "tcp.flags": "0x0002",
          },
        },
      ],
    },
  },
  {
    run_id: "record",
    seq: 4,
    ts: "2026-09-24T10:00:03Z",
    kind: "phase",
    data: { state: "completed" },
  },
  {
    run_id: "record",
    seq: 5,
    ts: "2026-09-24T10:00:04Z",
    kind: "error",
    data: {
      message:
        "The lab stopped because a component failed. Check commands and service logs; this run is not successful.",
      detail: "traffic generator on h1a exited with code 127",
    },
  },
];

// The managed controller is drawn beside the topology but is not part of it.
const dataEdges = ".react-flow__edge:not(.control-edge)";
const deviceNodes = '.react-flow__node:not([data-id="__controller__"])';

const calls: string[] = [];

async function mockApi(page: Page, running = false) {
  calls.length = 0;
  const writes: string[] = [];
  let authenticated = false;
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.slice(4);
    const method = route.request().method();
    if (method === "POST") writes.push(path);
    calls.push(`${method} ${path}`);
    let response: unknown = {};
    if (path === "/session") {
      if (method === "POST") authenticated = true;
      response = { authenticated };
    } else if (path === "/presets") {
      if (running) await new Promise((resolve) => setTimeout(resolve, 300));
      response = [{ ...topology, name: "Alternate preset" }, topology];
    } else if (path === "/projects") response = [];
    else if (path === "/runs")
      response = [
        {
          id: "record",
          name: topology.name,
          status: "completed",
          started_at: "2026-09-24T10:00:00Z",
        },
      ];
    else if (path === "/runs/record")
      response = {
        id: "record",
        topology: running
          ? { ...topology, name: "Restored active network" }
          : topology,
        status: running ? "running" : "completed",
      };
    else if (path === "/runs/record/events")
      response = url.searchParams.get("after") === "0" ? recorded : [];
    else if (path === "/events") {
      await route.fulfill({
        contentType: "text/event-stream",
        body:
          "event: status\ndata: " +
          JSON.stringify(
            running
              ? { state: "running", run_id: "record" }
              : { state: "idle", run_id: null },
          ) +
          "\n\n",
      });
      return;
    } else if (path === "/import") {
      await route.fulfill({
        status: 422,
        json: { detail: "Unsupported or malformed topology." },
      });
      return;
    }
    await route.fulfill({ json: response });
  });
  await page.goto("/");
  await page.getByLabel("Local access token").fill("browser-test-token");
  await page.getByRole("button", { name: "Enter workspace" }).click();
  await expect(
    page.getByRole("heading", {
      name: running ? "Restored active network" : topology.name,
    }),
  ).toBeVisible();
  return writes;
}

test("topology workspace edits devices, validates, and keeps experiment confirmation off", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await mockApi(page);
  await expect(
    page.getByRole("button", { name: "Start experiment" }),
  ).toBeDisabled();
  // The mitigation toggle is gone; the traffic-kind picker replaces it.
  await expect(
    page.getByLabel("Enable temporary controller mitigation"),
  ).toHaveCount(0);
  await expect(page.getByText("TCP SYN flood")).toBeVisible();
  // The resource readout names its scope: the Ryu controller process, not the host.
  await expect(page.getByText(/Ryu controller process/)).toBeVisible();
  await page.getByRole("button", { name: "+ Host", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "h4", exact: true }),
  ).toBeVisible();
  await page.getByLabel("IPv4 address / prefix").fill("10.0.0.24/24");
  await page
    .getByRole("button", { name: "Remove device and its links" })
    .click();
  await page.getByRole("button", { name: "Validate topology" }).click();
  await expect(page.getByRole("status")).toContainText("ready to run");
  await expect(page.locator(dataEdges)).toHaveCount(3);
  for (const name of ["s1", "h1", "h2", "h3"]) {
    await expect(
      page.locator(`.react-flow__node[data-id="${name}"]`),
    ).toBeInViewport();
  }
  const device = page.locator('.react-flow__node[data-id="s1"]');
  const before = (await device.boundingBox())!;
  await page.mouse.move(
    before.x + before.width / 2,
    before.y + before.height / 2,
  );
  await page.mouse.down();
  await page.mouse.move(
    before.x + before.width / 2 + 70,
    before.y + before.height / 2 + 20,
    { steps: 10 },
  );
  expect((await device.boundingBox())!.x).toBeGreaterThan(before.x + 40);
  await page.mouse.up();
  await page.screenshot({ path: "test-results/workspace.png", fullPage: true });
  expect(errors).toEqual([]);
});

test("host pickers show a paginated table with host, ip and switch parent", async ({
  page,
}) => {
  await mockApi(page);
  await page.getByRole("button", { name: /Select attackers/ }).click();
  const dialog = page.getByRole("dialog", { name: "Select attackers" });
  await expect(dialog).toBeVisible();
  for (const col of ["Host name", "IP address", "Switch parent"])
    await expect(dialog.getByRole("columnheader", { name: col })).toBeVisible();
  // Every host hangs off s1 in this topology.
  await expect(
    dialog.getByRole("cell", { name: "s1", exact: true }),
  ).toHaveCount(3);
  await expect(dialog).toContainText("Page 1 of 1");
  // h2 is the default victim, so it is locked out of the attacker table.
  await expect(dialog.getByRole("checkbox", { name: "Select h2" })).toHaveCount(
    0,
  );
  await expect(dialog.getByText("1 selected")).toBeVisible();
  await dialog.getByRole("checkbox", { name: "Select h3" }).check();
  await expect(dialog.getByText("2 selected")).toBeVisible();
  await dialog.getByRole("button", { name: "Done" }).click();
  await expect(dialog).toBeHidden();
});

test("replay steps through recorded headers without starting lab traffic", async ({
  page,
}) => {
  const writes = await mockApi(page);
  await page.getByRole("button", { name: "Inspect", exact: true }).click();
  await page.getByLabel("Project name").fill("Unsaved editor draft");
  await page.getByRole("button", { name: "History", exact: true }).click();
  await page.getByRole("button", { name: "Replay", exact: true }).click();
  await expect(
    page.getByText("RECORDED REPLAY · NO TRAFFIC IS SENT"),
  ).toBeVisible();
  await page.getByRole("button", { name: "Step →" }).click();
  await page.getByRole("button", { name: /Packets/ }).click();
  await expect(
    page.getByRole("button", { name: /link-1.*10.0.0.1/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Step →" }).click();
  await page.getByRole("button", { name: "Step →" }).click();
  await page.getByRole("button", { name: /Packets/ }).click();
  await page.getByRole("button", { name: /link-1.*10.0.0.1/ }).click();
  await expect(
    page.getByText('"tcp.flags": "0x0002"', { exact: false }),
  ).toBeVisible();
  // Replaying to the recorded error shows the failure card with the exact reason.
  await page.getByLabel("Replay position").fill("5");
  await expect(page.getByText("This run failed.")).toBeVisible();
  await expect(
    page.getByText("traffic generator on h1a exited with code 127"),
  ).toBeVisible();
  expect(writes).not.toContain("/runs");
  expect(writes).not.toContain("/capture");
  const exported = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download", exact: true }).click();
  const stream = await (await exported).createReadStream();
  let data = "";
  for await (const chunk of stream!) data += chunk;
  expect(JSON.parse(data).name).toBe(topology.name);
  await page.getByRole("button", { name: "Exit", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Unsaved editor draft" }),
  ).toBeVisible();
});

test("invalid imports show the server rejection and preserve the topology", async ({
  page,
}) => {
  await mockApi(page);
  await page.locator("input[type=file]").setInputFiles({
    name: "unsafe.mn",
    mimeType: "application/json",
    buffer: Buffer.from('{"version":"2"}'),
  });
  await expect(page.getByRole("alert")).toContainText(
    "Unsupported or malformed",
  );
  await expect(
    page.getByRole("heading", { name: topology.name }),
  ).toBeVisible();
});

test("reload restores the running topology even when preset loading is slower", async ({
  page,
}) => {
  await mockApi(page, true);
  await expect(
    page.getByRole("button", { name: "+ Host", exact: true }),
  ).toBeDisabled();
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Restored active network" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Refresh records" }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "History", exact: true }).click();
  // Busy clears only once the slower bootstrap has completed.
  await expect(
    page.getByRole("button", { name: "Refresh records" }),
  ).toBeEnabled();
  await expect(
    page.getByRole("heading", { name: "Restored active network" }),
  ).toBeVisible();
});

test("several devices are selected together and removed in one action", async ({
  page,
}) => {
  await mockApi(page);
  await page.locator('.react-flow__node[data-id="h1"]').click();
  await expect(
    page.getByRole("heading", { name: "h1", exact: true }),
  ).toBeVisible();
  await page.locator('.react-flow__node[data-id="h2"]').click({
    modifiers: ["Shift"],
  });
  await page.locator('.react-flow__node[data-id="h3"]').click({
    modifiers: ["Shift"],
  });
  await expect(page.getByRole("heading", { name: "3 selected" })).toBeVisible();
  await expect(page.locator(".device.selected")).toHaveCount(3);
  await page.getByRole("button", { name: "Remove 3 selected items" }).click();
  await expect(page.locator(deviceNodes)).toHaveCount(1);
  await expect(page.locator(dataEdges)).toHaveCount(0);
});

test("a broken network explains itself before anything is sent", async ({
  page,
}) => {
  await mockApi(page);
  await page.locator('.react-flow__node[data-id="h1"]').click();
  await page.getByLabel("IPv4 address / prefix").fill("10.0.0.2/24");
  await expect(
    page.getByRole("button", { name: /1 problem to fix/ }),
  ).toBeVisible();
  await page.getByRole("button", { name: /1 problem to fix/ }).click();
  await expect(
    page.getByText("The address 10.0.0.2 is used by more than one host"),
  ).toBeVisible();
  // Opening the list clears the selection, so pick the host again to fix it.
  await page.locator('.react-flow__node[data-id="h1"]').click();
  await page.getByLabel("IPv4 address / prefix").fill("10.0.0.9/24");
  await expect(
    page.getByRole("button", { name: /problem to fix/ }),
  ).toHaveCount(0);
});

test("one download button offers both file formats", async ({ page }) => {
  await mockApi(page);
  await page.getByRole("button", { name: "Choose a download format" }).click();
  await expect(
    page.getByRole("menuitem", { name: /Project JSON/ }),
  ).toBeVisible();
  const exported = page.waitForEvent("download");
  await page.getByRole("menuitem", { name: /MiniEdit topology/ }).click();
  expect((await exported).suggestedFilename()).toBe(
    "small-teaching-network.mn",
  );
});

test("form fields explain what they change", async ({ page }) => {
  await mockApi(page);
  await page
    .getByRole("button", {
      name: /What this means: How many packets per second each attacker/,
    })
    .click();
  await expect(page.getByRole("tooltip")).toContainText(
    "the emulated network works much harder",
  );
});

test("the managed controller is visible, inspectable, and not editable", async ({
  page,
}) => {
  await mockApi(page);
  const controller = page.locator(
    '.react-flow__node[data-id="__controller__"]',
  );
  await expect(controller).toBeInViewport();
  await expect(controller).toContainText("c0");
  // One dashed control link per switch, and it never counts as a topology link.
  await expect(page.locator(".react-flow__edge.control-edge")).toHaveCount(1);
  await expect(page.locator(".canvas-footer")).toContainText(
    "1 controller / 1 switches / 3 hosts / 3 links",
  );

  await controller.click();
  await expect(page.getByRole("heading", { name: "c0" })).toBeVisible();
  await expect(page.getByText("127.0.0.1:6653", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /^Remove/ })).toHaveCount(0);

  // It stays out of bulk selections, so it can never be swept up and deleted.
  await page.locator('.react-flow__node[data-id="h1"]').click({
    modifiers: ["Shift"],
  });
  await expect(
    page.getByRole("heading", { name: "h1", exact: true }),
  ).toBeVisible();

  // And it is never written into an exported topology.
  const exported = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download", exact: true }).click();
  const stream = await (await exported).createReadStream();
  let data = "";
  for await (const chunk of stream!) data += chunk;
  expect(JSON.parse(data).switches).toHaveLength(1);
  expect(data).not.toContain("__controller__");
});

test("Stop lab reaches the runner instead of the static bundle", async ({
  page,
}) => {
  await mockApi(page, true);
  await page.getByRole("button", { name: "Stop lab" }).click();
  // A GET here matched no route and was answered by StaticFiles with "Not Found".
  expect(calls).toContain("POST /stop");
  expect(calls).not.toContain("GET /stop");
  await expect(page.getByRole("alert")).toHaveCount(0);
});
