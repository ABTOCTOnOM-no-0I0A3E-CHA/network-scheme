import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { x25519 } from "@noble/curves/ed25519.js";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { fingerprint } from "@/lib/keys";
import { toBase64 } from "@/lib/seal";
import { DiscoveryPage } from "./DiscoveryPage";

const err = (status: number, code: string) => HttpResponse.json({ error: { code, message: "RAW SERVER MESSAGE" } }, { status });
const kp = x25519.keygen();

type Scan = { id: number; cidr: string; group_id: number; enabled: boolean; interval_s: number; last_run_at: string | null };
type Find = { id: number; scan_id: number; group_id: number; address: string; sys_object_id: string; sys_descr: string; sys_name: string; found_at: string; status: string };

let scans: Scan[] = [];
let finds: Find[] = [];
let scanPost: (body: Record<string, unknown>) => Response;
let acceptFn: () => Response;
let ignoreFn: () => Response;
let profileBody: Record<string, unknown> | undefined;
const posted: Record<string, unknown>[] = [];

const find = (id: number, over: Partial<Find> = {}): Find => ({
  id,
  scan_id: 1,
  group_id: 2,
  address: `192.0.2.${id}`,
  sys_object_id: "1.3.6.1.4.1.35265.1.1",
  sys_descr: "Eltex MES2324",
  sys_name: `sw-${id}`,
  found_at: "2026-10-20T10:00:00Z",
  status: "pending",
  ...over,
});

const server = setupServer(
  http.get("*/api/discovery/scans", () => HttpResponse.json(scans)),
  http.post("*/api/discovery/scans", async ({ request }) => {
    const body = (await request.json()) as Record<string, unknown>;
    posted.push(body);
    return scanPost(body);
  }),
  http.patch("*/api/discovery/scans/:id", () => new HttpResponse(null, { status: 204 })),
  http.put("*/api/discovery/scans/:id/profile", async ({ request }) => {
    profileBody = (await request.json()) as Record<string, unknown>;
    return new HttpResponse(null, { status: 204 });
  }),
  http.get("*/api/discovery/inbox", () => HttpResponse.json(finds)),
  http.post("*/api/discovery/inbox/:id/accept", () => acceptFn()),
  http.post("*/api/discovery/inbox/:id/ignore", () => ignoreFn()),
  http.get("*/api/groups", () =>
    HttpResponse.json([
      { id: 1, parent_id: null, name: "Core" },
      { id: 2, parent_id: 1, name: "Edge" },
    ]),
  ),
  http.get("*/keys.json", () => HttpResponse.json({ version: 1, domains: { read: { key_version: 1, public_key: toBase64(kp.publicKey), fingerprint: fingerprint(kp.publicKey) } } })),
);

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  scans = [];
  finds = [];
  posted.length = 0;
  profileBody = undefined;
});
afterAll(() => server.close());

function setup(onOpenDevice = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <DiscoveryPage onOpenDevice={onOpenDevice} />
    </QueryClientProvider>,
  );
  return onOpenDevice;
}

async function submitScan(cidr: string, interval?: string) {
  await userEvent.type(await screen.findByLabelText(ru.scan.cidr), cidr);
  await screen.findByRole("option", { name: "Edge" });
  if (interval !== undefined) {
    const field = screen.getByLabelText(ru.scan.interval);
    await userEvent.clear(field);
    await userEvent.type(field, interval);
  }
  await userEvent.click(screen.getByRole("button", { name: ru.scan.create }));
}

describe("scan form", () => {
  it("shows the wide-prefix error from the API in plain words, not the server message", async () => {
    scanPost = () => err(400, "cidr_too_wide");
    setup();
    await submitScan("10.0.0.0/15");
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.scan.err.tooWide);
    expect(screen.queryByText(/RAW SERVER MESSAGE/)).not.toBeInTheDocument();
    expect(posted[0]).toMatchObject({ cidr: "10.0.0.0/15", interval_s: 86400 });
    /* the typed value stays for correction */
    expect(screen.getByLabelText(ru.scan.cidr)).toHaveValue("10.0.0.0/15");
  });

  it("explains a reserved or malformed prefix", async () => {
    scanPost = () => err(400, "bad_request");
    setup();
    await submitScan("127.0.0.0/24");
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.scan.err.badCidr);
    expect(screen.queryByText(/RAW SERVER MESSAGE/)).not.toBeInTheDocument();
  });

  it("rejects an interval under one hour before sending", async () => {
    setup();
    await submitScan("192.0.2.0/24", "600");
    expect(await screen.findByRole("alert")).toHaveTextContent("3600");
    expect(posted).toHaveLength(0);
  });

  it("requires a prefix", async () => {
    setup();
    await screen.findByRole("option", { name: "Edge" });
    await userEvent.click(screen.getByRole("button", { name: ru.scan.create }));
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.scan.required);
    expect(posted).toHaveLength(0);
  });

  it("after creation opens the credential form of that scan and seals in the browser", async () => {
    scanPost = () => HttpResponse.json({ id: 7 }, { status: 201 });
    setup();
    await submitScan("192.0.2.0/24", "7200");
    expect(posted[0]).toEqual({ cidr: "192.0.2.0/24", group_id: 1, interval_s: 7200 });
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByRole("option", { name: ru.profile.title.ssh_read })).not.toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(ru.profile.community), "scan-community-0123456789");
    await userEvent.click(within(dialog).getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(profileBody).toBeDefined());
    expect(profileBody).toMatchObject({ kind: "snmp2c", key_version: 1 });
    expect(JSON.stringify(profileBody)).not.toContain("scan-community");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});

describe("scan list", () => {
  it("lists scans with the group name and toggles enabled", async () => {
    scans = [{ id: 3, cidr: "198.51.100.0/24", group_id: 1, enabled: true, interval_s: 3600, last_run_at: null }];
    setup();
    expect(await screen.findByText("198.51.100.0/24")).toBeInTheDocument();
    expect(screen.getAllByText("Core").length).toBeGreaterThan(0);
    expect(screen.getByText(ru.scan.never)).toBeInTheDocument();
    expect(screen.getByLabelText(ru.scan.toggle.replace("{{cidr}}", "198.51.100.0/24"))).toBeChecked();
  });
});

describe("inbox", () => {
  it("renders device-reported strings as text only", async () => {
    finds = [find(1, { sys_name: "<img src=x onerror=alert(1)>", sys_descr: "<b>bold</b>‮fdp" })];
    setup();
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(screen.getByText(/<b>bold<\/b>�fdp/)).toBeInTheDocument();
    expect(document.querySelector("img, b")).toBeNull();
  });

  it("accepts under a chosen name and group and opens the new device", async () => {
    finds = [find(5, { sys_name: "sw-five" })];
    let body: unknown;
    server.use(
      http.post("*/api/discovery/inbox/:id/accept", async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ id: 99 }, { status: 201 });
      }),
    );
    const open = setup();
    await userEvent.click(await screen.findByRole("button", { name: ru.inbox.accept }));
    const dialog = await screen.findByRole("dialog");
    const name = within(dialog).getByLabelText(ru.devices.addDialog.name);
    expect(name).toHaveValue("sw-five");
    await userEvent.clear(name);
    await userEvent.type(name, "core-5");
    await within(dialog).findByRole("option", { name: "Core" });
    await userEvent.selectOptions(within(dialog).getByLabelText(ru.devices.addDialog.group), "1");
    await userEvent.click(within(dialog).getByRole("button", { name: ru.inbox.accept }));
    await waitFor(() => expect(open).toHaveBeenCalledWith(99));
    expect(body).toEqual({ name: "core-5", group_id: 1 });
  });

  it("shows not_pending when the find was handled elsewhere", async () => {
    finds = [find(5)];
    acceptFn = () => err(409, "not_pending");
    setup();
    await userEvent.click(await screen.findByRole("button", { name: ru.inbox.accept }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: ru.inbox.accept }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(ru.errors.not_pending);
  });

  it("ignores a find and reports a failure by code", async () => {
    finds = [find(5)];
    ignoreFn = () => err(409, "not_pending");
    setup();
    await userEvent.click(await screen.findByRole("button", { name: ru.inbox.ignore }));
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.not_pending);
  });

  it("shows an empty state", async () => {
    setup();
    expect(await screen.findByText(ru.inbox.empty)).toBeInTheDocument();
  });
});
