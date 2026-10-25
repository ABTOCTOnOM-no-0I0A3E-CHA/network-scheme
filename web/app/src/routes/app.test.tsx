import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { api, clearCsrfToken } from "@/lib/api";
import { queryClient } from "@/lib/query";
import { buildRouter } from "@/router";

const putImageData = vi.fn();
const codes = Array.from({ length: 10 }, (_, i) => `BACKUPCODE00000${i}`.slice(0, 16));
let loggedIn = false;
let loginResponse: () => Response;
let roles: { role: string; group_id: number | null }[] = [];
const inventory = [
  { id: 1, name: "core-sw", address: "192.0.2.10", group_id: 1, driver: "generic-snmp", model: "", firmware: "", insecure_protocols: false, state: "up", state_since: null },
  { id: 2, name: "edge-rtr", address: "198.51.100.7", group_id: 1, driver: "generic-snmp", model: "", firmware: "", insecure_protocols: false, state: "down", state_since: null },
];

/* GET /api/search: devices from the inventory, the other types for fixed queries ("multi" hits every type) */
let searchQs: string[] = [];
const none = { items: [], more: false };
const ipHit = { device_id: 2, device_name: "edge-rtr", ip: "10.0.0.5", mac: "02:aa:bb:cc:dd:ee", if_index: 7, port_name: "ge-0/0/7" };
const macHit = { device_id: 2, device_name: "edge-rtr", mac: "02:aa:bb:cc:dd:ee", source: "fdb", vlan: 30, ip: null, if_index: 7, port_name: "ge-0/0/7" };
const portHit = { device_id: 2, device_name: "edge-rtr", if_index: 7, name: "ge-0/0/7", alias: "<img src=x onerror=alert(1)> uplink" };
function searchFor(q: string) {
  const all = q === "multi";
  const devices = inventory.filter((d) => all ? d.id === 2 : d.name.includes(q) || d.address.startsWith(q)).map(({ id, name, address }) => ({ id, name, address }));
  return {
    devices: { items: devices, more: false },
    ips: all || q.startsWith("10.") ? { items: [ipHit], more: false } : none,
    macs: all || q.startsWith("02:") ? { items: [macHit], more: true } : none,
    ports: all || q.includes("uplink") ? { items: [portHit], more: false } : none,
  };
}

const apiError = (status: number, code: string) =>
  HttpResponse.json({ error: { code, message: "RAW SERVER MESSAGE" } }, { status });

const server = setupServer(
  http.post("*/api/auth/login", () => loginResponse()),
  http.post("*/api/auth/totp", () => {
    loggedIn = true;
    return new HttpResponse(null, { status: 204 });
  }),
  http.post("*/api/auth/enroll", () => {
    loggedIn = true;
    return HttpResponse.json({ backup_codes: codes });
  }),
  http.post("*/api/auth/logout", () => {
    loggedIn = false;
    return new HttpResponse(null, { status: 204 });
  }),
  http.get("*/api/devices", () => HttpResponse.json(inventory)),
  http.get("*/api/devices/2", () => HttpResponse.json({ ...inventory[1], snmp_port: 161, interval_avail_s: null, interval_metrics_s: null, interval_inventory_s: null })),
  http.get("*/api/devices/2/interfaces", () => HttpResponse.json({ items: [], next_offset: null })),
  http.get("*/api/devices/2/arp", () => HttpResponse.json({ items: [], next_offset: null })),
  http.get("*/api/devices/2/mac", () => HttpResponse.json({ items: [], next_offset: null })),
  http.get("*/api/devices/2/metrics/if", () => HttpResponse.json({ step_s: 0, points: [] })),
  http.get("*/api/search", ({ request }) => {
    const q = new URL(request.url).searchParams.get("q") ?? "";
    searchQs.push(q);
    return HttpResponse.json(searchFor(q));
  }),
  http.get("*/api/groups", () => apiError(403, "forbidden")),
  http.get("*/api/problems", () => HttpResponse.json({ items: [], next_cursor: null })),
  http.get("*/api/map/views", () => HttpResponse.json([])),
  http.get("*/api/dashboards", () => HttpResponse.json([])),
  http.get("*/api/topology", () => HttpResponse.json({ nodes: [], links: [], areas: [] })),
  http.get("*/api/templates", () => HttpResponse.json([])),
  http.get("*/api/maintenance", () => HttpResponse.json([])),
  http.get("*/api/system/status", () => HttpResponse.json({ now: new Date().toISOString(), pollers: [], eventd: [], db_size_bytes: 0, queues: [] })),
  http.get("*/api/auth/me", () =>
    loggedIn ? HttpResponse.json({ id: 1, username: "admin", roles, csrf_token: "tok" }) : apiError(401, "unauthenticated"),
  ),
);

beforeAll(() => {
  /* index.html carries this marker so input-otp does not inject a runtime <style> */
  const marker = document.createElement("meta");
  marker.id = "input-otp-style";
  document.head.append(marker);
  server.listen({ onUnhandledFrame: "error" });
  window.matchMedia ??= ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })) as never;
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
  Element.prototype.scrollIntoView ??= () => {};
  window.scrollTo = () => {}; /* router scroll restoration; jsdom does not implement it */
  document.elementFromPoint ??= () => null; /* used by input-otp password-manager detection */
  /* jsdom has no canvas: a stub 2d context is enough for qrcode to draw into */
  HTMLCanvasElement.prototype.getContext = (() => ({
    createImageData: (w: number, h: number) => ({ data: new Uint8ClampedArray(w * h * 4) }),
    clearRect() {},
    putImageData,
  })) as never;
});
afterAll(() => server.close());
beforeEach(() => {
  loggedIn = false;
  roles = [];
  searchQs = [];
  loginResponse = () => HttpResponse.json({ stage: "totp", challenge: "ch1" });
  putImageData.mockClear();
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
  queryClient.clear();
  clearCsrfToken();
});

function renderApp(path: string) {
  const router = buildRouter(createMemoryHistory({ initialEntries: [path] }));
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return router;
}

async function submitCredentials(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText(ru.auth.username), "admin");
  await user.type(screen.getByLabelText(ru.auth.password), "correct horse battery");
  await user.click(screen.getByRole("button", { name: ru.auth.submit }));
}

describe("login flow", () => {
  it("login → totp → shell", async () => {
    const user = userEvent.setup();
    renderApp("/login");
    await submitCredentials(user);
    await user.type(await screen.findByLabelText(ru.auth.totp.label), "123456");
    expect(await screen.findByRole("navigation", { name: ru.nav.label })).toBeInTheDocument();
    for (const k of ["dashboards", "devices", "settings"] as const) {
      expect(screen.getAllByText(ru.nav[k]).length).toBeGreaterThan(0);
    }
    /* the home page is the dashboards section */
    expect(await screen.findByText(ru.dashboards.none)).toBeInTheDocument();
    /* the panel CSP forbids runtime <style> elements */
    expect(document.querySelectorAll("style")).toHaveLength(0);
  });

  it("backup code can be used instead of a TOTP code", async () => {
    const user = userEvent.setup();
    renderApp("/login");
    await submitCredentials(user);
    await user.click(await screen.findByRole("button", { name: ru.auth.backup.use }));
    await user.type(screen.getByLabelText(ru.auth.backup.label), "ABCDEFGHJKLMNPQR");
    await user.click(screen.getByRole("button", { name: ru.auth.verify }));
    expect(await screen.findByRole("navigation", { name: ru.nav.label })).toBeInTheDocument();
  });

  it("enroll shows QR and backup codes", async () => {
    loginResponse = () =>
      HttpResponse.json({ stage: "enroll", challenge: "ch2", otpauth_uri: "otpauth://totp/NMS:admin?secret=JBSWY3DPEHPK3PXP&issuer=NMS" });
    const user = userEvent.setup();
    renderApp("/login");
    await submitCredentials(user);
    expect(await screen.findByRole("img", { name: ru.auth.enroll.qr })).toBeInstanceOf(HTMLCanvasElement);
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();
    await waitFor(() => expect(putImageData).toHaveBeenCalled());

    await user.type(screen.getByLabelText(ru.auth.totp.label), "123456");
    const list = await screen.findByTestId("backup-codes");
    expect(list.querySelectorAll("li")).toHaveLength(10);
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: ru.auth.codes.saved }));
    expect(await screen.findByRole("navigation", { name: ru.nav.label })).toBeInTheDocument();
    expect(screen.queryByTestId("backup-codes")).not.toBeInTheDocument();
    expect(JSON.stringify([...Object.entries(localStorage), ...Object.entries(sessionStorage)])).not.toContain(codes[0]);
  });

  it.each([
    [401, "invalid_credentials", ru.errors.invalid_credentials],
    [423, "locked", ru.errors.locked],
    [429, "rate_limited", ru.errors.rate_limited],
    [502, "gateway_error", ru.errors.gateway_error],
  ])("error codes are localized (%i %s)", async (status, code, text) => {
    loginResponse = () => apiError(status, code);
    const user = userEvent.setup();
    renderApp("/login");
    await submitCredentials(user);
    expect(await screen.findByRole("alert")).toHaveTextContent(text);
    expect(screen.queryByText(/RAW SERVER MESSAGE/)).not.toBeInTheDocument();
  });

  it("redirects unauthenticated visitors from the shell to /login", async () => {
    const router = renderApp("/devices");
    expect(await screen.findByLabelText(ru.auth.username)).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/login");
  });
});

describe("network failures", () => {
  const unhandled: unknown[] = [];
  const onRejection = (e: unknown) => unhandled.push(e);
  beforeEach(() => {
    unhandled.length = 0;
    process.on("unhandledRejection", onRejection);
  });
  afterEach(() => {
    process.off("unhandledRejection", onRejection);
    expect(unhandled).toEqual([]);
  });

  it("login: re-enables the button, clears the password and shows a localized message", async () => {
    loginResponse = () => HttpResponse.error();
    const user = userEvent.setup();
    renderApp("/login");
    await submitCredentials(user);
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.network);
    expect(screen.getByRole("button", { name: ru.auth.submit })).toBeEnabled();
    expect(screen.getByLabelText(ru.auth.password)).toHaveValue("");
  });

  it("totp: re-enables input, clears the code and shows a localized message", async () => {
    server.use(http.post("*/api/auth/totp", () => HttpResponse.error()));
    const user = userEvent.setup();
    renderApp("/login");
    await submitCredentials(user);
    await user.type(await screen.findByLabelText(ru.auth.totp.label), "123456");
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.network);
    const input = screen.getByLabelText(ru.auth.totp.label);
    expect(input).toBeEnabled();
    expect(input).toHaveValue("");
  });

  it("enroll: re-enables input, clears the code and shows a localized message", async () => {
    loginResponse = () =>
      HttpResponse.json({ stage: "enroll", challenge: "ch2", otpauth_uri: "otpauth://totp/NMS:admin?secret=JBSWY3DPEHPK3PXP" });
    server.use(http.post("*/api/auth/enroll", () => HttpResponse.error()));
    const user = userEvent.setup();
    renderApp("/login");
    await submitCredentials(user);
    await user.type(await screen.findByLabelText(ru.auth.totp.label), "123456");
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.network);
    const input = screen.getByLabelText(ru.auth.totp.label);
    expect(input).toBeEnabled();
    expect(input).toHaveValue("");
  });

  it("post-login /me failure returns to the credentials step with a message", async () => {
    /* the login guard's own /me call answers 401; only the post-login refresh fails */
    let calls = 0;
    server.use(http.get("*/api/auth/me", () => (calls++ === 0 ? apiError(401, "unauthenticated") : HttpResponse.error())));
    const user = userEvent.setup();
    renderApp("/login");
    await submitCredentials(user);
    await user.type(await screen.findByLabelText(ru.auth.totp.label), "123456");
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.network);
    expect(screen.getByLabelText(ru.auth.username)).toBeEnabled();
    expect(screen.getByRole("button", { name: ru.auth.submit })).toBeEnabled();
  });
});

describe("shell", () => {
  beforeEach(() => {
    loggedIn = true;
  });

  it("Ctrl+K opens empty palette", async () => {
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    await user.keyboard("{Control>}k{/Control}");
    expect(await screen.findByText(ru.palette.empty)).toBeInTheDocument();
    expect(document.querySelectorAll("style")).toHaveLength(0);
    expect(screen.getByPlaceholderText(ru.palette.placeholder)).toBeInTheDocument();
  });

  it("palette finds a device by name or by address and opens the list on it", async () => {
    roles = [{ role: "viewer", group_id: null }];
    const user = userEvent.setup();
    const router = renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    await user.keyboard("{Control>}k{/Control}");
    await user.type(screen.getByPlaceholderText(ru.palette.placeholder), "198.51");
    await user.click(await screen.findByRole("option", { name: /edge-rtr/ }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/devices/2"));
    expect(await screen.findByRole("heading", { name: "edge-rtr" })).toBeInTheDocument();

    await user.keyboard("{Control>}k{/Control}");
    await user.type(screen.getByPlaceholderText(ru.palette.placeholder), "core");
    expect(await screen.findByRole("option", { name: /core-sw/ })).toBeInTheDocument();
  });

  it("palette debounces the query: one search for a typed word, none for one character", async () => {
    roles = [{ role: "viewer", group_id: null }];
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    await user.keyboard("{Control>}k{/Control}");
    const input = screen.getByPlaceholderText(ru.palette.placeholder);
    await user.type(input, "e");
    await new Promise((r) => setTimeout(r, 400));
    expect(searchQs).toEqual([]);
    await user.type(input, "dge");
    expect(await screen.findByRole("option", { name: /edge-rtr/ })).toBeInTheDocument();
    expect(searchQs).toEqual(["edge"]);
    expect(input).toHaveAttribute("maxlength", "100");
    /* the earlier results do not linger under a query too short to search */
    await user.clear(input);
    await user.type(input, "e");
    expect(screen.queryByRole("option")).not.toBeInTheDocument();
  });

  it("palette groups results by type and opens the chosen one from the keyboard", async () => {
    roles = [{ role: "viewer", group_id: null }];
    const user = userEvent.setup();
    const router = renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    await user.keyboard("{Control>}k{/Control}");
    await user.type(screen.getByPlaceholderText(ru.palette.placeholder), "multi");
    await screen.findByRole("option", { name: /10\.0\.0\.5/ });
    const headings = [...document.querySelectorAll("[cmdk-group-heading]")].map((h) => h.textContent);
    expect(headings).toEqual([ru.palette.devices, ru.palette.ips, ru.palette.macs, ru.palette.ports]);
    expect(screen.getByText(ru.palette.more)).toBeInTheDocument(); /* the MAC type had more results */
    /* device-reported strings are text: the alias markup is shown, never parsed */
    expect(screen.getByRole("option", { name: /<img src=x onerror=alert\(1\)> uplink/ })).toBeInTheDocument();
    expect(document.querySelector("dialog img")).toBeNull();
    /* the first item is selected; three steps down is the port */
    await user.keyboard("{ArrowDown}{ArrowDown}{ArrowDown}{Enter}");
    await waitFor(() => expect(router.state.location.pathname).toBe("/devices/2"));
    expect(router.state.location.search).toEqual({ tab: "graphs", if: 7 });
    expect(await screen.findByRole("tab", { name: ru.card.tab.graphs })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByPlaceholderText(ru.palette.placeholder)).not.toBeInTheDocument();
  });

  it("palette opens the ARP and FDB tabs for IP and MAC results", async () => {
    roles = [{ role: "viewer", group_id: null }];
    const user = userEvent.setup();
    const router = renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    for (const [q, name, tab] of [["10.0.0", /10\.0\.0\.5/, "arp"], ["02:aa", /FDB · VLAN 30/, "mac"]] as const) {
      await user.keyboard("{Control>}k{/Control}");
      await user.type(screen.getByPlaceholderText(ru.palette.placeholder), q);
      await user.click(await screen.findByRole("option", { name }));
      await waitFor(() => expect(router.state.location.search).toEqual({ tab }));
      expect(await screen.findByRole("tab", { name: ru.card.tab[tab] })).toHaveAttribute("aria-selected", "true");
    }
  });

  it("palette finds panel sections the user may open", async () => {
    roles = [{ role: "viewer", group_id: null }];
    const user = userEvent.setup();
    const router = renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    await user.keyboard("{Control>}k{/Control}");
    const input = screen.getByPlaceholderText(ru.palette.placeholder);
    /* the system health section is not offered to a viewer */
    await user.type(input, ru.nav.health.slice(0, 5));
    expect(await screen.findByText(ru.palette.empty)).toBeInTheDocument();
    expect(screen.queryByRole("option")).not.toBeInTheDocument();
    await user.clear(input);
    await user.type(input, ru.nav.map.slice(0, 3).toLowerCase());
    expect(await screen.findByRole("option", { name: ru.nav.map })).toBeInTheDocument();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(router.state.location.pathname).toBe("/map"));
  });

  it("problems, templates and maintenance are real screens reachable from the menu", async () => {
    loggedIn = true;
    roles = [{ role: "admin", group_id: null }];
    const user = userEvent.setup();
    const router = renderApp("/");
    const nav = await screen.findByRole("navigation", { name: ru.nav.label });
    for (const [key, path, empty] of [
      ["problems", "/problems", ru.problems.empty],
      ["templates", "/templates", ru.templates.empty],
      ["maintenance", "/maintenance", ru.maintenance.empty],
    ] as const) {
      await user.click(within(nav).getByRole("link", { name: ru.nav[key] }));
      await waitFor(() => expect(router.state.location.pathname).toBe(path));
      expect(await screen.findByText(empty)).toBeInTheDocument();
      expect(screen.queryByText(ru.placeholder.soon)).not.toBeInTheDocument();
    }
  });

  it("devices screen: viewer has no add button, admin has", async () => {
    roles = [{ role: "viewer", group_id: null }];
    renderApp("/devices");
    await screen.findByLabelText(ru.devices.search);
    expect(screen.queryByRole("button", { name: ru.devices.add })).not.toBeInTheDocument();
    cleanup();
    roles = [{ role: "admin", group_id: null }];
    queryClient.clear();
    renderApp("/devices");
    expect(await screen.findByRole("button", { name: ru.devices.add })).toBeInTheDocument();
  });

  it("system status: viewer has no menu item and no data, operator and admin do", async () => {
    roles = [{ role: "viewer", group_id: null }];
    renderApp("/health");
    expect(await screen.findByText(ru.system.forbidden)).toBeInTheDocument();
    expect(within(screen.getByRole("navigation", { name: ru.nav.label })).queryByText(ru.nav.health)).not.toBeInTheDocument();
    cleanup();
    roles = [{ role: "operator", group_id: null }];
    queryClient.clear();
    renderApp("/health");
    expect(await screen.findByText(ru.system.noPollers)).toBeInTheDocument();
    expect(within(screen.getByRole("navigation", { name: ru.nav.label })).getByText(ru.nav.health)).toBeInTheDocument();
  });

  it("templates and maintenance are in the menu for admins only", async () => {
    const nav = () => within(screen.getByRole("navigation", { name: ru.nav.label }));
    roles = [{ role: "viewer", group_id: null }];
    renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    expect(nav().queryByText(ru.nav.templates)).not.toBeInTheDocument();
    expect(nav().queryByText(ru.nav.maintenance)).not.toBeInTheDocument();
    cleanup();
    roles = [{ role: "admin", group_id: 1 }];
    queryClient.clear();
    renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    expect(await nav().findByText(ru.nav.templates)).toBeInTheDocument();
    expect(nav().getByText(ru.nav.maintenance)).toBeInTheDocument();
  });

  it("logout returns to /login", async () => {
    const user = userEvent.setup();
    const router = renderApp("/");
    await user.click(await screen.findByRole("button", { name: ru.shell.userMenu }));
    await user.click(screen.getByRole("menuitem", { name: ru.shell.logout }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/login"));
  });

  it("401 anywhere redirects to /login", async () => {
    server.use(http.get("*/api/users", () => apiError(401, "session_expired")));
    const router = renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    queryClient.setQueryData(["marker"], 1);
    loggedIn = false;
    await api.GET("/api/users");
    await waitFor(() => expect(router.state.location.pathname).toBe("/login"));
    expect(queryClient.getQueryData(["marker"])).toBeUndefined();
  });
});
