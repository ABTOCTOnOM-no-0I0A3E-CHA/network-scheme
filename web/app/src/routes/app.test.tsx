import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
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
  http.get("*/api/groups", () => apiError(403, "forbidden")),
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
    expect(screen.getByText(ru.placeholder.soon)).toBeInTheDocument();
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
    const user = userEvent.setup();
    const router = renderApp("/");
    await screen.findByRole("navigation", { name: ru.nav.label });
    await user.keyboard("{Control>}k{/Control}");
    await user.type(screen.getByPlaceholderText(ru.palette.placeholder), "198.51");
    await user.click(await screen.findByRole("option", { name: /edge-rtr/ }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/devices"));
    expect(router.state.location.search).toEqual({ q: "edge-rtr" });
    expect(await screen.findByLabelText(ru.devices.search)).toHaveValue("edge-rtr");

    await user.keyboard("{Control>}k{/Control}");
    await user.type(screen.getByPlaceholderText(ru.palette.placeholder), "core");
    expect(await screen.findByRole("option", { name: /core-sw/ })).toBeInTheDocument();
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
