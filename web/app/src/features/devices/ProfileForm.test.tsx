import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { x25519 } from "@noble/curves/ed25519.js";
import "@/i18n";
import ru from "@/i18n/ru.json";
import { fingerprint } from "@/lib/keys";
import { openSealed, toBase64 } from "@/lib/seal";
import { ProfileForm } from "./ProfileForm";

const kp = x25519.keygen();
const KEY_VERSION = 3;
const SECRET = "very-secret-community-9876";
const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let bodies: { url: string; text: string }[] = [];
let putStatus = 204;
const server = setupServer(
  http.get("*/keys.json", () =>
    HttpResponse.json({ version: 1, domains: { read: { key_version: KEY_VERSION, public_key: toBase64(kp.publicKey), fingerprint: fingerprint(kp.publicKey) } } }),
  ),
  http.put("*/api/devices/:id/profiles/:kind", async ({ request }) => {
    bodies.push({ url: request.url, text: await request.text() });
    return putStatus === 204 ? new HttpResponse(null, { status: 204 }) : HttpResponse.json({ error: { code: "stale_key", message: "RAW" } }, { status: putStatus });
  }),
  http.put("*/api/discovery/scans/:id/profile", async ({ request }) => {
    bodies.push({ url: request.url, text: await request.text() });
    return new HttpResponse(null, { status: 204 });
  }),
);

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
  bodies = [];
  putStatus = 204;
  localStorage.clear();
  sessionStorage.clear();
});
afterAll(() => server.close());

function setup(ui: (qc: QueryClient) => React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  render(<QueryClientProvider client={qc}>{ui(qc)}</QueryClientProvider>);
  return qc;
}

const COMMUNITY = ru.profile.community;

describe("ProfileForm", () => {
  it("has no password inputs (password managers), is masked text with ignore hints, and posts", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <ProfileForm owner="device:7" kind="snmp3" />
      </QueryClientProvider>,
    );
    expect(container.querySelector("input[type=password]")).toBeNull();
    for (const n of ["auth_key", "priv_key"]) {
      const el = container.querySelector(`input[name=${n}]`)!;
      expect(el).toHaveAttribute("autocomplete", "off");
      for (const a of ["data-1p-ignore", "data-lpignore", "data-bwignore", "data-form-type", "autocapitalize"]) expect(el).toHaveAttribute(a);
      expect(el.className).toContain("text-security");
    }
    expect(container.querySelector("form")).toHaveAttribute("method", "post");
  });

  it("reports a key-load failure as keyError", async () => {
    server.use(http.get("*/keys.json", () => new HttpResponse(null, { status: 500 })));
    setup(() => <ProfileForm owner="device:7" kind="snmp2c" />);
    await userEvent.type(screen.getByLabelText(COMMUNITY), SECRET);
    await userEvent.click(screen.getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(ru.profile.keyError));
    expect(bodies).toHaveLength(0);
  });

  it("seals in the browser: the request carries only ciphertext, the fields are cleared, nothing leaks into caches or storage", async () => {
    const spies = (["log", "info", "warn", "error", "debug"] as const).map((m) => vi.spyOn(console, m));
    const onSaved = vi.fn();
    const qc = setup(() => <ProfileForm owner="device:7" kind="snmp2c" onSaved={onSaved} />);
    await screen.findByText(ru.profile.key.replace("{{fingerprint}}", fingerprint(kp.publicKey)));
    const input = screen.getByLabelText(COMMUNITY);
    await userEvent.type(input, SECRET);
    await userEvent.click(screen.getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());

    expect(bodies).toHaveLength(1);
    const { url, text } = bodies[0]!;
    expect(url).toContain("/api/devices/7/profiles/snmp2c");
    expect(text).not.toContain(SECRET);
    const body = JSON.parse(text) as { ciphertext: string; key_version: number };
    expect(Object.keys(body).sort()).toEqual(["ciphertext", "key_version"]);
    expect(body.key_version).toBe(KEY_VERSION);
    const pt = JSON.parse(new TextDecoder().decode(openSealed(kp.publicKey, kp.secretKey, b64(body.ciphertext))));
    expect(pt).toMatchObject({ v: 1, owner: "device:7", kind: "snmp2c", secret: { community: SECRET } });

    expect((screen.getByLabelText(COMMUNITY) as HTMLInputElement).value).toBe("");
    const dump = JSON.stringify([qc.getQueryCache().getAll().map((q) => q.state.data), qc.getMutationCache().getAll().map((m) => [m.state.variables, m.state.data])]);
    expect(dump).not.toContain(SECRET);
    expect(JSON.stringify({ ...localStorage })).not.toContain(SECRET);
    expect(JSON.stringify({ ...sessionStorage })).not.toContain(SECRET);
    expect(location.href).not.toContain(SECRET);
    spies.forEach((s) => expect(s).not.toHaveBeenCalled());
    spies.forEach((s) => s.mockRestore());
  });

  it("rejects a short key and control characters before sending anything", async () => {
    setup(() => <ProfileForm owner="device:7" kind="snmp2c" />);
    await screen.findByText(/Ключ шифрования:/);
    await userEvent.type(screen.getByLabelText(COMMUNITY), "short");
    await userEvent.click(screen.getByRole("button", { name: ru.profile.save }));
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.profile.err.weak_snmp.replace("{{field}}", COMMUNITY));
    await userEvent.clear(screen.getByLabelText(COMMUNITY));
    await userEvent.type(screen.getByLabelText(COMMUNITY), "0123456789abcdef\t");
    await userEvent.click(screen.getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("управляющие символы"));
    expect(bodies).toHaveLength(0);
  });

  it("SNMPv3 offers no MD5 and generates 24-character keys", async () => {
    setup(() => <ProfileForm owner="device:7" kind="snmp3" />);
    const auth = (await screen.findByLabelText(ru.profile.authProto)) as HTMLSelectElement;
    expect([...auth.options].map((o) => o.value)).toEqual(["SHA224", "SHA256", "SHA384", "SHA512"]);
    expect([...(screen.getByLabelText(ru.profile.privProto) as HTMLSelectElement).options].map((o) => o.value)).toEqual(["AES", "AES256"]);
    await userEvent.click(screen.getAllByRole("button", { name: ru.profile.generate })[0]!);
    expect((screen.getByLabelText(ru.profile.authKey) as HTMLInputElement).value).toMatch(/^[A-Za-z0-9]{24}$/);
  });

  it("a scan owner uses the scan credential endpoint with kind in the body; ssh_read is not offered", async () => {
    const { unmount } = (() => {
      setup(() => <ProfileForm owner="scan:9" kind="ssh_read" />);
      return { unmount: cleanup };
    })();
    expect(screen.queryByRole("button", { name: ru.profile.save })).toBeNull();
    unmount();
    const onSaved = vi.fn();
    setup(() => <ProfileForm owner="scan:9" kind="snmp2c" onSaved={onSaved} />);
    await screen.findByText(/Ключ шифрования:/);
    await userEvent.type(screen.getByLabelText(COMMUNITY), SECRET);
    await userEvent.click(screen.getByRole("button", { name: ru.profile.save }));
    await waitFor(() => expect(onSaved).toHaveBeenCalled());
    expect(bodies[0]!.url).toContain("/api/discovery/scans/9/profile");
    expect(JSON.parse(bodies[0]!.text)).toMatchObject({ kind: "snmp2c", key_version: KEY_VERSION });
    expect(bodies[0]!.text).not.toContain(SECRET);
  });

  it("shows only status and date of an existing profile and keeps typed values on a localized API error", async () => {
    putStatus = 400;
    setup(() => <ProfileForm owner="device:7" kind="snmp2c" profile={{ status: "weak", updated_at: "2026-10-20T10:00:00Z" }} />);
    expect(screen.getByText(new RegExp(ru.profile.status.weak))).toBeInTheDocument();
    await screen.findByText(/Ключ шифрования:/);
    await userEvent.type(screen.getByLabelText(COMMUNITY), SECRET);
    await userEvent.click(screen.getByRole("button", { name: ru.profile.save }));
    expect(await screen.findByRole("alert")).toHaveTextContent(ru.errors.stale_key);
    expect(screen.queryByText("RAW")).toBeNull();
    expect((screen.getByLabelText(COMMUNITY) as HTMLInputElement).value).toBe(SECRET);
  });
});
