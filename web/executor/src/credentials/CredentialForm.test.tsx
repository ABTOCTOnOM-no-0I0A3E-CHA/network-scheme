import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { x25519 } from "@noble/curves/ed25519.js";
import { fingerprint } from "@nms/shared/keys";
import { openSealed } from "@nms/shared/seal";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import "../i18n";
import { createPoster } from "../client";
import { CredentialForm } from "./CredentialForm";
import { parseWriteKey } from "./writeKey";

/* jsdom has no IntersectionObserver v2: the visibility gate is driven by the test */
const vis = vi.hoisted(() => ({ unobscured: true }));
vi.mock("../useUnobscured", () => ({ useUnobscured: () => ({ ref: () => {}, unobscured: vis.unobscured, supported: true }) }));

const PASSWORD = "Wr1te-Pass-0123456";
const secretKey = x25519.utils.randomSecretKey();
const publicKey = x25519.getPublicKey(secretKey);
const b64 = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const keysDoc = { version: 1, domains: { write: { key_version: 1, public_key: b64(publicKey), fingerprint: fingerprint(publicKey) } } };
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const H = "ab".repeat(32);
const ch = {
  challenge_id: "c1",
  action: "credential.set",
  h: H,
  expires: "2026-11-04T10:02:00Z",
  fields: [
    { key: "address", value: "10.9.0.1" },
    { key: "ciphertext", value: "SECRET-CT" },
    { key: "device_id", value: "5" },
    { key: "write_key", value: fingerprint(publicKey) },
  ],
};

let fetchMock: ReturnType<typeof vi.fn>;
let tickets: number;
const touched: string[] = [];
beforeEach(() => {
  vis.unobscured = true;
  tickets = 0;
  touched.length = 0;
  fetchMock = vi.fn((url: string) => (url === "/keys.json" ? Promise.resolve(json(200, keysDoc)) : Promise.reject(new Error(`unexpected ${url}`))));
  vi.stubGlobal("fetch", fetchMock);
  for (const m of ["setItem", "getItem", "removeItem", "key", "clear"] as const) {
    vi.spyOn(Storage.prototype, m).mockImplementation(() => {
      touched.push(m);
      return null;
    });
  }
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const poster = () => createPoster({ requestTicket: () => Promise.resolve(`ticket-${++tickets}`) });
const bodyOf = (i: number) => JSON.parse((fetchMock.mock.calls[i] as [string, RequestInit])[1].body as string) as Record<string, unknown>;
const passwordInput = () => screen.getByLabelText("Пароль", { selector: "input[type=password]" }) as HTMLInputElement;

async function fill(user: ReturnType<typeof userEvent.setup>, pw = PASSWORD) {
  await screen.findByTestId("write-key");
  await user.type(screen.getByLabelText("ID устройства"), "5");
  await user.type(screen.getByLabelText("Имя пользователя"), "netadmin");
  await user.type(passwordInput(), pw);
}

async function issue(user: ReturnType<typeof userEvent.setup>) {
  await fill(user);
  fetchMock.mockImplementationOnce(() => Promise.resolve(json(200, ch)));
  await user.click(screen.getByRole("button", { name: "Зашифровать и проверить" }));
  await screen.findByTestId("confirm");
}

describe("CredentialForm", () => {
  it("seals {owner device:5, kind ssh_write} to the write key, confirms with TOTP, never shows the secret or touches storage", async () => {
    const user = userEvent.setup();
    render(<CredentialForm poster={poster()} />);
    await issue(user);
    expect(fetchMock.mock.calls[1][0]).toBe("/x/confirm/issue");
    const req = bodyOf(1);
    expect(req).toMatchObject({ action: "credential.set", ticket: "ticket-1" });
    const params = req.params as { device_id: number; ciphertext: string };
    expect(params.device_id).toBe(5);
    const env = JSON.parse(new TextDecoder().decode(openSealed(publicKey, secretKey, unb64(params.ciphertext)))) as Record<string, unknown>;
    expect(env).toMatchObject({ v: 1, owner: "device:5", kind: "ssh_write", secret: { username: "netadmin", password: PASSWORD } });
    expect(env.nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(JSON.stringify(req)).not.toContain(PASSWORD);
    expect(screen.getByTestId("h")).toHaveTextContent(H);
    expect(document.body.textContent).not.toContain("SECRET-CT");
    expect(document.body.textContent).not.toContain(PASSWORD);

    fetchMock.mockImplementationOnce(() => Promise.resolve(json(200, { action: "credential.set", result: { device_id: 5, created_at: "2026-11-04T10:00:00Z", method: "password" } })));
    await user.type(screen.getByLabelText("Код TOTP изменений"), "123456");
    await user.click(screen.getByRole("button", { name: "Сохранить" }));
    expect(await screen.findByTestId("done")).toHaveTextContent("Учётка устройства 5 сохранена");
    expect(bodyOf(2)).toEqual({ challenge_id: "c1", h: H, code: "123456", ticket: "ticket-2" });
    expect(document.body.textContent).not.toContain(PASSWORD);
    expect(passwordInput().value).toBe("");
    expect(touched).toEqual([]);
  });

  it("refuses a weak password before sealing: no request at all", async () => {
    const user = userEvent.setup();
    render(<CredentialForm poster={poster()} />);
    await fill(user, "short-pass1");
    await user.click(screen.getByRole("button", { name: "Зашифровать и проверить" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("Пароль слишком короткий");
    expect(fetchMock).toHaveBeenCalledTimes(1); /* keys.json only */
  });

  it("shows the executor's refusal by its code (stale)", async () => {
    const user = userEvent.setup();
    render(<CredentialForm poster={poster()} />);
    await fill(user);
    fetchMock.mockImplementationOnce(() => Promise.resolve(json(422, { error: { code: "stale" } })));
    await user.click(screen.getByRole("button", { name: "Зашифровать и проверить" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("Учётка не новее сохранённой.");
  });

  it("refuses a challenge whose write key is not the one keys.json gave (the anchor)", async () => {
    const user = userEvent.setup();
    render(<CredentialForm poster={poster()} />);
    await fill(user);
    const other = { ...ch, fields: ch.fields.map((f) => (f.key === "write_key" ? { ...f, value: "0000:0000:0000:0000:0000:0000:0000:0000" } : f)) };
    fetchMock.mockImplementationOnce(() => Promise.resolve(json(200, other)));
    await user.click(screen.getByRole("button", { name: "Зашифровать и проверить" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("другой ключ write-домена");
    expect(screen.queryByTestId("confirm")).toBeNull();
  });

  it("drops the challenge on a 5xx after confirm and says the outcome is unknown", async () => {
    const user = userEvent.setup();
    render(<CredentialForm poster={poster()} />);
    await issue(user);
    fetchMock.mockImplementationOnce(() => Promise.resolve(json(503, { error: { code: "outcome_unknown" } })));
    await user.type(screen.getByLabelText("Код TOTP изменений"), "123456");
    await user.click(screen.getByRole("button", { name: "Сохранить" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("Неизвестно, сохранена ли учётка");
    expect(screen.queryByTestId("confirm")).toBeNull();
  });

  it("gives the password manager nothing to save: no form, no username/password pair, autocomplete off", async () => {
    const user = userEvent.setup();
    const { container } = render(<CredentialForm poster={poster()} />);
    await screen.findByTestId("write-key");
    const check = () => {
      expect(container.querySelector("form")).toBeNull();
      for (const el of container.querySelectorAll("input:not([type=radio]), textarea")) {
        expect(el.getAttribute("autocomplete"), el.id).toBe("off");
        const names = [el.getAttribute("name"), el.id, el.getAttribute("autocomplete")].join(" ");
        expect(names, el.id).not.toMatch(/user|login|email|account-name|current-password|new-password/i);
      }
    };
    check();
    await user.click(screen.getByLabelText("Закрытый ключ (PEM)"));
    check();
    await user.click(screen.getByLabelText("Пароль", { selector: "input[type=radio]" }));
    check();
  });

  it("after a failed confirmation clears the code and never resends it", async () => {
    const user = userEvent.setup();
    render(<CredentialForm poster={poster()} />);
    await issue(user);
    fetchMock.mockImplementationOnce(() => Promise.resolve(json(429, { error: { code: "rate_limited" } })));
    const code = screen.getByLabelText("Код TOTP изменений") as HTMLInputElement;
    await user.type(code, "123456");
    await user.click(screen.getByRole("button", { name: "Сохранить" }));
    await waitFor(() => expect(code.value).toBe(""));
    expect(screen.getByTestId("failure")).toHaveTextContent("Слишком много запросов");
    await user.type(code, "123456");
    await user.click(screen.getByRole("button", { name: "Сохранить" }));
    expect(await screen.findByTestId("failure")).toHaveTextContent("Этот код уже использован");
    expect(fetchMock).toHaveBeenCalledTimes(3); /* keys.json, issue, one confirm */
  });

  it("refuses to confirm while the form is obscured", async () => {
    vis.unobscured = false;
    const user = userEvent.setup();
    render(<CredentialForm poster={poster()} />);
    await issue(user);
    await user.type(screen.getByLabelText("Код TOTP изменений"), "123456");
    expect(screen.getByRole("button", { name: "Сохранить" })).toBeDisabled();
    expect(screen.getByText("Окно перекрыто другим содержимым: подтверждение недоступно.")).toBeInTheDocument();
  });
});

describe("parseWriteKey", () => {
  it("takes the write domain and refuses anything else", () => {
    expect(parseWriteKey(keysDoc).publicKey).toEqual(publicKey);
    expect(() => parseWriteKey({ version: 1, domains: { write: { ...keysDoc.domains.write, fingerprint: "0000" } } })).toThrow();
    expect(() => parseWriteKey({ version: 1, domains: { read: keysDoc.domains.write } })).toThrow();
  });
});
