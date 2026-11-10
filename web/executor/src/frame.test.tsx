import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import "./i18n";
import ru from "./i18n/ru.json";
import { ConfirmPanel } from "./ConfirmPanel";
import { FrameContext } from "./frame";
import { Dialog } from "./session/Dialog";

const vis = vi.hoisted(() => ({ unobscured: true }));
vi.mock("./useUnobscured", () => ({ useUnobscured: () => ({ ref: () => {}, unobscured: vis.unobscured, supported: true }) }));

afterEach(() => vi.restoreAllMocks());

const frame = (over: Partial<{ compact: boolean; expand: () => void; dialog: (o: boolean) => void }> = {}) => ({ compact: false, expand: vi.fn(), dialog: vi.fn(), ...over });

describe("a confirmation in a low frame (review 4c.6 I1)", () => {
  it("is not a dead button: taller than the frame it says so and asks to expand; after the expand it can be confirmed", async () => {
    let height = 430;
    vi.spyOn(window, "innerHeight", "get").mockImplementation(() => height);
    vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(() => ({ height: 600 }) as DOMRect);
    const f = frame();
    const onConfirm = vi.fn();
    render(
      <FrameContext.Provider value={f}>
        <ConfirmPanel title="t" fields={[{ key: "a", label: "a", value: "1" }]} h={"ab".repeat(32)} confirmLabel="OK" busy={false} onConfirm={onConfirm} onCancel={() => {}} />
      </FrameContext.Provider>,
    );
    await userEvent.type(screen.getByLabelText(ru.executor.confirm.code), "123456");
    expect(screen.getByTestId("too-tall")).toHaveTextContent(ru.executor.tooTall);
    expect(screen.getByRole("button", { name: "OK" })).toBeDisabled();
    /* the notice is outside the observed element: it adds nothing to its height */
    expect(screen.getByTestId("confirm")).not.toContainElement(screen.getByTestId("too-tall"));
    await userEvent.click(screen.getByRole("button", { name: ru.executor.expand }));
    expect(f.expand).toHaveBeenCalledTimes(1);
    /* the panel gave the frame the viewport */
    height = 900;
    act(() => void window.dispatchEvent(new Event("resize")));
    expect(screen.queryByTestId("too-tall")).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: "OK" }));
    expect(onConfirm).toHaveBeenCalledWith("123456");
  });

  it("keeps the obscured notice outside the observed element", () => {
    vis.unobscured = false;
    render(<ConfirmPanel title="t" fields={[]} h={"ab".repeat(32)} confirmLabel="OK" busy={false} onConfirm={() => {}} onCancel={() => {}} />);
    expect(screen.getByTestId("confirm")).not.toContainElement(screen.getByText(ru.executor.obscured));
    vis.unobscured = true;
  });
});

describe("dialogs and the panel's frame", () => {
  it("a dialog asks for the whole viewport while it is open", () => {
    const f = frame();
    const { unmount } = render(
      <FrameContext.Provider value={f}>
        <Dialog title="x">body</Dialog>
      </FrameContext.Provider>,
    );
    expect(f.dialog).toHaveBeenCalledWith(true);
    unmount();
    expect(f.dialog).toHaveBeenLastCalledWith(false);
  });

  it("is never drawn into the compact strip", () => {
    render(
      <FrameContext.Provider value={frame({ compact: true })}>
        <Dialog title="x">body</Dialog>
      </FrameContext.Provider>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
