import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@/i18n";
import { clampWin, DeviceWindowsProvider, useDeviceWindows } from "./DeviceWindows";

afterEach(cleanup);

function Opener({ id, title }: { id: number; title: string }) {
  const w = useDeviceWindows()!;
  return <button onClick={() => w.open(id, title)}>open {id}</button>;
}

function setup() {
  const onOpenPage = vi.fn();
  render(
    <DeviceWindowsProvider renderBody={(id) => <input aria-label={`field ${id}`} />} onOpenPage={onOpenPage}>
      <Opener id={1} title="core-sw" />
      <Opener id={2} title="edge-rtr" />
      <Opener id={3} title={"<b>evil‮</b>"} />
    </DeviceWindowsProvider>,
  );
  return { onOpenPage };
}

const z = (name: string) => Number(screen.getByRole("dialog", { name }).style.zIndex);

describe("device windows", () => {
  it("is absent outside the provider", () => {
    function Probe() {
      return <span>{useDeviceWindows() === null ? "none" : "some"}</span>;
    }
    render(<Probe />);
    expect(screen.getByText("none")).toBeInTheDocument();
  });

  it("opens several windows, each focused when it opens, the newest on top", async () => {
    setup();
    await userEvent.click(screen.getByRole("button", { name: "open 1" }));
    const a = screen.getByRole("dialog", { name: "core-sw" });
    expect(a).toHaveFocus();
    expect(within(a).getByLabelText("field 1")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "open 2" }));
    expect(screen.getAllByRole("dialog")).toHaveLength(2);
    expect(z("edge-rtr")).toBeGreaterThan(z("core-sw"));
    /* reopening an open device brings its window forward instead of opening another */
    await userEvent.click(screen.getByRole("button", { name: "open 1" }));
    expect(screen.getAllByRole("dialog")).toHaveLength(2);
    expect(z("core-sw")).toBeGreaterThan(z("edge-rtr"));
  });

  it("opens at about 760x560 beside the click that opened it, the next one cascaded", async () => {
    setup();
    fireEvent.pointerDown(window, { clientX: 100, clientY: 150 });
    fireEvent.click(screen.getByRole("button", { name: "open 1" }));
    const a = screen.getByRole("dialog", { name: "core-sw" });
    expect([a.style.width, a.style.height]).toEqual(["760px", "560px"]);
    expect([a.style.left, a.style.top]).toEqual(["132px", "102px"]);
    fireEvent.pointerDown(window, { clientX: 100, clientY: 150 });
    fireEvent.click(screen.getByRole("button", { name: "open 2" }));
    const b = screen.getByRole("dialog", { name: "edge-rtr" });
    expect([b.style.left, b.style.top]).toEqual(["160px", "130px"]);
    /* opened from the keyboard after a click: centred, not beside the old click */
    fireEvent.pointerDown(window, { clientX: 100, clientY: 150 });
    fireEvent.keyDown(window, { key: "Enter" });
    fireEvent.click(screen.getByRole("button", { name: "open 3" }));
    expect(screen.getAllByRole("dialog").at(-1)!.style.top).toBe(`${72 + 2 * 28}px`);
  });

  it("opens left of a click near the right edge", () => {
    setup();
    fireEvent.pointerDown(window, { clientX: window.innerWidth - 100, clientY: 200 });
    fireEvent.click(screen.getByRole("button", { name: "open 1" }));
    const a = screen.getByRole("dialog", { name: "core-sw" });
    expect(parseFloat(a.style.left) + 760).toBeLessThanOrEqual(window.innerWidth - 100);
  });

  it("brings a window to the front when it is clicked", async () => {
    setup();
    await userEvent.click(screen.getByRole("button", { name: "open 1" }));
    await userEvent.click(screen.getByRole("button", { name: "open 2" }));
    const field = screen.getByLabelText("field 1");
    field.focus();
    fireEvent.pointerDown(field);
    expect(z("core-sw")).toBeGreaterThan(z("edge-rtr"));
    /* raising does not move DOM nodes, so the focused control keeps its focus */
    expect(screen.getAllByRole("dialog").map((d) => d.getAttribute("data-device-window"))).toEqual(["1", "2"]);
    expect(field).toHaveFocus();
  });

  it("closes the focused window with Escape and gives focus back to the opener", async () => {
    setup();
    const opener = screen.getByRole("button", { name: "open 1" });
    await userEvent.click(opener);
    await userEvent.click(screen.getByRole("button", { name: "open 2" }));
    screen.getByLabelText("field 1").focus();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "core-sw" })).toBeNull();
    expect(screen.getByRole("dialog", { name: "edge-rtr" })).toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("closes with its close button and opens the device page", async () => {
    const { onOpenPage } = setup();
    await userEvent.click(screen.getByRole("button", { name: "open 2" }));
    const w = screen.getByRole("dialog", { name: "edge-rtr" });
    await userEvent.click(within(w).getByRole("button", { name: "Открыть страницей" }));
    expect(onOpenPage).toHaveBeenCalledWith(2);
    await userEvent.click(within(w).getByRole("button", { name: "Закрыть окно" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("shows a device name as text only", async () => {
    setup();
    await userEvent.click(screen.getByRole("button", { name: "open 3" }));
    const w = screen.getByRole("dialog");
    expect(w.querySelector("b")).toBeNull();
    expect(within(w).getByRole("heading").textContent).toBe("<b>evil�</b>");
  });

  it("is dragged by its title bar and stays inside the viewport", async () => {
    setup();
    await userEvent.click(screen.getByRole("button", { name: "open 1" }));
    const w = screen.getByRole("dialog", { name: "core-sw" });
    const bar = within(w).getByRole("heading").parentElement!;
    const x0 = parseFloat(w.style.left);
    fireEvent.pointerDown(bar, { button: 0, clientX: 100, clientY: 100, pointerId: 1 });
    fireEvent.pointerMove(bar, { clientX: 130, clientY: 110, pointerId: 1 });
    fireEvent.pointerUp(bar, { pointerId: 1 });
    expect(parseFloat(w.style.left)).toBe(Math.min(x0 + 30, window.innerWidth - parseFloat(w.style.width) - 4));
    fireEvent.pointerDown(bar, { button: 0, clientX: 100, clientY: 100, pointerId: 1 });
    fireEvent.pointerMove(bar, { clientX: -5000, clientY: -5000, pointerId: 1 });
    fireEvent.pointerUp(bar, { pointerId: 1 });
    expect(w.style.left).toBe("4px");
    expect(w.style.top).toBe("4px");
  });
});

describe("clampWin", () => {
  const vp = { w: 1000, h: 800 };
  it("keeps a window inside the viewport", () => {
    expect(clampWin({ x: 900, y: 700, w: 500, h: 400 }, vp)).toEqual({ x: 496, y: 396, w: 500, h: 400 });
    expect(clampWin({ x: -50, y: -50, w: 500, h: 400 }, vp)).toEqual({ x: 4, y: 4, w: 500, h: 400 });
  });
  it("shrinks a window larger than the viewport", () => {
    expect(clampWin({ x: 0, y: 0, w: 3000, h: 3000 }, vp)).toEqual({ x: 4, y: 4, w: 992, h: 792 });
  });
});
