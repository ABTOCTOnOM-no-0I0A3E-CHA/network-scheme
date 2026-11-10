import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import "../i18n";
import { Terminal, encodeKey } from "./Terminal";

const hostile = '<img src=x onerror="alert(1)"><style>*{}</style><script>x()</script>\x1b]52;c;aGk=\x07\x1b[31mred';

describe("Terminal", () => {
  it("renders device output only as text", () => {
    render(<Terminal output={hostile} onKeys={() => {}} onPaste={() => {}} />);
    const pane = screen.getByTestId("terminal");
    expect(pane.textContent).toBe(hostile);
    expect(pane.children).toHaveLength(0);
    expect(document.querySelector("img, script, style")).toBeNull();
  });

  it("creates no <style> element when it mounts and updates", () => {
    const create = vi.spyOn(document, "createElement");
    const { rerender, unmount } = render(<Terminal output="a" onKeys={() => {}} onPaste={() => {}} />);
    rerender(<Terminal output={"a\nb"} onKeys={() => {}} onPaste={() => {}} />);
    expect(create.mock.calls.filter(([tag]) => tag.toLowerCase() === "style")).toEqual([]);
    expect(document.querySelectorAll("style")).toHaveLength(0);
    unmount();
    create.mockRestore();
  });

  it("sends key frames and pastes through the callbacks", () => {
    const onKeys = vi.fn();
    const onPaste = vi.fn();
    render(<Terminal output="" onKeys={onKeys} onPaste={onPaste} />);
    const pane = screen.getByTestId("terminal");
    fireEvent.keyDown(pane, { key: "s" });
    fireEvent.keyDown(pane, { key: "Enter" });
    fireEvent.keyDown(pane, { key: "ArrowUp" });
    fireEvent.keyDown(pane, { key: "u", ctrlKey: true });
    fireEvent.keyDown(pane, { key: "F5" });
    fireEvent.paste(pane, { clipboardData: { getData: () => "line1\nline2" } });
    expect(onKeys.mock.calls).toEqual([["s"], ["\r"], ["\x1b[A"], ["\x15"]]);
    expect(onPaste).toHaveBeenCalledWith("line1\nline2");
  });

  it("forwards nothing in read-only mode", () => {
    const onKeys = vi.fn();
    const onPaste = vi.fn();
    render(<Terminal output="" onKeys={onKeys} onPaste={onPaste} readOnly />);
    const pane = screen.getByTestId("terminal");
    fireEvent.keyDown(pane, { key: "a" });
    fireEvent.paste(pane, { clipboardData: { getData: () => "x" } });
    expect(onKeys).not.toHaveBeenCalled();
    expect(onPaste).not.toHaveBeenCalled();
  });

  it("encodes only known keys", () => {
    const k = (key: string, mods: Partial<{ ctrlKey: boolean; altKey: boolean; metaKey: boolean }> = {}) =>
      encodeKey({ key, ctrlKey: false, altKey: false, metaKey: false, ...mods });
    expect(k("Delete")).toBe("\x1b[3~");
    expect(k("Escape")).toBeNull();
    expect(k("a", { altKey: true })).toBeNull();
    expect(k("1", { ctrlKey: true })).toBeNull();
    expect(k("я")).toBe("я");
  });
});
