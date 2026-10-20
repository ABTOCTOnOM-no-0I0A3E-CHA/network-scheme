import { beforeEach, describe, expect, it, vi } from "vitest";
import { getTheme, setTheme } from "./theme";

function mockPrefersDark(dark: boolean) {
  vi.stubGlobal(
    "matchMedia",
    vi.fn().mockImplementation((query: string) => ({
      matches: dark && query === "(prefers-color-scheme: dark)",
      media: query,
    })),
  );
}

describe("theme", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.className = "";
    mockPrefersDark(false);
  });

  it("defaults to prefers-color-scheme", () => {
    expect(getTheme()).toBe("light");
    mockPrefersDark(true);
    expect(getTheme()).toBe("dark");
  });

  it("setTheme toggles the dark class and persists the value", () => {
    setTheme("dark");
    expect(document.documentElement).toHaveClass("dark");
    expect(localStorage.getItem("nms.theme")).toBe("dark");
    expect(getTheme()).toBe("dark");

    setTheme("light");
    expect(document.documentElement).not.toHaveClass("dark");
    expect(localStorage.getItem("nms.theme")).toBe("light");
    expect(getTheme()).toBe("light");
  });

  it("a stored value wins over prefers-color-scheme", () => {
    mockPrefersDark(true);
    localStorage.setItem("nms.theme", "light");
    expect(getTheme()).toBe("light");
  });

  it("ignores an invalid stored value", () => {
    localStorage.setItem("nms.theme", "purple");
    expect(getTheme()).toBe("light");
  });
});
