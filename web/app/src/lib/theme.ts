export type Theme = "light" | "dark";

const KEY = "nms.theme";

function systemTheme(): Theme {
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

/** Returns the stored theme, or the OS preference when nothing valid is stored. */
export function getTheme(): Theme {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(KEY);
  } catch {
    /* storage unavailable: fall back to the OS preference */
  }
  return stored === "light" || stored === "dark" ? stored : systemTheme();
}

/** Applies the theme as the `dark` class on <html> and persists it in localStorage. */
export function setTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", theme === "dark");
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* the class is already applied; persistence is best-effort */
  }
}

/** Applies the effective theme without persisting it (used once at startup). */
export function applyTheme(): void {
  document.documentElement.classList.toggle("dark", getTheme() === "dark");
}
