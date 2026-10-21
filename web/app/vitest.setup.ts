import "@testing-library/jest-dom/vitest";

/* jsdom has no matchMedia; uPlot reads it while its module loads */
if (typeof window !== "undefined") window.matchMedia ??= ((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia;
