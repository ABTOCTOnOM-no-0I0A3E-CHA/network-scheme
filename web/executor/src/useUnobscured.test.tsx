import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { observeUnobscured, useUnobscured, visibilityV2Supported } from "./useUnobscured";

type Entry = { isIntersecting: boolean; intersectionRatio: number; isVisible?: boolean };
let instances: FakeIO[] = [];
class FakeIO {
  disconnect = vi.fn();
  observe = vi.fn();
  constructor(
    readonly cb: (e: Entry[]) => void,
    readonly opts: Record<string, unknown>,
  ) {
    instances.push(this);
  }
  fire(...e: Entry[]) {
    this.cb(e);
  }
}
class FakeEntryV2 {
  get isVisible() {
    return true;
  }
}
class FakeEntryV1 {}

function install(entry: unknown) {
  vi.stubGlobal("IntersectionObserver", FakeIO);
  vi.stubGlobal("IntersectionObserverEntry", entry);
}
beforeEach(() => (instances = []));
afterEach(() => vi.unstubAllGlobals());

describe("observeUnobscured", () => {
  it("asks the browser to track visibility (v2), with the minimum delay and a full-visibility threshold", () => {
    install(FakeEntryV2);
    observeUnobscured(document.createElement("div"), () => {});
    expect(instances[0].opts).toMatchObject({ trackVisibility: true, delay: 100, threshold: [1] });
  });

  it("is true only when fully intersecting and isVisible; any covering turns it off again", () => {
    install(FakeEntryV2);
    const seen: boolean[] = [];
    observeUnobscured(document.createElement("div"), (v) => seen.push(v));
    const io = instances[0];
    io.fire({ isIntersecting: true, intersectionRatio: 1, isVisible: true });
    io.fire({ isIntersecting: true, intersectionRatio: 1, isVisible: false }); /* overlaid */
    io.fire({ isIntersecting: true, intersectionRatio: 0.6, isVisible: true }); /* partly clipped */
    io.fire({ isIntersecting: false, intersectionRatio: 0, isVisible: true });
    io.fire({ isIntersecting: true, intersectionRatio: 1 }); /* no isVisible at all */
    expect(seen).toEqual([false, true, false, false, false, false]);
  });

  it("only the latest entry of a batch counts", () => {
    install(FakeEntryV2);
    const seen: boolean[] = [];
    observeUnobscured(document.createElement("div"), (v) => seen.push(v));
    instances[0].fire({ isIntersecting: true, intersectionRatio: 1, isVisible: true }, { isIntersecting: true, intersectionRatio: 1, isVisible: false });
    expect(seen.at(-1)).toBe(false);
  });

  it("stops observing", () => {
    install(FakeEntryV2);
    const stop = observeUnobscured(document.createElement("div"), () => {});
    stop();
    expect(instances[0].disconnect).toHaveBeenCalled();
  });
});

describe("unsupported browsers refuse", () => {
  it("without IntersectionObserver v2 the answer is false and no observer is created", () => {
    install(FakeEntryV1);
    expect(visibilityV2Supported()).toBe(false);
    const seen: boolean[] = [];
    observeUnobscured(document.createElement("div"), (v) => seen.push(v));
    expect(instances).toHaveLength(0);
    expect(seen).toEqual([false]);
  });

  it("without IntersectionObserver at all", () => {
    vi.stubGlobal("IntersectionObserver", undefined);
    expect(visibilityV2Supported()).toBe(false);
  });
});

describe("useUnobscured", () => {
  it("is false until the browser says the element is visible, then follows it", () => {
    install(FakeEntryV2);
    const el = document.createElement("div");
    const ref = { current: el };
    const { result } = renderHook(() => useUnobscured(ref));
    expect(result.current).toEqual({ unobscured: false, supported: true });
    act(() => instances[0].fire({ isIntersecting: true, intersectionRatio: 1, isVisible: true }));
    expect(result.current.unobscured).toBe(true);
    act(() => instances[0].fire({ isIntersecting: true, intersectionRatio: 1, isVisible: false }));
    expect(result.current.unobscured).toBe(false);
  });

  it("stays false and reports unsupported when v2 is missing", () => {
    install(FakeEntryV1);
    const ref = { current: document.createElement("div") };
    const { result } = renderHook(() => useUnobscured(ref));
    expect(result.current).toEqual({ unobscured: false, supported: false });
  });
});
