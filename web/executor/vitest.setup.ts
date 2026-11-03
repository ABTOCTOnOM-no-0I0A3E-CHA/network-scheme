import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";
import "@nms/shared/zod-jitless";

afterEach(cleanup);
