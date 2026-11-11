import { createRoute } from "@tanstack/react-router";
import { ChangesPage } from "@/features/changes/ChangesPage";
import { shellRoute } from "./index";

/** Changesets at /changes (metadata from the panel; the content stays in the executor). */
export const changesRoute = createRoute({ getParentRoute: () => shellRoute, path: "/changes", component: ChangesPage });
