import { createRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { canAckProblems } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { ProblemList } from "@/features/problems/ProblemList";
import { shellRoute } from "./index";

function ProblemsPage() {
  const { t } = useTranslation();
  const { data: session } = useSession();
  return (
    <section className="grid gap-4">
      <h1 className="text-xl font-semibold">{t("nav.problems")}</h1>
      <ProblemList canAck={canAckProblems(session)} />
    </section>
  );
}

/** Problem list at /problems. */
export const problemsRoute = createRoute({ getParentRoute: () => shellRoute, path: "/problems", component: ProblemsPage });
