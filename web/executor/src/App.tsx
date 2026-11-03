import { useTranslation } from "react-i18next";
import { StatusWidget } from "./StatusWidget";

export function App() {
  const { t } = useTranslation();
  return (
    <main className="mx-auto max-w-xl space-y-4 p-4">
      <h1 className="text-lg font-semibold">{t("executor.title")}</h1>
      <StatusWidget />
    </main>
  );
}
