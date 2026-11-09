import { useTranslation } from "react-i18next";
import { StatusWidget } from "./StatusWidget";
import type { Poster } from "./client";
import { DevicesPage } from "./devices/DevicesPage";
import { RecordingsPage } from "./recordings/RecordingsPage";

export function App({ poster }: { poster?: Poster }) {
  const { t } = useTranslation();
  return (
    <main className="mx-auto max-w-xl space-y-4 p-4">
      <h1 className="text-lg font-semibold">{t("executor.title")}</h1>
      <StatusWidget />
      {poster && <DevicesPage poster={poster} />}
      {poster && <RecordingsPage poster={poster} />}
    </main>
  );
}
