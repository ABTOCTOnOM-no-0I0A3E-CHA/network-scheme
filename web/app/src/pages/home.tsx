import { useState } from "react";
import { Moon, Sun } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getTheme, setTheme } from "@/lib/theme";

/** Placeholder landing page proving i18n, theming and the component set work end to end. */
export function Home() {
  const { t } = useTranslation();
  const [theme, setThemeState] = useState(getTheme);

  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    setThemeState(next);
  };

  return (
    <main className="mx-auto flex min-h-screen max-w-xl items-center p-6">
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{t("home.title")}</CardTitle>
          <CardDescription>{t("home.subtitle")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="outline" onClick={toggle} aria-label={t("theme.toggle")}>
            {theme === "dark" ? <Sun /> : <Moon />}
            {theme === "dark" ? t("theme.light") : t("theme.dark")}
          </Button>
        </CardContent>
      </Card>
    </main>
  );
}
