import { useState } from "react";
import { createRoute, redirect, useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { thrownKey } from "@/features/auth/errors";
import { EnrollStep } from "@/features/auth/EnrollStep";
import { LoginForm, type Challenge } from "@/features/auth/LoginForm";
import { TotpStep } from "@/features/auth/TotpStep";
import { meQuery, refreshSession } from "@/features/auth/useSession";
import { queryClient } from "@/lib/query";
import { rootRoute } from "./__root";

function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [step, setStep] = useState<Challenge | undefined>();
  const [notice, setNotice] = useState<string | undefined>();

  /*
   * A fresh GET /me caches the session and the CSRF token before entering the shell.
   * If it fails the second factor is already spent, so fall back to the credentials step.
   */
  const done = async () => {
    try {
      await refreshSession();
    } catch (e) {
      setStep(undefined);
      setNotice(thrownKey(e));
      return;
    }
    await navigate({ to: "/" });
  };
  const restart = () => {
    setStep(undefined);
    setNotice("errors.challenge_expired");
  };

  const stage = step?.stage ?? "credentials";
  return (
    <main className="mx-auto flex min-h-screen max-w-sm items-center p-6">
      <Card className="w-full">
        <CardHeader>
          <CardTitle>{t("app.name")}</CardTitle>
          <CardDescription>{t(`auth.title.${stage}`)}</CardDescription>
        </CardHeader>
        <CardContent>
          {!step && <LoginForm key={notice} notice={notice ? t(notice) : undefined} onChallenge={setStep} />}
          {step?.stage === "totp" && <TotpStep challenge={step.challenge} onDone={done} onExpired={restart} />}
          {step?.stage === "enroll" && step.otpauthUri && (
            <EnrollStep challenge={step.challenge} otpauthUri={step.otpauthUri} onDone={done} onExpired={restart} />
          )}
        </CardContent>
      </Card>
    </main>
  );
}

/** /login — redirects to the shell when a session already exists. */
export const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  beforeLoad: async () => {
    if (await queryClient.ensureQueryData(meQuery)) throw redirect({ to: "/" });
  },
  component: LoginPage,
});
