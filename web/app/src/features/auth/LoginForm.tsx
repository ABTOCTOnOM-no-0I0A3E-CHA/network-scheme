import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { errorKey } from "./errors";

export type Challenge = { stage: "totp" | "enroll"; challenge: string; otpauthUri?: string };

/** Username/password step. Values are read from the form on submit and never kept in state. */
export function LoginForm({ notice, onChallenge }: { notice?: string; onChallenge: (c: Challenge) => void }) {
  const { t } = useTranslation();
  const [error, setError] = useState<string | undefined>(notice);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const fd = new FormData(form);
    const username = String(fd.get("username") ?? "");
    const password = String(fd.get("password") ?? "");
    setBusy(true);
    setError(undefined);
    const { data, error: err } = await api.POST("/api/auth/login", { body: { username, password } });
    setBusy(false);
    form.reset();
    if (data) onChallenge({ stage: data.stage, challenge: data.challenge, otpauthUri: data.otpauth_uri });
    else setError(t(errorKey(err)));
  };

  return (
    <form onSubmit={submit} className="grid gap-4" noValidate>
      <div className="grid gap-2">
        <Label htmlFor="username">{t("auth.username")}</Label>
        <Input id="username" name="username" autoComplete="username" autoFocus required />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="password">{t("auth.password")}</Label>
        <Input id="password" name="password" type="password" autoComplete="current-password" required />
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" disabled={busy}>
        {t("auth.submit")}
      </Button>
    </form>
  );
}
