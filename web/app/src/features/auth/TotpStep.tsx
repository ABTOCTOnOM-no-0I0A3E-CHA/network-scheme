import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { api } from "@/lib/api";
import { errorCode, errorKey, thrownKey } from "./errors";

/** Second factor: 6-digit TOTP, or a 16-character backup code behind a toggle. */
export function TotpStep({ challenge, onDone, onExpired }: { challenge: string; onDone: () => Promise<void>; onExpired: () => void }) {
  const { t } = useTranslation();
  const [backup, setBackup] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  const verify = async (value: string) => {
    setBusy(true);
    setError(undefined);
    try {
      const { error: err, response } = await api.POST("/api/auth/totp", { body: { challenge, code: value } });
      setCode("");
      if (response.ok) return await onDone();
      if (errorCode(err) === "challenge_expired") return onExpired();
      setError(t(errorKey(err)));
    } catch (e) {
      setError(t(thrownKey(e)));
    } finally {
      setBusy(false);
      setCode("");
    }
  };

  const submitBackup = (e: FormEvent) => {
    e.preventDefault();
    void verify(code.trim());
  };

  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">{t(backup ? "auth.backup.prompt" : "auth.totp.prompt")}</p>
      {backup ? (
        <form onSubmit={submitBackup} className="grid gap-2">
          <Label htmlFor="backup-code">{t("auth.backup.label")}</Label>
          <Input id="backup-code" value={code} maxLength={16} autoComplete="off" autoFocus onChange={(e) => setCode(e.target.value)} />
          <Button type="submit" disabled={busy || code.trim().length !== 16}>
            {t("auth.verify")}
          </Button>
        </form>
      ) : (
        <div className="grid justify-center gap-2">
          <InputOTP
            maxLength={6}
            inputMode="numeric"
            pattern="[0-9]*"
            autoFocus
            autoComplete="one-time-code"
            aria-label={t("auth.totp.label")}
            value={code}
            disabled={busy}
            onChange={setCode}
            onComplete={(v) => void verify(v)}
          >
            <InputOTPGroup>
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <InputOTPSlot key={i} index={i} />
              ))}
            </InputOTPGroup>
          </InputOTP>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button
        type="button"
        variant="link"
        className="justify-self-start px-0"
        onClick={() => {
          setBackup(!backup);
          setCode("");
          setError(undefined);
        }}
      >
        {t(backup ? "auth.totp.use" : "auth.backup.use")}
      </Button>
    </div>
  );
}
