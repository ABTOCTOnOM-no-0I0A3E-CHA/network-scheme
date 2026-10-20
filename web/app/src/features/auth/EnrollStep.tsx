import { useEffect, useMemo, useRef, useState } from "react";
import QRCode from "qrcode";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { api } from "@/lib/api";
import { errorCode, errorKey } from "./errors";

/**
 * First-time TOTP enrollment: QR drawn locally into a canvas, manual key, then
 * confirmation with a code. Backup codes are shown once and live only in this
 * component's state.
 */
export function EnrollStep({
  challenge,
  otpauthUri,
  onDone,
  onExpired,
}: {
  challenge: string;
  otpauthUri: string;
  onDone: () => void;
  onExpired: () => void;
}) {
  const { t } = useTranslation();
  const canvas = useRef<HTMLCanvasElement>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [codes, setCodes] = useState<string[] | undefined>();

  const secret = useMemo(() => {
    try {
      return new URL(otpauthUri).searchParams.get("secret") ?? "";
    } catch {
      return "";
    }
  }, [otpauthUri]);

  useEffect(() => {
    if (canvas.current && !codes) QRCode.toCanvas(canvas.current, otpauthUri, { width: 200, margin: 1 }).catch(() => {});
  }, [otpauthUri, codes]);

  const confirm = async (value: string) => {
    setBusy(true);
    setError(undefined);
    const { data, error: err } = await api.POST("/api/auth/enroll", { body: { challenge, code: value } });
    setBusy(false);
    setCode("");
    if (data) return setCodes(data.backup_codes);
    if (errorCode(err) === "challenge_expired") return onExpired();
    setError(t(errorKey(err)));
  };

  if (codes) {
    return (
      <div className="grid gap-4">
        <p className="text-sm text-muted-foreground">{t("auth.codes.description")}</p>
        <ul className="grid grid-cols-2 gap-2 font-mono text-sm" data-testid="backup-codes">
          {codes.map((c) => (
            <li key={c} className="rounded-md border px-2 py-1 text-center">
              {c}
            </li>
          ))}
        </ul>
        <Button
          onClick={() => {
            setCodes(undefined);
            onDone();
          }}
        >
          {t("auth.codes.saved")}
        </Button>
      </div>
    );
  }

  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">{t("auth.enroll.description")}</p>
      <canvas ref={canvas} role="img" aria-label={t("auth.enroll.qr")} className="mx-auto rounded-md bg-white" />
      {secret && (
        <div className="grid gap-1 text-center">
          <span className="text-xs text-muted-foreground">{t("auth.enroll.manual")}</span>
          <code className="font-mono text-sm break-all select-all">{secret}</code>
        </div>
      )}
      <div className="grid justify-center gap-2">
        <InputOTP
          maxLength={6}
          inputMode="numeric"
          pattern="[0-9]*"
          autoComplete="one-time-code"
          aria-label={t("auth.totp.label")}
          value={code}
          disabled={busy}
          onChange={setCode}
          onComplete={(v) => void confirm(v)}
        >
          <InputOTPGroup>
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <InputOTPSlot key={i} index={i} />
            ))}
          </InputOTPGroup>
        </InputOTP>
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
