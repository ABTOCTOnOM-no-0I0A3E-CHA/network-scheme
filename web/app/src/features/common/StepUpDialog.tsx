import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Dialog } from "radix-ui";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { errorCode, errorKey, thrownKey } from "@/features/auth/errors";
import { api, notifyUnauthorized } from "@/lib/api";
import { stepUpStore } from "./stepup";

/** Host of the step-up prompt; mount once inside the authenticated shell. */
export function StepUpDialog() {
  const open = useSyncExternalStore(stepUpStore.subscribe, stepUpStore.isOpen);
  /* the host going away (logout, session loss) must not leave the prompt pending for the next mount */
  useEffect(() => () => stepUpStore.settle(false), []);
  return (
    <Dialog.Root open={open} onOpenChange={(o) => !o && stepUpStore.settle(false)}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 grid w-full max-w-sm -translate-x-1/2 -translate-y-1/2 gap-4 rounded-lg border bg-background p-6 shadow-lg">
          <StepUpForm />
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/* Mounted only while open, so its state resets for every prompt. */
function StepUpForm() {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const otp = useRef<HTMLInputElement>(null);

  /* the input is disabled while verifying and loses focus; give it back after a failed attempt */
  useEffect(() => {
    if (!busy && error) otp.current?.focus();
  }, [busy, error]);

  const verify = async (value: string) => {
    setBusy(true);
    setError(undefined);
    try {
      const { error: err, response } = await api.POST("/api/auth/stepup", {
        params: { header: { "X-CSRF-Token": "" } },
        body: { code: value },
      });
      if (response.ok) return stepUpStore.settle(true);
      /* a wrong code answers 401 too; only these codes mean the session itself is gone */
      const code = errorCode(err);
      if (code === "session_expired" || code === "unauthenticated") {
        stepUpStore.settle(false);
        return notifyUnauthorized();
      }
      setError(t(errorKey(err)));
    } catch (e) {
      setError(t(thrownKey(e)));
    } finally {
      setBusy(false);
      setCode("");
    }
  };

  return (
    <>
      <Dialog.Title className="text-lg font-semibold">{t("stepup.title")}</Dialog.Title>
      <Dialog.Description className="text-sm text-muted-foreground">{t("stepup.description")}</Dialog.Description>
      <div className="grid justify-center gap-2">
        <InputOTP
          maxLength={6}
          inputMode="numeric"
          pattern="[0-9]*"
          ref={otp}
          autoFocus
          autoComplete="one-time-code"
          aria-label={t("stepup.label")}
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
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="button" variant="outline" onClick={() => stepUpStore.settle(false)}>
        {t("stepup.cancel")}
      </Button>
    </>
  );
}
