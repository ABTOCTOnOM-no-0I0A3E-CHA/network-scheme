import { useRef, useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Eye, EyeOff } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { loadReadKey, readKeyQueryKey, useReadKey } from "@/lib/keys";
import {
  AUTH_PROTOS,
  PRIV_PROTOS,
  buildPayload,
  generateKey,
  sealCredential,
  toBase64,
  validateSecret,
  type CredKind,
  type Owner,
  type SecretOf,
} from "@/lib/seal";
import { useSaveProfile, type Profile } from "./profiles";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

type Props = {
  /** `device:<id>` stores via the device profile endpoint, `scan:<id>` via the scan credential endpoint (snmp2c/snmp3 only). */
  owner: Owner;
  kind: CredKind;
  /** Current state of this kind, shown as status and date only (the content is never available). */
  profile?: Pick<Profile, "status" | "updated_at">;
  onSaved?: () => void;
};

/**
 * Sets one read credential. Secret fields are uncontrolled (read from the form on
 * submit, never kept in React state); the value is validated, sealed in the browser
 * to the current read-domain key and only the ciphertext leaves the form. Fields are
 * cleared after a successful save.
 */
export function ProfileForm({ owner, kind, profile, onSaved }: Props) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const formRef = useRef<HTMLFormElement>(null);
  const key = useReadKey();
  const save = useSaveProfile(owner);
  const [reveal, setReveal] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [done, setDone] = useState(false);

  if (owner.startsWith("scan:") && kind === "ssh_read") return null;

  const fieldLabel = (field: string) =>
    t(
      {
        community: "profile.community",
        user: "profile.user",
        auth_proto: "profile.authProto",
        auth_key: "profile.authKey",
        priv_proto: "profile.privProto",
        priv_key: "profile.privKey",
        username: "profile.username",
        password: "profile.password",
        private_key: "profile.privateKey",
      }[field] ?? "profile.title." + kind,
    );

  const read = (fd: FormData): SecretOf[CredKind] => {
    const f = (n: string) => String(fd.get(n) ?? "");
    if (kind === "snmp2c") return { community: f("community") };
    if (kind === "snmp3") return { user: f("user"), auth_proto: f("auth_proto"), auth_key: f("auth_key"), priv_proto: f("priv_proto"), priv_key: f("priv_key") };
    return { username: f("username"), password: f("password") || undefined, private_key: f("private_key") || undefined };
  };

  const generate = (name: string) => {
    const el = formRef.current?.elements.namedItem(name);
    if (el instanceof HTMLInputElement) el.value = generateKey();
  };

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    setError(undefined);
    setDone(false);
    const secret = read(new FormData(form));
    const problem = validateSecret(kind, secret as never);
    if (problem) return setError(t(`profile.err.${problem.problem}`, { field: fieldLabel(problem.field) }));
    try {
      /* always the current key: a rotated key must not be sealed to from a stale cache */
      const readKey = await qc.fetchQuery({ queryKey: readKeyQueryKey, queryFn: loadReadKey, staleTime: 0 });
      const ct = sealCredential(readKey.publicKey, buildPayload(owner, kind, secret as never));
      await save.mutateAsync({ kind, ciphertext: toBase64(ct), keyVersion: readKey.keyVersion });
      form.reset();
      setReveal(false);
      setDone(true);
      onSaved?.();
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      if (err instanceof ApiError) {
        if (err.code === "stale_key") void qc.invalidateQueries({ queryKey: readKeyQueryKey });
        return setError(t(errorKey({ error: { code: err.code } })));
      }
      setError(t(err instanceof TypeError ? thrownKey(err) : "errors.unknown"));
    }
  };

  const secretInput = (name: string, label: string, gen = false, autoComplete = "new-password") => (
    <div className="grid gap-2">
      <Label htmlFor={`${owner}-${kind}-${name}`}>{label}</Label>
      <div className="flex gap-2">
        <Input id={`${owner}-${kind}-${name}`} name={name} type={reveal ? "text" : "password"} autoComplete={autoComplete} spellCheck={false} />
        {gen && (
          <Button type="button" variant="outline" onClick={() => generate(name)}>
            {t("profile.generate")}
          </Button>
        )}
      </div>
    </div>
  );

  const textInput = (name: string, label: string) => (
    <div className="grid gap-2">
      <Label htmlFor={`${owner}-${kind}-${name}`}>{label}</Label>
      <Input id={`${owner}-${kind}-${name}`} name={name} autoComplete="off" spellCheck={false} />
    </div>
  );

  const proto = (name: string, label: string, options: readonly string[]) => (
    <div className="grid gap-2">
      <Label htmlFor={`${owner}-${kind}-${name}`}>{label}</Label>
      <select id={`${owner}-${kind}-${name}`} name={name} defaultValue={options[0]} className={SELECT_CLASS}>
        {options.map((o) => (
          <option key={o}>{o}</option>
        ))}
      </select>
    </div>
  );

  return (
    <form ref={formRef} onSubmit={submit} className="grid gap-4" noValidate autoComplete="off">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-medium">{t(`profile.title.${kind}`)}</h3>
        <p className="text-xs text-muted-foreground">
          {profile ? `${t(`profile.status.${profile.status}`)}, ${t("profile.updated", { date: new Date(profile.updated_at).toLocaleString("ru-RU") })}` : t("profile.status.none")}
        </p>
      </div>
      {kind === "snmp2c" && secretInput("community", t("profile.community"))}
      {kind === "snmp3" && (
        <>
          {textInput("user", t("profile.user"))}
          {proto("auth_proto", t("profile.authProto"), AUTH_PROTOS)}
          {secretInput("auth_key", t("profile.authKey"), true)}
          {proto("priv_proto", t("profile.privProto"), PRIV_PROTOS)}
          {secretInput("priv_key", t("profile.privKey"), true)}
        </>
      )}
      {kind === "ssh_read" && (
        <>
          {textInput("username", t("profile.username"))}
          {secretInput("password", t("profile.password"))}
          <div className="grid gap-2">
            <Label htmlFor={`${owner}-${kind}-private_key`}>{t("profile.privateKey")}</Label>
            <textarea
              id={`${owner}-${kind}-private_key`}
              name="private_key"
              rows={5}
              spellCheck={false}
              autoComplete="off"
              className={`${SELECT_CLASS} h-auto py-2 font-mono ${reveal ? "" : "[-webkit-text-security:disc]"}`}
            />
            <p className="text-xs text-muted-foreground">{t("profile.orKey")}</p>
          </div>
        </>
      )}
      <p className="text-xs text-muted-foreground">{t("profile.hint")}</p>
      <p className="text-xs text-muted-foreground">
        {key.data ? t("profile.key", { fingerprint: key.data.fingerprint }) : key.isError ? t("profile.keyError") : t("profile.keyLoading")}
      </p>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {done && (
        <p role="status" className="text-sm text-muted-foreground">
          {t("profile.saved")}
        </p>
      )}
      <div className="flex gap-2">
        <Button type="submit" disabled={save.isPending}>
          {t("profile.save")}
        </Button>
        <Button type="button" variant="ghost" size="icon" aria-label={t(reveal ? "profile.hide" : "profile.show")} aria-pressed={reveal} onClick={() => setReveal((r) => !r)}>
          {reveal ? <EyeOff /> : <Eye />}
        </Button>
      </div>
    </form>
  );
}
