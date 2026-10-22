import { useTranslation } from "react-i18next";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { safeText } from "@/lib/text";
import type { Group } from "@/features/devices/api";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

type Props = {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  /** Known groups (global admin); without them the id is typed in. */
  groups?: Group[];
};

/** Group picker: a select when the groups can be listed, otherwise a numeric id field. */
export function GroupField({ id, label, value, onChange, groups }: Props) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={id}>{label}</Label>
      {groups ? (
        <select id={id} className={SELECT_CLASS} value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">{t("common.choose")}</option>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {safeText(g.name)}
            </option>
          ))}
        </select>
      ) : (
        <Input id={id} type="number" min={1} value={value} onChange={(e) => onChange(e.target.value)} />
      )}
    </div>
  );
}
