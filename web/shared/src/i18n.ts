import i18n from "i18next";
import { initReactI18next } from "react-i18next";

/* Russian is the default and fallback language; strings never leave the bundle. Each bundle passes its own dictionary. */
export function setupI18n(ru: Record<string, unknown>) {
  void i18n.use(initReactI18next).init({
    resources: { ru: { translation: ru } },
    lng: "ru",
    fallbackLng: "ru",
    interpolation: { escapeValue: false },
    initAsync: false,
  });
  return i18n;
}
