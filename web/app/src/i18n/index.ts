import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import ru from "./ru.json";

/* Russian is the default and fallback language; strings never leave the bundle. */
void i18n.use(initReactI18next).init({
  resources: { ru: { translation: ru } },
  lng: "ru",
  fallbackLng: "ru",
  interpolation: { escapeValue: false },
  initAsync: false,
});

export default i18n;
