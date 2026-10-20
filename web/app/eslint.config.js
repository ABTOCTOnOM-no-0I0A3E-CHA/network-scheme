import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "src/api/schema.d.ts"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  reactHooks.configs.flat.recommended,
  {
    languageOptions: { globals: { ...globals.browser, ...globals.node } },
  },
  {
    /* generated shadcn code */
    files: ["src/components/ui/**", "src/hooks/**"],
    rules: { "react-hooks/purity": "off", "react-hooks/set-state-in-effect": "off" },
  },
);
