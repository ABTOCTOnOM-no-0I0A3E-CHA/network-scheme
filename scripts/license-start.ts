/*
 * Where license-checker should start for a project directory (used by check-licenses.sh).
 *
 * license-checker finds a package's dependencies only through node_modules directories next to or above the package
 * itself, and tells production dependencies from the rest by following them from the start directory. A member of a Bun
 * workspace has its dependencies hoisted into the workspace root's node_modules, so a scan started in the member
 * finds none and passes without checking anything. For a workspace member this builds a temporary directory with the
 * member's package.json and a node_modules that mirrors the root's: each package reduced to its package.json and
 * license files (all the checker reads), as a real flat install looks to it. A version that Bun had to nest in the
 * member's own node_modules would be missed, so that case is refused. Anything that is not a workspace member starts
 * where it is.
 *
 * usage: bun scripts/license-start.ts <dir>      prints the directory to start from
 *        bun scripts/license-start.ts --clean <tmp-dir>
 */
import { copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const LICENSE_FILE = /^(licen[sc]e|notice|copying|patents)/i;

/* mirrors the packages of src (a node_modules directory) into dst, with nested node_modules */
function mirror(src: string, dst: string): void {
  for (const e of readdirSync(src)) {
    if (e.startsWith(".")) continue;
    const dirs = e.startsWith("@") ? readdirSync(path.join(src, e)).map((p) => path.join(e, p)) : [e];
    for (const d of dirs) {
      const from = path.join(src, d);
      /* workspace members are linked here; they are not dependencies */
      if (lstatSync(from).isSymbolicLink() || !existsSync(path.join(from, "package.json"))) continue;
      const to = path.join(dst, d);
      mkdirSync(to, { recursive: true });
      for (const f of readdirSync(from)) {
        if (f === "package.json" || (LICENSE_FILE.test(f) && lstatSync(path.join(from, f)).isFile())) copyFileSync(path.join(from, f), path.join(to, f));
      }
      if (existsSync(path.join(from, "node_modules"))) mirror(path.join(from, "node_modules"), path.join(to, "node_modules"));
    }
  }
}

if (process.argv[2] === "--clean") {
  const tmp = path.resolve(process.argv[3] ?? "");
  if (path.basename(tmp).startsWith("nms-license-")) rmSync(tmp, { recursive: true, force: true });
} else {
  const dir = path.resolve(process.argv[2] ?? "");
  const root = path.dirname(dir);
  const rootPkg = path.join(root, "package.json");
  const member = existsSync(rootPkg) && Array.isArray((JSON.parse(readFileSync(rootPkg, "utf8")) as { workspaces?: unknown }).workspaces);
  if (!member) {
    console.log(dir);
  } else {
    const nested = existsSync(path.join(dir, "node_modules")) ? readdirSync(path.join(dir, "node_modules")).filter((e) => !e.startsWith(".")) : [];
    if (nested.length > 0) {
      console.error(`license-start: ${dir} has its own node_modules (${nested.join(", ")}): the scan would miss them`);
      process.exit(1);
    }
    const tmp = mkdtempSync(path.join(tmpdir(), "nms-license-"));
    copyFileSync(path.join(dir, "package.json"), path.join(tmp, "package.json"));
    mkdirSync(path.join(tmp, "node_modules"));
    mirror(path.join(root, "node_modules"), path.join(tmp, "node_modules"));
    console.log(tmp);
  }
}
