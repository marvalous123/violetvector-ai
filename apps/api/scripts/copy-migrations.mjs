import { cpSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";

const outputRoot = resolve(process.argv[2] ?? "dist");
const migrations = resolve(outputRoot, "db", "migrations");
mkdirSync(migrations, { recursive: true });
cpSync(new URL("../src/db/migrations/", import.meta.url), migrations, { recursive: true });
