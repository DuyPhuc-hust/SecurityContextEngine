import { readdir, readFile } from "node:fs/promises";

const files = (await readdir(new URL("../schemas/", import.meta.url))).filter((file) => file.endsWith(".json"));
for (const file of files) {
  const parsed = JSON.parse(await readFile(new URL(`../schemas/${file}`, import.meta.url), "utf8"));
  if (!parsed.$schema || !parsed.title || parsed.type !== "object") throw new Error(`Invalid schema envelope: ${file}`);
}
console.log(`Validated ${files.length} schema envelopes.`);
