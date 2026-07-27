import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";

const execFileAsync = promisify(execFile);

async function git(root, args) {
  const { stdout } = await execFileAsync("git", ["-C", root, ...args], { maxBuffer: 16 * 1024 * 1024 });
  return stdout;
}

function languageFor(file) {
  const extension = file.includes(".") ? file.slice(file.lastIndexOf(".") + 1).toLowerCase() : "other";
  return ({ ts: "TypeScript", tsx: "TypeScript", js: "JavaScript", jsx: "JavaScript", py: "Python", java: "Java", go: "Go", rs: "Rust", rb: "Ruby", php: "PHP", cs: "C#", c: "C", cpp: "C++", h: "C/C++", sql: "SQL", yaml: "YAML", yml: "YAML", json: "JSON" })[extension] ?? "other";
}

/** Build a deterministic source inventory without reading untracked or ignored files. */
export async function inventoryGitRepository(root) {
  const repositoryRoot = resolve(root);
  const revision = (await git(repositoryRoot, ["rev-parse", "HEAD"])).trim();
  const status = await git(repositoryRoot, ["status", "--short"]);
  const files = (await git(repositoryRoot, ["ls-files", "-z"])).split("\0").filter(Boolean);
  const languages = {};
  for (const file of files) {
    const language = languageFor(file);
    languages[language] = (languages[language] ?? 0) + 1;
  }
  return {
    repositoryRoot,
    revision,
    trackedFileCount: files.length,
    languages,
    dirty: status.length > 0,
    changedPaths: status.split("\n").filter(Boolean).map((line) => line.slice(3))
  };
}

export async function changedGitPaths(root, fromRevision, toRevision) {
  const output = await git(resolve(root), ["diff", "--name-only", `${fromRevision}..${toRevision}`]);
  return output.split("\n").filter(Boolean);
}

export async function trackedGitFiles(root) {
  return (await git(resolve(root), ["ls-files", "-z"])).split("\0").filter(Boolean);
}
