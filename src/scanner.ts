import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import type { Finding, ScanResult } from "./types.ts";
import {
  ALWAYS_MALICIOUS_FILENAMES,
  MALICIOUS_FILE_HASHES,
  PERSISTENCE_FILES,
  INJECTED_PACKAGES,
  COMPROMISED_PACKAGE_VERSIONS,
  MALICIOUS_GIT_AUTHOR,
  MALICIOUS_COMMIT_HASH,
  MALICIOUS_HOOK_STRINGS,
  MALICIOUS_TASK_STRINGS,
  NETWORK_IOCS,
} from "./iocs.ts";

const MAX_HASH_FILE_SIZE = 10 * 1024 * 1024;

function sha256(filePath: string): string {
  const stat = fs.statSync(filePath);
  if (stat.size > MAX_HASH_FILE_SIZE) return "";
  const content = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(content).digest("hex");
}

function walk(
  dir: string,
  skipDirs: Set<string>,
  onFile: (filePath: string, rel: string) => void,
  onDir: (dirPath: string, rel: string) => void,
  root: string = dir
): void {
  const queue: string[] = [dir];

  while (queue.length > 0) {
    const current = queue.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const full = path.join(current, entry.name);
      const rel = path.relative(root, full);

      if (entry.isSymbolicLink()) continue;

      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue;
        onDir(full, rel);
        queue.push(full);
      } else if (entry.isFile()) {
        onFile(full, rel);
      }
    }
  }
}

export function scan(targetDir: string, scanNodeModules: boolean): ScanResult {
  const findings: Finding[] = [];
  let scannedFiles = 0;
  let scannedDirs = 0;

  const skipDirs = new Set(["node_modules"]);
  if (scanNodeModules) skipDirs.clear();
  const nodeModulesPath = path.join(targetDir, "node_modules");

  const processFile = (filePath: string, rel: string) => {
    scannedFiles++;

    const basename = path.basename(filePath);
    const basenameLower = basename.toLowerCase();

    if (ALWAYS_MALICIOUS_FILENAMES.has(basenameLower)) {
      findings.push({
        severity: "critical",
        category: "malicious-file",
        path: rel,
        detail: `Malicious worm payload: ${basename}`,
        fixable: true,
        label: basename,
      });
      return;
    }

    if (
      filePath.endsWith(".js") ||
      filePath.endsWith(".mjs") ||
      filePath.endsWith(".cjs")
    ) {
      try {
        const hash = sha256(filePath);
        if (hash && MALICIOUS_FILE_HASHES.has(hash)) {
          findings.push({
            severity: "critical",
            category: "malicious-file-hash",
            path: rel,
            detail: `SHA256 matches known malicious payload: ${hash.slice(0, 16)}...`,
            fixable: true,
            label: path.basename(rel),
          });
        }
      } catch {
      }
    }

    if (basename === "package.json") {
      checkPackageJson(filePath, rel, findings);
    }

    if (
      basename === "settings.json" &&
      rel.split(path.sep).includes(".claude")
    ) {
      checkClaudeSettings(filePath, rel, findings);
    }

    if (
      basename === "tasks.json" &&
      rel.split(path.sep).includes(".vscode")
    ) {
      checkVscodeTasks(filePath, rel, findings);
    }

    if (
      filePath.endsWith(".js") ||
      filePath.endsWith(".mjs") ||
      filePath.endsWith(".cjs") ||
      filePath.endsWith(".ts") ||
      filePath.endsWith(".tsx")
    ) {
      checkNetworkIocs(filePath, rel, findings);
    }
  };

  const processDir = (dirPath: string, rel: string) => {
    scannedDirs++;

    const basename = path.basename(dirPath);

    const maliciousFiles = PERSISTENCE_FILES[basename];
    if (maliciousFiles) {
      for (const mf of maliciousFiles) {
        const candidate = path.join(dirPath, mf);
        if (fs.existsSync(candidate)) {
          findings.push({
            severity: "critical",
            category: "persistence",
            path: path.join(rel, mf),
            detail: `Worm persistence file in ${basename}/: ${mf}`,
            fixable: true,
            label: mf,
          });
        }
      }
    }
  };

  walk(targetDir, skipDirs, processFile, processDir);
  checkTopLevelHiddenDirs(targetDir, findings);

  if (fs.existsSync(nodeModulesPath)) {
    checkNodeModules(nodeModulesPath, findings);
  }

  checkGitHistory(targetDir, findings);

  return { findings, scannedFiles, scannedDirs };
}

function isMaliciousScriptValue(cmd: unknown): boolean {
  const cmds = Array.isArray(cmd) ? cmd.map(String) : [String(cmd)];
  return cmds.some(
    (s) =>
      s.includes("tanstack_runner.js") ||
      s.includes("router_init.js") ||
      s.includes("router_runtime.js")
  );
}

function checkPackageJson(filePath: string, rel: string, findings: Finding[]) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const pkg = JSON.parse(content);

    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
      ...pkg.optionalDependencies,
      ...pkg.peerDependencies,
    };

    for (const injected of INJECTED_PACKAGES) {
      if (injected in allDeps) {
        const depSection = Object.keys({
          ...(pkg.optionalDependencies || {}),
        }).includes(injected)
          ? "optionalDependencies"
          : "dependencies";
        findings.push({
          severity: "critical",
          category: "injected-dependency",
          path: rel,
          detail: `Injected malicious package "${injected}" found in ${depSection}`,
          fixable: true,
          label: injected,
        });
      }
    }

    const scripts = pkg.scripts || {};
    for (const [scriptName, scriptCmd] of Object.entries(scripts)) {
      if (isMaliciousScriptValue(scriptCmd)) {
        findings.push({
          severity: "critical",
          category: "malicious-script",
          path: rel,
          detail: `Malicious lifecycle hook in scripts.${scriptName}: ${JSON.stringify(scriptCmd)}`,
          fixable: true,
          label: `scripts.${scriptName}`,
        });
      }
    }

    for (const [pkgName, badVersions] of Object.entries(COMPROMISED_PACKAGE_VERSIONS)) {
      const specifier = allDeps[pkgName];
      if (specifier != null) {
        const matched = badVersions.find((bv) => String(specifier).includes(bv));
        if (matched) {
          findings.push({
            severity: "high",
            category: "compromised-version",
            path: rel,
            detail: `Package "${pkgName}@${specifier}" matches known compromised version ${matched} — verify lockfile and reinstall`,
            fixable: false,
            label: `${pkgName}@${specifier}`,
          });
        }
      }

      if (pkg.name === pkgName && badVersions.includes(pkg.version)) {
        findings.push({
          severity: "critical",
          category: "compromised-installed-package",
          path: rel,
          detail: `Installed package "${pkgName}@${pkg.version}" is a known compromised version`,
          fixable: false,
          label: `${pkgName}@${pkg.version}`,
        });
      }
    }
  } catch {
  }
}

function checkClaudeSettings(
  filePath: string,
  rel: string,
  findings: Finding[]
) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const found = MALICIOUS_HOOK_STRINGS.filter((s) => content.includes(s));
    if (found.length > 0) {
      findings.push({
        severity: "critical",
        category: "persistence-hooks",
        path: rel,
        detail: `Claude Code settings contain malicious hook references: ${found.join(", ")}`,
        fixable: false,
        label: found.join(", "),
      });
    }
  } catch {
  }
}

function checkVscodeTasks(filePath: string, rel: string, findings: Finding[]) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const found = MALICIOUS_TASK_STRINGS.filter((s) => content.includes(s));
    if (found.length > 0) {
      findings.push({
        severity: "critical",
        category: "persistence-tasks",
        path: rel,
        detail: `VS Code tasks contain malicious script references: ${found.join(", ")}`,
        fixable: false,
        label: found.join(", "),
      });
    }

    const parsed = JSON.parse(content);
    const tasks: any[] = Array.isArray(parsed.tasks) ? parsed.tasks : [];
    for (const task of tasks) {
      if (task?.runOptions?.runOn === "folderOpen") {
        findings.push({
          severity: "high",
          category: "auto-run-task",
          path: rel,
          detail: `VS Code task "${task.label || "unnamed"}" auto-runs on folder open`,
          fixable: false,
          label: task.label || "unnamed task",
        });
      }
    }
  } catch {
  }
}

function checkTopLevelHiddenDirs(targetDir: string, findings: Finding[]) {
  for (const [dirName, maliciousFiles] of Object.entries(PERSISTENCE_FILES)) {
    const dirPath = path.join(targetDir, dirName);
    if (!fs.existsSync(dirPath)) continue;

    for (const mf of maliciousFiles) {
      const candidate = path.join(dirPath, mf);
      if (fs.existsSync(candidate)) {
        const rel = path.join(dirName, mf);
        if (!findings.some((f) => f.path === rel)) {
          findings.push({
            severity: "critical",
            category: "persistence",
            path: rel,
            detail: `Worm persistence file in ${dirName}/: ${mf}`,
            fixable: true,
            label: mf,
          });
        }
      }
    }
  }
}

function checkNodeModules(nodeModulesPath: string, findings: Finding[]) {
  const tanstackPath = path.join(nodeModulesPath, "@tanstack");
  if (!fs.existsSync(tanstackPath)) return;

  let packages: string[];
  try {
    packages = fs.readdirSync(tanstackPath);
  } catch {
    return;
  }

  for (const pkg of packages) {
    const pkgPath = path.join(tanstackPath, pkg);

    const routerInit = path.join(pkgPath, "router_init.js");
    if (fs.existsSync(routerInit)) {
      findings.push({
        severity: "critical",
        category: "compromised-package",
        path: `node_modules/@tanstack/${pkg}/router_init.js`,
        detail: `Compromised @tanstack package contains malicious payload`,
        fixable: true,
        label: `@tanstack/${pkg}`,
      });
    }

    try {
      const pkgFiles = fs.readdirSync(pkgPath, { withFileTypes: true });
      for (const f of pkgFiles) {
        if (f.isSymbolicLink()) continue; // SC-05
        if (f.isFile() && f.name.endsWith(".js")) {
          const full = path.join(pkgPath, f.name);
          try {
            const hash = sha256(full);
            if (hash && MALICIOUS_FILE_HASHES.has(hash)) {
              findings.push({
                severity: "critical",
                category: "compromised-package-hash",
                path: `node_modules/@tanstack/${pkg}/${f.name}`,
                detail: `SHA256 matches malicious payload: ${hash.slice(0, 16)}...`,
                fixable: true,
                label: `@tanstack/${pkg}`,
              });
            }
          } catch {
          }
        }
      }
    } catch {
    }

    const pkgJson = path.join(pkgPath, "package.json");
    if (fs.existsSync(pkgJson)) {
      checkPackageJson(
        pkgJson,
        `node_modules/@tanstack/${pkg}/package.json`,
        findings
      );
    }
  }
}

const MAX_CONTENT_SCAN_SIZE = 1 * 1024 * 1024;

function checkNetworkIocs(filePath: string, rel: string, findings: Finding[]) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > MAX_CONTENT_SCAN_SIZE) return;
    const content = fs.readFileSync(filePath, "utf8");
    const found = NETWORK_IOCS.filter((ioc) => content.includes(ioc));
    if (found.length > 0) {
      findings.push({
        severity: "high",
        category: "network-ioc",
        path: rel,
        detail: `File references known C2/exfiltration endpoint: ${found.join(", ")}`,
        fixable: false,
        label: found.join(", "),
      });
    }
  } catch {
  }
}

function checkGitHistory(targetDir: string, findings: Finding[]) {
  const authorResult = spawnSync(
    "git",
    ["-C", targetDir, "log", "--all", "--format=%H %ae %s", `--author=${MALICIOUS_GIT_AUTHOR}`],
    { encoding: "utf8", timeout: 10000 }
  );

  if (authorResult.status === 0 && authorResult.stdout.trim()) {
    const lines = authorResult.stdout.trim().split("\n").filter(Boolean);
    for (const line of lines) {
      const [hash, ...rest] = line.split(" ");
      findings.push({
        severity: "critical",
        category: "malicious-commit",
        path: `.git`,
        detail: `Unauthorized commit from worm author (${MALICIOUS_GIT_AUTHOR}): ${(hash ?? "").slice(0, 12)} — ${rest.slice(1).join(" ")}`,
        fixable: false,
        label: (hash ?? "").slice(0, 12),
      });
    }
  }

  const hashResult = spawnSync(
    "git",
    ["-C", targetDir, "cat-file", "-e", MALICIOUS_COMMIT_HASH],
    { encoding: "utf8", timeout: 5000 }
  );

  if (hashResult.status === 0) {
    findings.push({
      severity: "critical",
      category: "known-malicious-commit",
      path: ".git",
      detail: `Known malicious commit hash present: ${MALICIOUS_COMMIT_HASH}`,
      fixable: false,
      label: MALICIOUS_COMMIT_HASH.slice(0, 12),
    });
  }
}
