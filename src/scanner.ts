import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execSync } from "node:child_process";
import type { Finding, ScanResult } from "./types.ts";
import {
  ALWAYS_MALICIOUS_FILENAMES,
  MALICIOUS_FILE_HASHES,
  PERSISTENCE_FILES,
  INJECTED_PACKAGES,
  MALICIOUS_GIT_AUTHOR,
  MALICIOUS_COMMIT_HASH,
  MALICIOUS_HOOK_STRINGS,
  MALICIOUS_TASK_STRINGS,
} from "./iocs.ts";

function sha256(filePath: string): string {
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
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(root, full);

    if (entry.isDirectory()) {
      if (skipDirs.has(entry.name)) continue;
      onDir(full, rel);
      walk(full, skipDirs, onFile, onDir, root);
    } else if (entry.isFile()) {
      onFile(full, rel);
    }
  }
}

export function scan(targetDir: string, scanNodeModules: boolean): ScanResult {
  const findings: Finding[] = [];
  let scannedFiles = 0;
  let scannedDirs = 0;

  const skipDirs = new Set(["node_modules"]);
  if (scanNodeModules) skipDirs.clear();
  // Always check top-level node_modules explicitly
  const nodeModulesPath = path.join(targetDir, "node_modules");

  const processFile = (filePath: string, rel: string) => {
    scannedFiles++;

    const basename = path.basename(filePath);

    // Check always-malicious filenames
    if (ALWAYS_MALICIOUS_FILENAMES.has(basename)) {
      findings.push({
        severity: "critical",
        category: "malicious-file",
        path: rel,
        detail: `Malicious worm payload: ${basename}`,
        fixable: true,
      });
      return; // no need to hash, confirmed bad
    }

    // Hash check for any .js file that could be renamed
    if (filePath.endsWith(".js")) {
      try {
        const hash = sha256(filePath);
        if (MALICIOUS_FILE_HASHES.has(hash)) {
          findings.push({
            severity: "critical",
            category: "malicious-file-hash",
            path: rel,
            detail: `SHA256 matches known malicious payload: ${hash.slice(0, 16)}...`,
            fixable: true,
          });
        }
      } catch {
        // skip unreadable files
      }
    }

    // Check package.json for injected deps/hooks
    if (basename === "package.json") {
      checkPackageJson(filePath, rel, findings);
    }

    // Check .claude/settings.json for malicious hooks
    if (
      basename === "settings.json" &&
      rel.split(path.sep).includes(".claude")
    ) {
      checkClaudeSettings(filePath, rel, findings);
    }

    // Check .vscode/tasks.json for malicious auto-run tasks
    if (
      basename === "tasks.json" &&
      rel.split(path.sep).includes(".vscode")
    ) {
      checkVscodeTasks(filePath, rel, findings);
    }
  };

  const processDir = (dirPath: string, rel: string) => {
    scannedDirs++;

    const basename = path.basename(dirPath);
    const parentBasename = path.basename(path.dirname(dirPath));

    // Check persistence files in .claude and .vscode
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
          });
        }
      }
    }
  };

  // Walk target dir (skip node_modules by default)
  walk(targetDir, skipDirs, processFile, processDir);

  // Also check top-level hidden dirs explicitly
  checkTopLevelHiddenDirs(targetDir, findings);

  // Scan node_modules for compromised @tanstack packages
  if (fs.existsSync(nodeModulesPath)) {
    checkNodeModules(nodeModulesPath, findings);
  }

  // Check git history
  checkGitHistory(targetDir, findings);

  return { findings, scannedFiles, scannedDirs };
}

function checkPackageJson(filePath: string, rel: string, findings: Finding[]) {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const pkg = JSON.parse(content);

    // Check optionalDependencies for injected packages
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
        });
      }
    }

    // Check scripts for malicious hook patterns
    const scripts = pkg.scripts || {};
    for (const [scriptName, scriptCmd] of Object.entries(scripts)) {
      if (typeof scriptCmd === "string") {
        if (
          scriptCmd.includes("tanstack_runner.js") ||
          scriptCmd.includes("router_init.js") ||
          scriptCmd.includes("router_runtime.js")
        ) {
          findings.push({
            severity: "critical",
            category: "malicious-script",
            path: rel,
            detail: `Malicious lifecycle hook in scripts.${scriptName}: "${scriptCmd}"`,
            fixable: true,
          });
        }
      }
    }
  } catch {
    // skip unparseable package.json
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
        fixable: false, // requires manual review
      });
    }
  } catch {
    // skip
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
      });
    }

    // Check for folderOpen auto-run tasks
    const parsed = JSON.parse(content);
    const tasks: any[] = parsed.tasks || [];
    for (const task of tasks) {
      if (task?.runOptions?.runOn === "folderOpen") {
        findings.push({
          severity: "high",
          category: "auto-run-task",
          path: rel,
          detail: `VS Code task "${task.label || "unnamed"}" auto-runs on folder open`,
          fixable: false,
        });
      }
    }
  } catch {
    // skip
  }
}

function checkTopLevelHiddenDirs(targetDir: string, findings: Finding[]) {
  // Check .claude and .vscode at the root explicitly
  for (const [dirName, maliciousFiles] of Object.entries(PERSISTENCE_FILES)) {
    const dirPath = path.join(targetDir, dirName);
    if (!fs.existsSync(dirPath)) continue;

    for (const mf of maliciousFiles) {
      const candidate = path.join(dirPath, mf);
      if (fs.existsSync(candidate)) {
        const rel = path.join(dirName, mf);
        // Avoid duplicate if walk already found it
        if (!findings.some((f) => f.path === rel)) {
          findings.push({
            severity: "critical",
            category: "persistence",
            path: rel,
            detail: `Worm persistence file in ${dirName}/: ${mf}`,
            fixable: true,
          });
        }
      }
    }
  }
}

function checkNodeModules(nodeModulesPath: string, findings: Finding[]) {
  // Check @tanstack scope for router_init.js
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

    // Check for router_init.js directly
    const routerInit = path.join(pkgPath, "router_init.js");
    if (fs.existsSync(routerInit)) {
      const rel = path.relative(
        path.dirname(path.dirname(nodeModulesPath)),
        routerInit
      );
      findings.push({
        severity: "critical",
        category: "compromised-package",
        path: `node_modules/@tanstack/${pkg}/router_init.js`,
        detail: `Compromised @tanstack package contains malicious payload`,
        fixable: true,
      });
    }

    // Hash-check any .js files in package root
    try {
      const pkgFiles = fs.readdirSync(pkgPath, { withFileTypes: true });
      for (const f of pkgFiles) {
        if (f.isFile() && f.name.endsWith(".js")) {
          const full = path.join(pkgPath, f.name);
          try {
            const hash = sha256(full);
            if (MALICIOUS_FILE_HASHES.has(hash)) {
              findings.push({
                severity: "critical",
                category: "compromised-package-hash",
                path: `node_modules/@tanstack/${pkg}/${f.name}`,
                detail: `SHA256 matches malicious payload: ${hash.slice(0, 16)}...`,
                fixable: true,
              });
            }
          } catch {
            // skip
          }
        }
      }
    } catch {
      // skip
    }

    // Check package.json of this installed package
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

function checkGitHistory(targetDir: string, findings: Finding[]) {
  // Check for commits from the spoofed author
  try {
    const authorLog = execSync(
      `git -C "${targetDir}" log --all --format="%H %ae %s" --author="${MALICIOUS_GIT_AUTHOR}" 2>/dev/null`,
      { encoding: "utf8", timeout: 10000 }
    ).trim();

    if (authorLog) {
      const lines = authorLog.split("\n").filter(Boolean);
      for (const line of lines) {
        const [hash, ...rest] = line.split(" ");
        findings.push({
          severity: "critical",
          category: "malicious-commit",
          path: `.git`,
          detail: `Unauthorized commit from worm author (${MALICIOUS_GIT_AUTHOR}): ${hash.slice(0, 12)} — ${rest.slice(1).join(" ")}`,
          fixable: false,
        });
      }
    }

    // Check for the known malicious commit hash
    try {
      const knownBad = execSync(
        `git -C "${targetDir}" log --all --format="%H" 2>/dev/null | grep "${MALICIOUS_COMMIT_HASH.slice(0, 12)}"`,
        { encoding: "utf8", timeout: 5000 }
      ).trim();
      if (knownBad) {
        findings.push({
          severity: "critical",
          category: "known-malicious-commit",
          path: ".git",
          detail: `Known malicious commit hash present: ${MALICIOUS_COMMIT_HASH}`,
          fixable: false,
        });
      }
    } catch {
      // commit not found, good
    }
  } catch {
    // not a git repo or git not available
  }
}
