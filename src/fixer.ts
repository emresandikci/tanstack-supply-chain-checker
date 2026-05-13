import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.ts";
import { INJECTED_PACKAGES, SENSITIVE_ENV_VARS, NETWORK_IOCS } from "./iocs.ts";

export interface FixResult {
  fixed: string[];
  skipped: string[];
  manualActions: string[];
}

function isUnderTarget(targetDir: string, fullPath: string): boolean {
  const resolved = path.resolve(fullPath);
  const target = path.resolve(targetDir);
  return resolved === target || resolved.startsWith(target + path.sep);
}

export function fix(targetDir: string, findings: Finding[]): FixResult {
  const fixed: string[] = [];
  const skipped: string[] = [];
  const manualActions: string[] = [];
  const fixedPackageJsons = new Set<string>();

  for (const finding of findings) {
    if (!finding.fixable) {
      skipped.push(finding.path);
      continue;
    }

    const fullPath = path.join(targetDir, finding.path);

    if (!isUnderTarget(targetDir, fullPath)) {
      skipped.push(finding.path);
      continue;
    }

    switch (finding.category) {
      case "malicious-file":
      case "malicious-file-hash":
      case "persistence":
      case "compromised-package":
      case "compromised-package-hash": {
        if (deleteFile(fullPath)) {
          fixed.push(finding.path);
        } else {
          skipped.push(finding.path);
        }
        break;
      }

      case "injected-dependency":
      case "malicious-script": {
        if (fixedPackageJsons.has(fullPath)) {
          if (!fixed.includes(finding.path)) fixed.push(finding.path);
          break;
        }
        if (fixPackageJson(fullPath, finding)) {
          fixedPackageJsons.add(fullPath);
          if (!fixed.includes(finding.path)) fixed.push(finding.path);
        } else {
          skipped.push(finding.path);
        }
        break;
      }

      default:
        skipped.push(finding.path);
    }
  }

  const hasGitFindings = findings.some((f) => f.category.includes("commit"));
  const hasPersistenceHooks = findings.some(
    (f) => f.category === "persistence-hooks"
  );
  const hasVsCodeTasks = findings.some(
    (f) =>
      f.category === "persistence-tasks" || f.category === "auto-run-task"
  );
  const hasCredentialRisk = findings.some(
    (f) =>
      f.category === "malicious-file" ||
      f.category === "malicious-file-hash" ||
      f.category === "compromised-package" ||
      f.category === "compromised-package-hash"
  );

  if (hasCredentialRisk) {
    manualActions.push(
      "ROTATE ALL SECRETS immediately — worm harvests env vars at install time:",
      ...SENSITIVE_ENV_VARS.map((v) => `  • ${v}`),
      "  • All npm publish tokens",
      "  • Kubernetes service account tokens",
      "  • HashiCorp Vault tokens (VAULT_TOKEN, VAULT_AUTH_TOKEN)"
    );

    manualActions.push(
      "",
      "Revoke GitHub Actions OIDC federation grants for affected repos:",
      "  • Settings → Actions → General → OIDC token permissions",
      "  • Or add: permissions: id-token: none to all workflows"
    );
  }

  if (hasGitFindings) {
    manualActions.push(
      "",
      "Audit and revert unauthorized git commits:",
      `  git log --all --author="claude@users.noreply.github.com"`,
      `  git revert <hash>  # or force-push after review`
    );
  }

  if (hasPersistenceHooks) {
    manualActions.push(
      "",
      "Manually review and clean .claude/settings.json hooks section.",
      "Remove any hooks referencing: router_runtime.js, setup.mjs, tanstack_runner.js"
    );
  }

  if (hasVsCodeTasks) {
    manualActions.push(
      "",
      "Manually review .vscode/tasks.json — remove tasks with runOn: folderOpen",
      "referencing suspicious scripts."
    );
  }

  if (hasCredentialRisk) {
    manualActions.push(
      "",
      "Block egress to exfiltration endpoints:",
      ...NETWORK_IOCS.map((ioc) => `  • ${ioc}`)
    );

    manualActions.push(
      "",
      "Re-install affected @tanstack packages from clean versions:",
      "  npm install  (or)  bun install  (or)  pnpm install"
    );
  }

  return { fixed, skipped, manualActions };
}

function deleteFile(fullPath: string): boolean {
  try {
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
      return true;
    }
    return false;
  } catch {
    return false;
  }
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

function fixPackageJson(fullPath: string, _finding: Finding): boolean {
  try {
    const content = fs.readFileSync(fullPath, "utf8");
    const pkg = JSON.parse(content);
    let changed = false;

    for (const section of [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies",
    ] as const) {
      if (pkg[section]) {
        for (const injected of INJECTED_PACKAGES) {
          if (injected in pkg[section]) {
            delete pkg[section][injected];
            changed = true;
          }
        }
        if (Object.keys(pkg[section]).length === 0) {
          delete pkg[section];
        }
      }
    }

    if (pkg.scripts) {
      for (const [name, cmd] of Object.entries(pkg.scripts)) {
        if (isMaliciousScriptValue(cmd)) {
          delete pkg.scripts[name];
          changed = true;
        }
      }
    }

    if (changed) {
      const tmp = fullPath + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify(pkg, null, 2) + "\n", "utf8");
      fs.renameSync(tmp, fullPath);
      return true;
    }
    return false;
  } catch {
    return false;
  }
}
