import * as p from "@clack/prompts";
import fs from "node:fs";
import path from "node:path";
import { scan } from "./scanner.ts";
import { fix, type FixResult } from "./fixer.ts";
import { printSecuritySummary } from "./report.ts";
import type { Finding, ScanResult } from "./types.ts";

interface ProjectInfo {
  name: string;
  dir: string;
  relPath: string;
}

function findProjects(rootDir: string): ProjectInfo[] {
  const projects: ProjectInfo[] = [];
  const seen = new Set<string>();

  function walk(dir: string, depth: number) {
    if (depth > 6) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;

      const subdir = path.join(dir, entry.name);
      walk(subdir, depth + 1);
    }

    const pkgJson = path.join(dir, "package.json");
    if (fs.existsSync(pkgJson) && !seen.has(dir)) {
      seen.add(dir);
      let name = path.basename(dir);
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgJson, "utf8"));
        if (pkg.name) name = pkg.name;
      } catch {}
      const relPath = path.relative(rootDir, dir) || ".";
      projects.push({ name, dir, relPath });
    }
  }

  const rootPkg = path.join(rootDir, "package.json");
  if (fs.existsSync(rootPkg)) {
    let name = path.basename(rootDir);
    try {
      const pkg = JSON.parse(fs.readFileSync(rootPkg, "utf8"));
      if (pkg.name) name = pkg.name;
    } catch {}
    projects.push({ name, dir: rootDir, relPath: "." });
    seen.add(rootDir);
  }

  walk(rootDir, 0);

  return projects.sort((a, b) => {
    if (a.relPath === ".") return -1;
    if (b.relPath === ".") return 1;
    return a.relPath.localeCompare(b.relPath);
  });
}

function severityColor(sev: string): string {
  switch (sev) {
    case "critical": return "\x1b[31m";
    case "high": return "\x1b[33m";
    default: return "\x1b[34m";
  }
}

const R = "\x1b[31m";
const G = "\x1b[32m";
const Y = "\x1b[33m";
const B = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";

function formatFindings(findings: Finding[]): string {
  if (findings.length === 0) return `${G}✓ Clean${RESET}`;
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const parts: string[] = [];
  if (critical > 0) parts.push(`${R}${critical} critical${RESET}`);
  if (high > 0) parts.push(`${Y}${high} high${RESET}`);
  const rest = findings.length - critical - high;
  if (rest > 0) parts.push(`${rest} other`);
  return parts.join(", ");
}

export async function runInteractive() {
  p.intro(`${BOLD}tanstack-supply-chain-checker${RESET}  ${B}mini-shai-hulud attack detector${RESET}`);

  const inputPath = await p.text({
    message: "Root path to scan",
    placeholder: ".",
    defaultValue: ".",
    validate(val) {
      const resolved = path.resolve(val || ".");
      if (!fs.existsSync(resolved)) return `Path not found: ${resolved}`;
      if (!fs.statSync(resolved).isDirectory()) return "Must be a directory";
    },
  });

  if (p.isCancel(inputPath)) {
    p.cancel("Cancelled.");
    process.exit(0);
  }

  const rootDir = path.resolve(inputPath as string || ".");

  const spinner = p.spinner();
  spinner.start("Discovering projects...");
  const projects = findProjects(rootDir);
  spinner.stop(`Found ${projects.length} project(s)`);

  if (projects.length === 0) {
    p.log.warn("No package.json files found under this path.");
    p.outro("Done.");
    process.exit(0);
  }

  const selected = await p.multiselect<ProjectInfo>({
    message: "Select projects to scan",
    options: projects.map((proj) => ({
      value: proj,
      label: proj.name,
      hint: proj.relPath,
    })),
    initialValues: projects,
    required: true,
  });

  if (p.isCancel(selected)) {
    p.cancel("Cancelled.");
    process.exit(0);
  }

  const doFix = await p.confirm({
    message: "Auto-fix detected issues?",
    initialValue: false,
  });
  if (p.isCancel(doFix)) { p.cancel("Cancelled."); process.exit(0); }

  const includeNodeModules = await p.confirm({
    message: "Include node_modules in scan? (slower, more thorough)",
    initialValue: false,
  });
  if (p.isCancel(includeNodeModules)) { p.cancel("Cancelled."); process.exit(0); }

  console.log();

  const results: Array<{
    project: ProjectInfo;
    scanResult: ScanResult;
    fixResult?: FixResult;
  }> = [];
  const failedProjects: Array<{ project: ProjectInfo; reason: string }> = [];

  for (const project of selected as unknown as ProjectInfo[]) {
    const s = p.spinner();
    s.start(`Scanning ${BOLD}${project.name}${RESET} ${B}(${project.relPath})${RESET}`);

    let scanResult: ScanResult;
    try {
      scanResult = scan(project.dir, includeNodeModules as boolean);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      failedProjects.push({ project, reason });
      s.stop(`${project.name}  ${R}scan error${RESET}`);
      p.log.error(`  ${project.name}: ${reason}`);
      continue;
    }

    if (scanResult.findings.length === 0) {
      s.stop(`${project.name}  ${G}✓ clean${RESET}`);
      results.push({ project, scanResult });
      continue;
    }

    s.stop(`${project.name}  ${formatFindings(scanResult.findings)}`);

    for (const finding of scanResult.findings) {
      const color = severityColor(finding.severity);
      p.log.warn(
        `  ${color}[${finding.severity.toUpperCase()}]${RESET} ${finding.path}\n` +
        `    ${B}${finding.category}:${RESET} ${finding.detail}`
      );
    }

    let fixResult: FixResult | undefined;
    if (doFix) {
      const fs2 = p.spinner();
      fs2.start("Applying fixes...");
      fixResult = fix(project.dir, scanResult.findings);
      const fixedCount = fixResult.fixed.length;
      fs2.stop(`Fixed ${fixedCount} item(s)`);

      if (fixResult.fixed.length > 0) {
        for (const f of fixResult.fixed) {
          p.log.success(`  Removed: ${f}`);
        }
      }
      if (fixResult.skipped.length > 0) {
        for (const s of fixResult.skipped) {
          p.log.warn(`  Skipped (manual): ${s}`);
        }
      }
    }

    printSecuritySummary(scanResult.findings);

    results.push({ project, scanResult, fixResult });
    console.log();
  }

  const totalFindings = results.reduce((n, r) => n + r.scanResult.findings.length, 0);
  const compromised = results.filter((r) => r.scanResult.findings.length > 0);
  const scanErrors = failedProjects.length;

  console.log();
  p.log.step(`${BOLD}SCAN SUMMARY${RESET}`);
  console.log();

  const allNames = [
    ...results.map((r) => r.project.name),
    ...failedProjects.map((f) => f.project.name),
  ];
  const nameWidth = Math.max(...allNames.map((n) => n.length), 10);

  for (const r of results) {
    const name = r.project.name.padEnd(nameWidth);
    const status = formatFindings(r.scanResult.findings);
    const path2 = `${B}${r.project.relPath}${RESET}`;
    console.log(`  ${name}  ${status}  ${path2}`);
  }

  for (const f of failedProjects) {
    const name = f.project.name.padEnd(nameWidth);
    const path2 = `${B}${f.project.relPath}${RESET}`;
    console.log(`  ${name}  ${R}scan failed${RESET}  ${path2}  ${B}${f.reason}${RESET}`);
  }

  console.log();

  if (results.length > 1 && totalFindings > 0) {
    const allFindings = results.flatMap((r) => r.scanResult.findings);
    printSecuritySummary(allFindings);
  }

  if (totalFindings === 0 && scanErrors === 0) {
    p.outro(`${G}${BOLD}All projects clean. No indicators of compromise found.${RESET}`);
  } else if (totalFindings === 0 && scanErrors > 0) {
    p.outro(`${Y}${BOLD}${scanErrors} project(s) failed to scan. Review errors above — results are incomplete.${RESET}`);
  } else {
    if (doFix) {
      const allManual = results
        .flatMap((r) => r.fixResult?.manualActions ?? [])
        .filter((line, i, arr) => arr.indexOf(line) === i); // dedupe

      if (allManual.length > 0) {
        p.log.error(`${BOLD}Required manual actions:${RESET}`);
        for (const action of allManual) {
          if (action === "") console.log();
          else if (action.startsWith("  ")) console.log(`${B}${action}${RESET}`);
          else p.log.warn(action);
        }
        console.log();
      }

      p.outro(`${Y}${BOLD}${compromised.length} project(s) were compromised. Review manual actions above.${RESET}`);
    } else {
      p.outro(
        `${R}${BOLD}${compromised.length} project(s) compromised.${RESET} Re-run and select "Auto-fix" to remediate.`
      );
    }
  }
}
