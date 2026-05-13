import path from "node:path";
import fs from "node:fs";
import { scan } from "./scanner.ts";
import { fix } from "./fixer.ts";
import { runInteractive } from "./interactive.ts";
import { printSecuritySummary } from "./report.ts";
import type { Finding, Severity } from "./types.ts";

const R = "\x1b[31m";
const Y = "\x1b[33m";
const G = "\x1b[32m";
const B = "\x1b[34m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: R,
  high: Y,
  medium: Y,
  info: B,
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH    ",
  medium: "MEDIUM  ",
  info: "INFO    ",
};

function printBanner() {
  console.log();
  console.log(
    `${BOLD}tanstack-supply-chain-checker${RESET} ${DIM}v1.0.0${RESET}`
  );
  console.log(
    `${DIM}Detects mini-shai-hulud TanStack supply-chain attack IOCs${RESET}`
  );
  console.log();
}

function printFinding(f: Finding, index: number) {
  const color = SEVERITY_COLOR[f.severity];
  const label = SEVERITY_LABEL[f.severity];
  console.log(
    `  ${color}${BOLD}[${label}]${RESET} ${BOLD}${f.path}${RESET}`
  );
  console.log(`           ${DIM}${f.category}${RESET}: ${f.detail}`);
  if (f.fixable) {
    console.log(`           ${G}→ auto-fixable with --fix${RESET}`);
  } else {
    console.log(`           ${Y}→ requires manual action${RESET}`);
  }
  console.log();
}

function printHelp() {
  console.log(`${BOLD}Usage:${RESET}`);
  console.log(
    `  npx tanstack-supply-chain-checker [directory] [options]`
  );
  console.log();
  console.log(`${BOLD}Arguments:${RESET}`);
  console.log(`  directory              Directory to scan (default: .)`);
  console.log();
  console.log(`${BOLD}Options:${RESET}`);
  console.log(`  -i, --interactive      Interactive mode (default when no args)`);
  console.log(`  --fix                  Auto-remove malicious files and fix package.json`);
  console.log(`  --include-node-modules Also scan inside node_modules (slow)`);
  console.log(`  --json                 Output findings as JSON`);
  console.log(`  --help, -h             Show this help`);
  console.log();
  console.log(`${BOLD}Examples:${RESET}`);
  console.log(`  npx @emstack/tanstack-supply-chain-checker            # interactive`);
  console.log(`  npx @emstack/tanstack-supply-chain-checker -i`);
  console.log(`  npx @emstack/tanstack-supply-chain-checker ./my-project --fix`);
  console.log(`  npx @emstack/tanstack-supply-chain-checker . --json`);
  console.log();
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    printBanner();
    printHelp();
    process.exit(0);
  }

  const doFix = args.includes("--fix");
  const jsonOutput = args.includes("--json");
  const includeNodeModules = args.includes("--include-node-modules");
  const isInteractive = args.includes("-i") || args.includes("--interactive");

  const dirArg = args.find(
    (a) => !a.startsWith("--") && !a.startsWith("-")
  );

  if (isInteractive || (!dirArg && !doFix && !jsonOutput && !includeNodeModules)) {
    await runInteractive();
    return;
  }

  const targetDir = path.resolve(dirArg || ".");

  if (!fs.existsSync(targetDir)) {
    console.error(`${R}Error: directory not found: ${targetDir}${RESET}`);
    process.exit(1);
  }

  if (!jsonOutput) {
    printBanner();
    console.log(`${DIM}Scanning: ${targetDir}${RESET}`);
    if (includeNodeModules) {
      console.log(`${DIM}Including node_modules (this may be slow)...${RESET}`);
    }
    console.log();
  }

  const result = scan(targetDir, includeNodeModules);
  const { findings, scannedFiles, scannedDirs } = result;

  if (jsonOutput) {
    const output: any = { target: targetDir, findings, scannedFiles, scannedDirs };

    if (doFix && findings.length > 0) {
      const fixResult = fix(targetDir, findings);
      output.fix = fixResult;
    }

    console.log(JSON.stringify(output, null, 2));
    process.exit(findings.length > 0 ? 1 : 0);
  }

  const bySeverity: Finding[][] = [
    findings.filter((f) => f.severity === "critical"),
    findings.filter((f) => f.severity === "high"),
    findings.filter((f) => f.severity === "medium"),
    findings.filter((f) => f.severity === "info"),
  ].filter((g) => g.length > 0);

  if (findings.length === 0) {
    console.log(
      `${G}${BOLD}✓ No indicators of compromise found.${RESET}`
    );
    console.log(
      `${DIM}Scanned ${scannedFiles} files across ${scannedDirs} directories.${RESET}`
    );
    console.log();
    process.exit(0);
  }

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;

  console.log(
    `${R}${BOLD}⚠ COMPROMISED — ${findings.length} indicator(s) found${RESET}`
  );
  console.log(
    `${DIM}Scanned ${scannedFiles} files across ${scannedDirs} directories${RESET}`
  );
  console.log();

  for (const group of bySeverity) {
    for (let i = 0; i < group.length; i++) {
      printFinding(group[i], i);
    }
  }

  printSecuritySummary(findings);

  const fixableCount = findings.filter((f) => f.fixable).length;

  if (!doFix && fixableCount > 0) {
    console.log(
      `${Y}${fixableCount} finding(s) can be auto-fixed. Re-run with ${BOLD}--fix${RESET}${Y} to apply.${RESET}`
    );
    console.log();
  }

  if (doFix) {
    console.log(`${BOLD}Applying fixes...${RESET}`);
    console.log();
    const fixResult = fix(targetDir, findings);

    if (fixResult.fixed.length > 0) {
      console.log(`${G}${BOLD}Fixed:${RESET}`);
      for (const f of fixResult.fixed) {
        console.log(`  ${G}✓ ${f}${RESET}`);
      }
      console.log();
    }

    if (fixResult.skipped.length > 0) {
      console.log(`${Y}${BOLD}Skipped (manual action required):${RESET}`);
      for (const s of fixResult.skipped) {
        console.log(`  ${Y}• ${s}${RESET}`);
      }
      console.log();
    }

    if (fixResult.manualActions.length > 0) {
      console.log(`${R}${BOLD}Required manual actions:${RESET}`);
      for (const action of fixResult.manualActions) {
        if (action === "") {
          console.log();
        } else if (action.startsWith("  ")) {
          console.log(`${DIM}${action}${RESET}`);
        } else {
          console.log(`${Y}${BOLD}${action}${RESET}`);
        }
      }
      console.log();
    }
  }

  if (!doFix && criticalCount > 0) {
    console.log(
      `${R}${BOLD}IMPORTANT:${RESET} If malicious files were executed (e.g., during npm install),`
    );
    console.log(
      `credentials may have been exfiltrated. Rotate all secrets immediately.`
    );
    console.log();
  }

  process.exit(1);
}

main().catch((err) => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
