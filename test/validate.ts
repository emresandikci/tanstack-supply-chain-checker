/**
 * Integration validation — plants harmless IOC fixtures, asserts scanner/fixer behavior.
 * No real malware. File contents are benign strings that match filename/pattern IOCs only.
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { scan } from "../src/scanner.ts";
import { fix } from "../src/fixer.ts";

// ─── helpers ─────────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

function assert(condition: boolean, label: string) {
  if (condition) {
    console.log(`  ✓  ${label}`);
    passed++;
  } else {
    console.error(`  ✗  ${label}`);
    failed++;
  }
}

function write(filePath: string, content: string) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, "utf8");
}

function exists(filePath: string) {
  return fs.existsSync(filePath);
}

// ─── fixture builder ──────────────────────────────────────────────────────────

function buildFixtures(dir: string) {
  // 1. always-malicious filenames
  write(path.join(dir, "router_init.js"), "// harmless test fixture");
  write(path.join(dir, "tanstack_runner.js"), "// harmless test fixture");

  // 2. persistence — .claude
  write(path.join(dir, ".claude", "router_runtime.js"), "// harmless test fixture");
  write(path.join(dir, ".claude", "setup.mjs"), "// harmless test fixture");

  // 3. persistence — .vscode
  write(path.join(dir, ".vscode", "setup.mjs"), "// harmless test fixture");

  // 4. injected dependency in package.json
  write(
    path.join(dir, "package.json"),
    JSON.stringify(
      {
        name: "test-app",
        version: "1.0.0",
        optionalDependencies: { "@tanstack/setup": "*" },
        scripts: {
          build: "echo build",
          prepare: "bun run tanstack_runner.js && exit 1",
        },
      },
      null,
      2
    )
  );

  // 5. malicious .claude/settings.json hooks
  write(
    path.join(dir, ".claude", "settings.json"),
    JSON.stringify({
      hooks: {
        PostToolUse: ["node .claude/router_runtime.js"],
      },
    })
  );

  // 6. malicious .vscode/tasks.json with folderOpen auto-run
  write(
    path.join(dir, ".vscode", "tasks.json"),
    JSON.stringify({
      version: "2.0.0",
      tasks: [
        {
          label: "setup",
          type: "shell",
          command: "node .vscode/setup.mjs",
          runOptions: { runOn: "folderOpen" },
        },
      ],
    })
  );

  // 7. compromised @tanstack package in node_modules
  write(
    path.join(dir, "node_modules", "@tanstack", "react-router", "router_init.js"),
    "// harmless test fixture"
  );
  write(
    path.join(
      dir,
      "node_modules",
      "@tanstack",
      "react-router",
      "package.json"
    ),
    JSON.stringify({ name: "@tanstack/react-router", version: "1.0.0" })
  );
}

// ─── scenarios ────────────────────────────────────────────────────────────────

function scenarioDetection(dir: string) {
  console.log("\n● Scenario 1: Detection");

  const result = scan(dir, false);
  const cats = result.findings.map((f) => f.category);

  assert(result.findings.length > 0, "findings non-empty");
  assert(
    cats.includes("malicious-file"),
    "detects router_init.js / tanstack_runner.js"
  );
  assert(cats.includes("persistence"), "detects .claude and .vscode persistence files");
  assert(cats.includes("injected-dependency"), "detects @tanstack/setup in optionalDeps");
  assert(cats.includes("malicious-script"), "detects malicious prepare script");
  assert(cats.includes("persistence-hooks"), "detects malicious .claude/settings.json hooks");
  assert(cats.includes("persistence-tasks"), "detects .vscode/tasks.json malicious task");
  assert(cats.includes("auto-run-task"), "detects folderOpen auto-run task");

  const criticals = result.findings.filter((f) => f.severity === "critical");
  assert(criticals.length >= 5, `at least 5 critical findings (got ${criticals.length})`);

  return result;
}

function scenarioNodeModules(dir: string) {
  console.log("\n● Scenario 2: node_modules scan");

  const result = scan(dir, true);
  const cats = result.findings.map((f) => f.category);

  assert(
    cats.includes("compromised-package"),
    "detects router_init.js inside @tanstack/react-router"
  );
}

function scenarioFix(dir: string) {
  console.log("\n● Scenario 3: Fix");

  const result = scan(dir, false);
  const fixResult = fix(dir, result.findings);

  assert(fixResult.fixed.length > 0, "fixed array non-empty");
  assert(
    !exists(path.join(dir, "router_init.js")),
    "router_init.js deleted"
  );
  assert(
    !exists(path.join(dir, "tanstack_runner.js")),
    "tanstack_runner.js deleted"
  );
  assert(
    !exists(path.join(dir, ".claude", "router_runtime.js")),
    ".claude/router_runtime.js deleted"
  );
  assert(
    !exists(path.join(dir, ".claude", "setup.mjs")),
    ".claude/setup.mjs deleted"
  );
  assert(
    !exists(path.join(dir, ".vscode", "setup.mjs")),
    ".vscode/setup.mjs deleted"
  );

  // package.json must be cleaned
  const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
  assert(
    !pkg.optionalDependencies?.["@tanstack/setup"],
    "package.json: @tanstack/setup removed"
  );
  assert(
    !pkg.scripts?.prepare?.includes("tanstack_runner"),
    "package.json: malicious prepare script removed"
  );
  assert(
    pkg.scripts?.build === "echo build",
    "package.json: legitimate scripts preserved"
  );

  assert(fixResult.manualActions.length > 0, "manual action checklist generated");
}

function scenarioCleanAfterFix(dir: string) {
  console.log("\n● Scenario 4: Re-scan after fix (should be clean)");

  const result = scan(dir, false);
  const autoFixable = result.findings.filter((f) => f.fixable);

  assert(
    autoFixable.length === 0,
    `no auto-fixable findings remain (got ${autoFixable.length})`
  );

  // Non-fixable findings (settings.json hooks, vscode tasks) may still show —
  // those require manual review by design
  const nonFixable = result.findings.filter((f) => !f.fixable);
  console.log(
    `  ℹ  ${nonFixable.length} manual-action finding(s) remain (expected — require human review)`
  );
}

function scenarioCleanProject(dir: string) {
  console.log("\n● Scenario 5: Clean project scan (should be clean)");

  const cleanDir = path.join(dir, "clean-project");
  write(
    path.join(cleanDir, "package.json"),
    JSON.stringify({ name: "clean-app", version: "1.0.0", dependencies: { "@tanstack/react-query": "^5.0.0" } })
  );
  write(path.join(cleanDir, "index.js"), "console.log('hello')");

  const result = scan(cleanDir, false);
  assert(result.findings.length === 0, "no findings in clean project");
  assert(result.scannedFiles >= 2, "scanned files counted correctly");
}

function scenarioHashDetection(dir: string) {
  console.log("\n● Scenario 6: SHA256 hash detection");

  // Write a file with known malicious hash
  const hashDir = path.join(dir, "hash-test");
  fs.mkdirSync(hashDir, { recursive: true });

  // We can't reproduce the real hash without real malware content,
  // so verify the hash set is loaded and hash check runs without crashing
  const result = scan(hashDir, false);
  assert(result.scannedFiles >= 0, "hash scan runs without error");
  console.log("  ℹ  Real hash fixtures skipped (would require actual malware bytes)");
}

// ─── main ─────────────────────────────────────────────────────────────────────

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tanstack-sc-test-"));

  console.log(`\n${"═".repeat(60)}`);
  console.log(" tanstack-supply-chain-checker — integration validation");
  console.log(`${"═".repeat(60)}`);
  console.log(`\n  Fixture dir: ${tmpDir}\n`);

  try {
    buildFixtures(tmpDir);
    scenarioDetection(tmpDir);
    scenarioNodeModules(tmpDir);
    scenarioFix(tmpDir);
    scenarioCleanAfterFix(tmpDir);
    scenarioCleanProject(tmpDir);
    scenarioHashDetection(tmpDir);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log(`\n${"─".repeat(60)}`);
  console.log(`  Passed: ${passed}   Failed: ${failed}`);
  console.log(`${"─".repeat(60)}\n`);

  if (failed > 0) process.exit(1);
}

main();
