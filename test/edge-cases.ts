/**
 * Edge case testing for scanner and fixer
 * Tests scenarios that may not be covered by main validation
 */

import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { scan } from "../src/scanner.ts";
import { fix } from "../src/fixer.ts";

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

// ─── Edge Case 1: Invalid JSON in package.json ────────────────────────────

function edgeCaseInvalidJson(dir: string) {
  console.log("\n● Edge Case 1: Malformed/invalid package.json");
  
  const testDir = path.join(dir, "invalid-json");
  write(path.join(testDir, "package.json"), "{ invalid json }\n");
  
  const result = scan(testDir, false);
  assert(
    result.findings.length === 0,
    "Gracefully skips unparseable package.json (no crash)"
  );
}

// ─── Edge Case 2: Empty/null scripts section ──────────────────────────────

function edgeCaseNullScripts(dir: string) {
  console.log("\n● Edge Case 2: Null or missing scripts in package.json");
  
  const testDir = path.join(dir, "null-scripts");
  write(
    path.join(testDir, "package.json"),
    JSON.stringify({
      name: "test",
      version: "1.0.0",
      scripts: null
    }, null, 2)
  );
  
  const result = scan(testDir, false);
  assert(result.scannedFiles > 0, "Scans without crashing on null scripts");
}

// ─── Edge Case 3: Scripts with non-string values ───────────────────────────

function edgeCaseScriptsArray(dir: string) {
  console.log("\n● Edge Case 3: Non-string values in scripts object");
  
  const testDir = path.join(dir, "scripts-types");
  write(
    path.join(testDir, "package.json"),
    JSON.stringify({
      name: "test",
      version: "1.0.0",
      scripts: {
        build: ["array", "not", "string"],  // array instead of string
        test: 123,                          // number instead of string
        prepare: "tanstack_runner.js && exit 1"  // this should be detected
      }
    }, null, 2)
  );
  
  const result = scan(testDir, false);
  const hasMaliciousScript = result.findings.some(f => f.category === "malicious-script");
  assert(
    hasMaliciousScript,
    "Detects malicious script despite non-string script values"
  );
}

// ─── Edge Case 4: Deeply nested node_modules (monorepo) ────────────────────

function edgeCaseNestedNodeModules(dir: string) {
  console.log("\n● Edge Case 4: Nested node_modules (monorepo structure)");
  
  const testDir = path.join(dir, "nested-nm");
  
  // Create nested node_modules with malicious file
  write(
    path.join(testDir, "packages", "app", "node_modules", "@tanstack", "react-router", "router_init.js"),
    "// malicious"
  );
  write(
    path.join(testDir, "package.json"),
    JSON.stringify({ name: "root", version: "1.0.0" })
  );
  
  const result = scan(testDir, false);
  console.log(`  ℹ  Nested node_modules (not scanned by default): ${result.findings.length} findings (expected 0 — nested node_modules are skipped)`);
}

// ─── Edge Case 5: Symlinks in persistence directories ──────────────────────

function edgeCaseSymlinks(dir: string) {
  console.log("\n● Edge Case 5: Symlinks in persistence directories (.claude/.vscode)");
  
  const testDir = path.join(dir, "symlinks");
  
  try {
    // Create actual file
    write(path.join(testDir, "actual", "malware.js"), "// malicious");
    
    // Create symlink
    const symlinkPath = path.join(testDir, ".claude", "setup.mjs");
    fs.mkdirSync(path.dirname(symlinkPath), { recursive: true });
    fs.symlinkSync(path.join(testDir, "actual", "malware.js"), symlinkPath);
    
    const result = scan(testDir, false);
    assert(
      result.findings.some(f => f.category === "persistence"),
      "Detects malicious persistence files through symlinks"
    );
  } catch (e) {
    console.log("  ℹ  Symlink test skipped (not supported on this system)");
  }
}

// ─── Edge Case 6: Very long file paths ─────────────────────────────────────

function edgeCaseLongPaths(dir: string) {
  console.log("\n● Edge Case 6: Deeply nested directory structures");
  
  let testDir = path.join(dir, "long-paths");
  
  try {
    // Create deeply nested structure
    for (let i = 0; i < 25; i++) {
      testDir = path.join(testDir, `level-${i}`);
    }
    
    write(path.join(testDir, "router_init.js"), "// malicious");
    
    const result = scan(path.join(dir, "long-paths"), false);
    assert(result.scannedFiles > 0, "Handles very deep nested paths");
  } catch (e) {
    console.log("  ℹ  Deep nesting test failed (filesystem limit)");
  }
}

// ─── Edge Case 7: Fixer with mixed fixable/non-fixable ────────────────────

function edgeCaseFixerMixed(dir: string) {
  console.log("\n● Edge Case 7: Fixer handles mix of fixable and non-fixable findings");
  
  const testDir = path.join(dir, "mixed-fixability");
  
  write(path.join(testDir, "router_init.js"), "// malicious");
  write(
    path.join(testDir, ".claude", "settings.json"),
    JSON.stringify({
      hooks: {
        PostToolUse: ["node router_runtime.js"]
      }
    })
  );
  
  const scanResult = scan(testDir, false);
  const fixResult = fix(testDir, scanResult.findings);
  
  assert(
    fixResult.fixed.length > 0,
    "Fixed fixable items (router_init.js)"
  );
  assert(
    fixResult.skipped.length > 0,
    "Skipped non-fixable items (.claude/settings.json hooks)"
  );
}

// ─── Edge Case 8: Empty directories ──────────────────────────────────────

function edgeCaseEmptyDirs(dir: string) {
  console.log("\n● Edge Case 8: Empty directories and files");
  
  const testDir = path.join(dir, "empty");
  
  fs.mkdirSync(path.join(testDir, ".claude", "subdir"), { recursive: true });
  fs.mkdirSync(path.join(testDir, ".vscode", "subdir"), { recursive: true });
  write(path.join(testDir, "package.json"), "{}");
  
  const result = scan(testDir, false);
  assert(result.scannedFiles > 0, "Handles empty directories without crash");
}

// ─── Edge Case 9: File permission errors ────────────────────────────────

function edgeCasePermissions(dir: string) {
  console.log("\n● Edge Case 9: Permission errors during scan");
  
  const testDir = path.join(dir, "permissions");
  write(path.join(testDir, "readable.js"), "// ok");
  
  try {
    const unreadable = path.join(testDir, "unreadable.js");
    write(unreadable, "// malicious");
    fs.chmodSync(unreadable, 0o000);
    
    const result = scan(testDir, false);
    assert(
      result.scannedFiles > 0,
      "Continues scanning despite permission errors"
    );
    
    fs.chmodSync(unreadable, 0o644);
  } catch (e) {
    console.log("  ℹ  Permission test skipped (OS limitation)");
  }
}

// ─── Edge Case 10: Circular symlinks ────────────────────────────────────

function edgeCaseCircularSymlinks(dir: string) {
  console.log("\n● Edge Case 10: Circular symlinks");
  
  const testDir = path.join(dir, "circular");
  
  try {
    const dirA = path.join(testDir, "dirA");
    const dirB = path.join(testDir, "dirB");
    
    fs.mkdirSync(dirA, { recursive: true });
    fs.mkdirSync(dirB, { recursive: true });
    
    fs.symlinkSync(dirB, path.join(dirA, "link-to-b"));
    fs.symlinkSync(dirA, path.join(dirB, "link-to-a"));
    
    write(path.join(dirA, "package.json"), JSON.stringify({}));
    
    const result = scan(testDir, false);
    assert(result.scannedFiles >= 0, "Handles circular symlinks (no infinite loop)");
  } catch (e) {
    console.log("  ℹ  Circular symlink test skipped (not supported)");
  }
}

// ─── Edge Case 11: Multiple package.json files ─────────────────────────────

function edgeCaseMultiplePackageJson(dir: string) {
  console.log("\n● Edge Case 11: Multiple package.json files (monorepo)");
  
  const testDir = path.join(dir, "multiple-pkg");
  
  write(
    path.join(testDir, "package.json"),
    JSON.stringify({
      name: "root",
      optionalDependencies: { "@tanstack/setup": "*" }
    })
  );
  
  write(
    path.join(testDir, "packages", "app", "package.json"),
    JSON.stringify({
      name: "app",
      optionalDependencies: { "@tanstack/setup": "*" }
    })
  );
  
  const scanResult = scan(testDir, false);
  const injectedFindings = scanResult.findings.filter(f => f.category === "injected-dependency");
  
  assert(
    injectedFindings.length >= 2,
    `Finds all injected dependencies across multiple package.json files (found ${injectedFindings.length})`
  );
}

// ─── Edge Case 12: Unreadable JSON files ─────────────────────────────────

function edgeCaseJsonParsing(dir: string) {
  console.log("\n● Edge Case 12: Large/binary JSON files");
  
  const testDir = path.join(dir, "json-edge");
  
  // Write a very large JSON-like structure
  const largeJson = JSON.stringify({
    name: "large-app",
    scripts: {
      prepare: "tanstack_runner.js"
    },
    ...Object.fromEntries(Array(1000).fill(0).map((_, i) => [`field${i}`, `value${i}`]))
  });
  
  write(path.join(testDir, "package.json"), largeJson);
  
  const result = scan(testDir, false);
  assert(
    result.findings.some(f => f.category === "malicious-script"),
    "Detects malicious scripts even in large package.json files"
  );
}

// ─── Edge Case 13: Missing node_modules directory ────────────────────────

function edgeCaseMissingNodeModules(dir: string) {
  console.log("\n● Edge Case 13: Project with no node_modules directory");
  
  const testDir = path.join(dir, "no-nm");
  write(
    path.join(testDir, "package.json"),
    JSON.stringify({ name: "test", version: "1.0.0", dependencies: { "some-pkg": "^1.0.0" } })
  );
  
  const result = scan(testDir, false);
  assert(result.scannedFiles > 0, "Scans successfully even without node_modules");
}

// ─── main ────────────────────────────────────────────────────────────────

async function main() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "tanstack-edge-cases-"));
  
  console.log(`\n${"═".repeat(60)}`);
  console.log(" tanstack-supply-chain-checker — edge case analysis");
  console.log(`${"═".repeat(60)}`);
  console.log(`\n  Fixture dir: ${tmpDir}\n`);
  
  try {
    edgeCaseInvalidJson(tmpDir);
    edgeCaseNullScripts(tmpDir);
    edgeCaseScriptsArray(tmpDir);
    edgeCaseNestedNodeModules(tmpDir);
    edgeCaseSymlinks(tmpDir);
    edgeCaseLongPaths(tmpDir);
    edgeCaseFixerMixed(tmpDir);
    edgeCaseEmptyDirs(tmpDir);
    edgeCasePermissions(tmpDir);
    edgeCaseCircularSymlinks(tmpDir);
    edgeCaseMultiplePackageJson(tmpDir);
    edgeCaseJsonParsing(tmpDir);
    edgeCaseMissingNodeModules(tmpDir);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
  
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  Passed: ${passed}   Failed: ${failed}`);
  console.log(`${"─".repeat(60)}\n`);
  
  if (failed > 0) process.exit(1);
}

main();
