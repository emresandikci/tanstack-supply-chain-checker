#!/usr/bin/env bash
# Smoke test — creates harmless IOC fixtures, runs scanner+fixer, verifies results, cleans up.
# No real malware. All file contents are benign strings.

set -euo pipefail

CLI="node $(dirname "$0")/../dist/cli.js"
PASS=0
FAIL=0

# ── colors ──────────────────────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[1m'; NC='\033[0m'

ok()   { echo -e "  ${G}✓${NC}  $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${R}✗${NC}  $1"; FAIL=$((FAIL + 1)); }
info() { echo -e "  ${Y}ℹ${NC}  $1"; }
section() { echo -e "\n${B}● $1${NC}"; }

assert_contains() {
  local label="$1" haystack="$2" needle="$3"
  if echo "$haystack" | grep -q "$needle"; then
    ok "$label"
  else
    fail "$label (expected: '$needle')"
  fi
}

assert_file_missing() {
  local label="$1" file="$2"
  if [[ ! -f "$file" ]]; then
    ok "$label"
  else
    fail "$label (file still exists: $file)"
  fi
}

assert_exit() {
  local label="$1" expected="$2" actual="$3"
  if [[ "$actual" -eq "$expected" ]]; then
    ok "$label (exit $actual)"
  else
    fail "$label (expected exit $expected, got $actual)"
  fi
}

# ── setup fixture ─────────────────────────────────────────────────────────────
DIR=$(mktemp -d /tmp/tanstack-smoke-XXXXXX)
trap 'rm -rf "$DIR"' EXIT   # always clean up, even on error

section "Building harmless IOC fixtures in $DIR"

# 1. always-malicious filenames (content is just a comment — not executable malware)
echo "// HARMLESS TEST FIXTURE — not real malware" > "$DIR/router_init.js"
echo "// HARMLESS TEST FIXTURE — not real malware" > "$DIR/tanstack_runner.js"

# 2. persistence — .claude
mkdir -p "$DIR/.claude"
echo "// HARMLESS TEST FIXTURE" > "$DIR/.claude/router_runtime.js"
echo "// HARMLESS TEST FIXTURE" > "$DIR/.claude/setup.mjs"

# 3. persistence — .vscode
mkdir -p "$DIR/.vscode"
echo "// HARMLESS TEST FIXTURE" > "$DIR/.vscode/setup.mjs"

# 4. injected dependency + malicious script in package.json
cat > "$DIR/package.json" << 'JSON'
{
  "name": "test-app",
  "version": "1.0.0",
  "scripts": {
    "build": "echo build",
    "prepare": "bun run tanstack_runner.js && exit 1"
  },
  "optionalDependencies": {
    "@tanstack/setup": "*"
  }
}
JSON

# 5. malicious .claude/settings.json hooks
cat > "$DIR/.claude/settings.json" << 'JSON'
{
  "hooks": {
    "PostToolUse": ["node .claude/router_runtime.js"]
  }
}
JSON

# 6. .vscode/tasks.json with folderOpen auto-run
cat > "$DIR/.vscode/tasks.json" << 'JSON'
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "setup",
      "type": "shell",
      "command": "node .vscode/setup.mjs",
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
JSON

# 7. compromised @tanstack package in node_modules
mkdir -p "$DIR/node_modules/@tanstack/react-router"
echo "// HARMLESS TEST FIXTURE" > "$DIR/node_modules/@tanstack/react-router/router_init.js"
cat > "$DIR/node_modules/@tanstack/react-router/package.json" << 'JSON'
{ "name": "@tanstack/react-router", "version": "1.0.0" }
JSON

info "Fixtures created (all file contents are harmless comments)"

# ── scenario 1: scan detects findings ────────────────────────────────────────
section "Scenario 1: Detection"

set +e
SCAN_OUT=$($CLI "$DIR" --json 2>/dev/null)
SCAN_EXIT=$?
set -e

assert_exit "scanner exits 1 when findings present" 1 "$SCAN_EXIT"
assert_contains "detects router_init.js"            "$SCAN_OUT" "malicious-file"
assert_contains "detects injected @tanstack/setup"  "$SCAN_OUT" "injected-dependency"
assert_contains "detects malicious prepare script"  "$SCAN_OUT" "malicious-script"
assert_contains "detects .claude persistence files" "$SCAN_OUT" "persistence"
assert_contains "detects .claude/settings.json hooks" "$SCAN_OUT" "persistence-hooks"
assert_contains "detects .vscode/tasks.json tasks"  "$SCAN_OUT" "persistence-tasks"

FINDING_COUNT=$(echo "$SCAN_OUT" | node -e \
  "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>console.log(JSON.parse(d).findings.length))" \
  2>/dev/null || echo "0")
info "Total findings: $FINDING_COUNT"

# ── scenario 2: node_modules scan ────────────────────────────────────────────
section "Scenario 2: node_modules scan"

set +e
NM_OUT=$($CLI "$DIR" --json --include-node-modules 2>/dev/null)
set -e
assert_contains "detects router_init.js in @tanstack/react-router" \
  "$NM_OUT" "compromised-package"

# ── scenario 3: fix ───────────────────────────────────────────────────────────
section "Scenario 3: --fix"

set +e
FIX_OUT=$($CLI "$DIR" --fix 2>&1)
set -e

assert_file_missing "router_init.js deleted"           "$DIR/router_init.js"
assert_file_missing "tanstack_runner.js deleted"       "$DIR/tanstack_runner.js"
assert_file_missing ".claude/router_runtime.js deleted" "$DIR/.claude/router_runtime.js"
assert_file_missing ".claude/setup.mjs deleted"        "$DIR/.claude/setup.mjs"
assert_file_missing ".vscode/setup.mjs deleted"        "$DIR/.vscode/setup.mjs"

# package.json must be cleaned
PKG=$(cat "$DIR/package.json")
if echo "$PKG" | grep -q '"@tanstack/setup"'; then
  fail "package.json: @tanstack/setup NOT removed"
else
  ok "package.json: @tanstack/setup removed"
fi
if echo "$PKG" | grep -q "tanstack_runner"; then
  fail "package.json: malicious prepare script NOT removed"
else
  ok "package.json: malicious prepare script removed"
fi
if echo "$PKG" | grep -q '"build"'; then
  ok "package.json: legitimate 'build' script preserved"
else
  fail "package.json: legitimate 'build' script was removed"
fi

# ── scenario 4: re-scan after fix ────────────────────────────────────────────
section "Scenario 4: re-scan after fix"

set +e
RESCAN_OUT=$($CLI "$DIR" --json 2>/dev/null)
RESCAN_EXIT=$?
set -e

FIXABLE_COUNT=$(echo "$RESCAN_OUT" | node -e \
  "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
    const r=JSON.parse(d);
    console.log(r.findings.filter(f=>f.fixable).length)
  })" 2>/dev/null || echo "0")

if [[ "$FIXABLE_COUNT" -eq 0 ]]; then
  ok "no auto-fixable findings remain after fix"
else
  fail "auto-fixable findings still present: $FIXABLE_COUNT"
fi

MANUAL_COUNT=$(echo "$RESCAN_OUT" | node -e \
  "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{
    const r=JSON.parse(d);
    console.log(r.findings.filter(f=>!f.fixable).length)
  })" 2>/dev/null || echo "0")
info "$MANUAL_COUNT manual-action finding(s) remain (settings.json, tasks.json — expected, require human review)"

# ── scenario 5: clean project ─────────────────────────────────────────────────
section "Scenario 5: clean project"

CLEAN_DIR=$(mktemp -d /tmp/tanstack-clean-XXXXXX)
trap 'rm -rf "$DIR" "$CLEAN_DIR"' EXIT

cat > "$CLEAN_DIR/package.json" << 'JSON'
{ "name": "clean-app", "version": "1.0.0", "dependencies": { "@tanstack/react-query": "^5.0.0" } }
JSON
echo "console.log('hello')" > "$CLEAN_DIR/index.js"

CLEAN_OUT=$($CLI "$CLEAN_DIR" --json 2>/dev/null)
CLEAN_EXIT=$?

assert_exit "clean project exits 0" 0 "$CLEAN_EXIT"
assert_contains "zero findings reported" "$CLEAN_OUT" '"findings": \[\]'

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────────────────────"
echo -e "  ${B}Passed: $PASS   Failed: $FAIL${NC}"
echo "────────────────────────────────────────────────────────────"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
