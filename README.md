# @emstack/tanstack-supply-chain-checker

Detect and remediate the **mini-shai-hulud** TanStack supply-chain attack (disclosed May 11, 2026).

> Reference: [socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)

## Quick start

```bash
npx @emstack/tanstack-supply-chain-checker
```

No arguments → **interactive mode**. Guides through path input, project selection, and options step by step.

```
┌  tanstack-supply-chain-checker  mini-shai-hulud attack detector
│
◆  Root path to scan
│  ./my-monorepo
│
◆  Select projects to scan
│  ■ my-app        packages/app
│  ■ my-lib        packages/lib
│  □ legacy        packages/legacy
│
◆  Auto-fix detected issues?
│  No / Yes
│
◆  Include node_modules in scan?
│  No / Yes
│
◇  Scanning my-app  2 critical, 1 high
│  [CRITICAL] package.json
│             injected-dependency: Injected malicious package "@tanstack/setup" found in dependencies
│  [HIGH]     package.json
│             compromised-version: Package "@opensearch-project/opensearch@3.5.3" matches known compromised version
│
  ────────────────────────────────────────────────────────
  SECURITY SUMMARY

  Compromised packages (2)
    ● @tanstack/setup            package.json
    ● @opensearch-project/opensearch@3.5.3   package.json

  ────────────────────────────────────────────────────────

◇  Scanning my-lib  ✓ clean
│
  SCAN SUMMARY
  my-app    2 critical, 1 high    packages/app
  my-lib    ✓ Clean               packages/lib
```

## Usage

### Interactive (default)

```bash
npx @emstack/tanstack-supply-chain-checker          # auto-launches interactive
npx @emstack/tanstack-supply-chain-checker -i       # explicit flag
```

Discovers all `package.json` projects under the given root, lets you select which to scan, and walks through options with prompts.

### Non-interactive (CI / scripting)

```bash
npx @emstack/tanstack-supply-chain-checker ./my-project
npx @emstack/tanstack-supply-chain-checker ./my-project --fix
npx @emstack/tanstack-supply-chain-checker . --include-node-modules
npx @emstack/tanstack-supply-chain-checker . --json
```

### Flags

| Flag | Description |
|---|---|
| `-i`, `--interactive` | Interactive mode (default when no args) |
| `--fix` | Auto-remove malicious files, clean `package.json` |
| `--include-node-modules` | Also scan inside `node_modules` (slow) |
| `--json` | Machine-readable output, exit 1 on findings |
| `--help` | Show help |

## Report output

After scanning, a **SECURITY SUMMARY** block groups findings by threat type so you can triage at a glance:

```
────────────────────────────────────────────────────────
  SECURITY SUMMARY

  Compromised packages (3)
    ● @tanstack/setup                   package.json
    ● @opensearch-project/opensearch@3.5.3   package.json
    ● @tanstack/router (router_init.js)     node_modules/...

  Malicious files (1)
    ● router_init.js                    router_init.js

  Backdoor hooks / tasks (1)
    ● scripts.prepare                   package.json

  Network IOCs in source (1)
    ● filev2.getsession.org             src/setup.ts

  Unauthorized git commits (1)
    ● a3f1bc9d2e44                      .git

────────────────────────────────────────────────────────
```

Groups shown only when findings exist in that category. Bold label = package name, script key, or IOC string. Dim path = location in repo. Same summary printed per-project in interactive mode and aggregated across all projects at the end.

## What it detects

| Category | Detail | Auto-fixable |
|---|---|---|
| Malicious payload files | `router_init.js`, `router_runtime.js`, `tanstack_runner.js` — case-insensitive, anywhere in tree | Yes |
| Known SHA256 hashes | 2 known payload hashes, checked against `.js`/`.mjs`/`.cjs` files | Yes |
| Persistence — Claude Code | `.claude/router_runtime.js`, `.claude/setup.mjs` | Yes |
| Persistence — VS Code | `.vscode/setup.mjs` | Yes |
| Injected dependency | `@tanstack/setup` in any dep section | Yes |
| Malicious lifecycle hook | `prepare`/`postinstall` referencing worm files (string and array form) | Yes |
| Compromised `@tanstack` package | `router_init.js` inside installed package | Yes |
| Compromised version — other packages | `@opensearch-project/opensearch@3.5.3–3.8.0`, `@squawk/mcp@0.9.5`, `@squawk/weather@0.5.10`, `@squawk/flightplan@0.5.6` | Manual |
| Installed compromised package | `package.json` inside `node_modules` matches known bad name + version | Manual |
| Network IOC in source | `.js`/`.ts` files referencing `filev2.getsession.org`, `git-tanstack.com` | Manual |
| Malicious Claude hooks | `.claude/settings.json` hooks referencing worm files | Manual |
| VS Code auto-run tasks | `.vscode/tasks.json` with `runOn: folderOpen` | Manual |
| Unauthorized git commits | Commits from `claude@users.noreply.github.com` | Manual |

## What `--fix` does

- Deletes all confirmed malicious files
- Strips `@tanstack/setup` from all `package.json` dependency sections
- Removes malicious lifecycle scripts (handles both string and array form)
- Writes `package.json` atomically (temp file → rename — no corruption risk)
- Prints secrets-rotation checklist covering npm, GitHub, AWS (incl. OIDC), GCP, Azure, Docker, PyPI, Ruby, Rust, Vault, GPG
- Prints git commands to audit unauthorized commits

## What requires manual action

- `.claude/settings.json` hooks — requires human judgment before editing
- `.vscode/tasks.json` auto-run tasks — inspect before deleting
- Git history — revert specific commits after review
- Secrets rotation — cannot be automated
- OIDC federation revocation — GitHub repo settings
- Compromised third-party package versions — pin to a clean version and reinstall
- Network IOC references in source — inspect file, determine if injected

## Affected packages

**@tanstack** — 84 compromised artifacts. Worm payload injected into `router_init.js` / `router_runtime.js` inside installed packages.

**Other npm packages** (loaded at runtime from `data/compromised-packages.csv` — sourced from Socket.dev disclosure):

| Namespace | Packages | Versions |
|---|---|---|
| `@opensearch-project` | `opensearch` | 3.5.3, 3.6.2, 3.7.0, 3.8.0 |
| `@squawk` | `airport-data`, `airports`, `airspace`, `airspace-data`, `airway-data`, `airways`, `fix-data`, `fixes`, `flight-math`, `flightplan`, `geo`, `icao-registry`, `icao-registry-data`, `mcp`, `navaid-data`, `navaids`, `notams`, `procedure-data`, `procedures`, `types`, `units`, `weather` | multiple (0.3.x – 0.9.x) |
| `@mistralai` | `mistralai`, `mistralai-azure`, `mistralai-gcp` | 1.7.1–1.7.3, 2.2.2–2.2.4 |
| `@uipath` | 45 packages (apollo-react, agent-sdk, robot, cli, …) | single versions per package |
| `@tallyui` | `components`, `connector-*`, `core`, `database`, `pos`, `storage-sqlite`, `theme` | 0.2.1–1.0.3 |
| `@beproduct` | `nestjs-auth` | 0.1.2–0.1.19 |
| `@draftlab` / `@draftauth` | `auth`, `auth-router`, `db`, `client`, `core` | 0.13.x–0.24.x |
| `@cap-js` | `db-service`, `postgres`, `sqlite` | 2.2.2, 2.10.1 |
| `@mesadev` | `rest`, `saguaro`, `sdk` | 0.28.3, 0.4.22 |
| `@ml-toolkit-ts` | `preprocessing`, `xgboost` | 1.0.2–1.0.4 |
| `@supersurkhet` | `cli`, `sdk` | 0.0.2–0.0.7 |
| `@taskflow-corp` | `cli` | 0.1.24–0.1.29 |
| `@tolka` | `cli` | 1.0.2–1.0.6 |
| `@dirigible-ai` | `sdk` | 0.6.2, 0.6.3 |
| _(unscoped)_ | `cross-stitch`, `git-branch-selector`, `git-git-git`, `ts-dna`, `wot-api`, `nextmove-mcp`, `cmux-agent-mcp`, `safe-action`, `ml-toolkit-ts`, `agentwork-cli`, `intercom-client`, `mbt` | various |

PyPI packages `mistralai@2.4.6` and `guardrails-ai@0.10.1` were also compromised but are outside the scope of this npm scanner.

## Updating the IOC package list

Compromised package versions are loaded at runtime from `data/compromised-packages.csv`. To add new packages:

1. Append rows to `data/compromised-packages.csv` using the same column format:
   ```
   Ecosystem,Namespace,Name,Version,Published,Detected
   npm,@example,package-name,1.2.3,,
   ```
2. Run `bun run build` — no code changes needed.

The scanner filters `Ecosystem = npm` and skips `@tanstack` (handled separately via file-based detection).

## Build & test

```bash
bun install
bun run build       # outputs dist/cli.js
bun run validate    # integration tests (runs automatically on publish)
bash test/smoke.sh  # end-to-end smoke test with harmless fixtures
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — especially the section on adding new IOCs.
