# @emstack/tanstack-supply-chain-checker

Detect and remediate the **mini-shai-hulud** TanStack supply-chain attack.

> Reference: [socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)

## Quick start

```bash
npx @emstack/tanstack-supply-chain-checker
```

No arguments → **interactive mode**. Guides you through path input, project selection, and options step by step.

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
# Scan single directory
npx @emstack/tanstack-supply-chain-checker ./my-project

# Scan and auto-fix
npx @emstack/tanstack-supply-chain-checker ./my-project --fix

# Deep scan including node_modules
npx @emstack/tanstack-supply-chain-checker . --include-node-modules

# JSON output — exit 1 if findings, exit 0 if clean
npx @emstack/tanstack-supply-chain-checker . --json
```

### All flags

| Flag | Description |
|---|---|
| `-i`, `--interactive` | Interactive mode (default when no args) |
| `--fix` | Auto-remove malicious files, clean `package.json` |
| `--include-node-modules` | Also scan inside `node_modules` (slow) |
| `--json` | Machine-readable output, exit code 1 on findings |
| `--help` | Show help |

## What it detects

| Category | IOC | Auto-fixable |
|---|---|---|
| Malicious payload files | `router_init.js`, `tanstack_runner.js` anywhere in tree | Yes |
| Known SHA256 hashes | 2 known payload hashes | Yes |
| Persistence — Claude Code | `.claude/router_runtime.js`, `.claude/setup.mjs` | Yes |
| Persistence — VS Code | `.vscode/setup.mjs` | Yes |
| Injected dependency | `@tanstack/setup` in any dep section | Yes |
| Malicious lifecycle hook | `prepare`/`postinstall` scripts referencing worm files | Yes |
| Compromised `@tanstack` package | `router_init.js` inside installed package | Yes |
| Malicious Claude hooks | `.claude/settings.json` hooks referencing worm files | Manual |
| VS Code auto-run tasks | `.vscode/tasks.json` with `runOn: folderOpen` | Manual |
| Unauthorized git commits | Commits from `claude@users.noreply.github.com` | Manual |

## What `--fix` does

- Deletes confirmed malicious files
- Strips `@tanstack/setup` from all `package.json` dependency sections
- Removes malicious lifecycle scripts from `package.json`
- Prints mandatory secrets-rotation checklist (GITHUB_TOKEN, NPM_TOKEN, AWS keys, Vault tokens, etc.)
- Prints git commands to audit unauthorized commits

## What requires manual action

- `.claude/settings.json` hooks — requires human judgment before editing
- `.vscode/tasks.json` auto-run tasks — inspect before deleting
- Git history — revert specific commits after review
- Secrets rotation — cannot be automated
- OIDC federation revocation — GitHub repo settings

## Build

```bash
bun install
bun run build   # outputs dist/cli.js
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — especially the section on adding new IOCs.

## Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). Do not open public issues for security bugs.
