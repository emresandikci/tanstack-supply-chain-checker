# tanstack-supply-chain-checker

Detect and remediate the **mini-shai-hulud** TanStack supply-chain attack.

> Reference: [socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)

## Usage

```bash
# Scan current directory
npx @emstack/tanstack-supply-chain-checker

# Scan specific directory
npx @emstack/tanstack-supply-chain-checker ./my-project

# Scan and auto-fix
npx @emstack/tanstack-supply-chain-checker ./my-project --fix

# Include node_modules in scan (slower, more thorough)
npx @emstack/tanstack-supply-chain-checker . --include-node-modules

# JSON output (for CI/scripting)
npx @emstack/tanstack-supply-chain-checker . --json
```

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
- Prints a mandatory secrets-rotation checklist (GITHUB_TOKEN, NPM_TOKEN, AWS keys, Vault tokens, etc.)
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
