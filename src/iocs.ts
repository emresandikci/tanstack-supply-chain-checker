// Indicators of Compromise — mini-shai-hulud TanStack supply-chain attack
// Source: https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack

export const MALICIOUS_FILE_HASHES = new Set([
  // router_init.js / router_runtime.js
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
  // tanstack_runner.js variant
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96",
]);

export const MALICIOUS_FILE_HASHES_MD5 = new Set([
  "833fd59ebe66a4449982c6d18db656b4",
  "b82e54923f7e440664d2d75bd31588ca",
]);

// Filenames that are always malicious regardless of location
export const ALWAYS_MALICIOUS_FILENAMES = new Set([
  "router_init.js",
  "tanstack_runner.js",
]);

// Filenames malicious only in specific dirs
export const PERSISTENCE_FILES: Record<string, string[]> = {
  ".claude": ["router_runtime.js", "setup.mjs"],
  ".vscode": ["setup.mjs"],
};

// package.json optionalDependencies injected by the worm
export const INJECTED_PACKAGES = new Set(["@tanstack/setup"]);

// Spoofed git commit author used by worm
export const MALICIOUS_GIT_AUTHOR = "claude@users.noreply.github.com";

// Known malicious commit hash
export const MALICIOUS_COMMIT_HASH = "79ac49eedf774dd4b0cfa308722bc463cfe5885c";

// Network IOCs (for reporting)
export const NETWORK_IOCS = ["filev2.getsession.org", "getsession.org"];

// Strings that indicate .claude/settings.json is compromised
export const MALICIOUS_HOOK_STRINGS = [
  "router_runtime.js",
  "tanstack_runner.js",
  "router_init.js",
  "setup.mjs",
  "filev2.getsession",
];

// Strings that indicate .vscode/tasks.json is compromised
export const MALICIOUS_TASK_STRINGS = [
  "router_runtime.js",
  "tanstack_runner.js",
  "router_init.js",
  "setup.mjs",
];

// Env vars that may have been exfiltrated
export const SENSITIVE_ENV_VARS = [
  "GITHUB_TOKEN",
  "NPM_TOKEN",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "VAULT_TOKEN",
  "VAULT_AUTH_TOKEN",
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
];
