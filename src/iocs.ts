export const MALICIOUS_FILE_HASHES = new Set([
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96",
]);

export const ALWAYS_MALICIOUS_FILENAMES = new Set([
  "router_init.js",
  "tanstack_runner.js",
]);

export const PERSISTENCE_FILES: Record<string, string[]> = {
  ".claude": ["router_runtime.js", "setup.mjs"],
  ".vscode": ["setup.mjs"],
};

export const INJECTED_PACKAGES = new Set(["@tanstack/setup"]);

export const MALICIOUS_GIT_AUTHOR = "claude@users.noreply.github.com";

export const MALICIOUS_COMMIT_HASH = "79ac49eedf774dd4b0cfa308722bc463cfe5885c";

export const NETWORK_IOCS = ["filev2.getsession.org", "getsession.org"];

export const MALICIOUS_HOOK_STRINGS = [
  "router_runtime.js",
  "tanstack_runner.js",
  "router_init.js",
  "setup.mjs",
  "filev2.getsession",
];

export const MALICIOUS_TASK_STRINGS = [
  "router_runtime.js",
  "tanstack_runner.js",
  "router_init.js",
  "setup.mjs",
];

export const SENSITIVE_ENV_VARS = [
  "GITHUB_TOKEN",
  "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  "GH_TOKEN",
  "NPM_TOKEN",
  "NODE_AUTH_TOKEN",
  "PYPI_TOKEN",
  "TWINE_PASSWORD",
  "GEM_HOST_API_KEY",
  "CARGO_REGISTRY_TOKEN",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "GCP_KEY",
  "AZURE_CLIENT_SECRET",
  "AZURE_SP_PASSWORD",
  "ALICLOUD_ACCESS_KEY",
  "VAULT_TOKEN",
  "VAULT_AUTH_TOKEN",
  "DOCKER_PASSWORD",
  "DOCKER_TOKEN",
  "GPG_PASSPHRASE",
  "SIGSTORE_OIDC_TOKEN",
  "DATABASE_URL",
  "REDIS_URL",
  "SECRET_KEY",
  "API_KEY",
];
