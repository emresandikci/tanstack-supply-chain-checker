import fs from "node:fs";
import path from "node:path";

export const MALICIOUS_FILE_HASHES = new Set([
  "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
  "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96",
]);

export const ALWAYS_MALICIOUS_FILENAMES = new Set([
  "router_init.js",
  "router_runtime.js",
  "tanstack_runner.js",
]);

export const PERSISTENCE_FILES: Record<string, string[]> = {
  ".claude": ["router_runtime.js", "setup.mjs"],
  ".vscode": ["setup.mjs"],
};

export const INJECTED_PACKAGES = new Set(["@tanstack/setup"]);

function loadCompromisedPackageVersions(): Record<string, string[]> {
  try {
    const scriptPath = fs.realpathSync(process.argv[1] || process.execPath);
    const csvPath = path.resolve(path.dirname(scriptPath), "..", "data", "compromised-packages.csv");
    const csv = fs.readFileSync(csvPath, "utf8");
    const result: Record<string, string[]> = {};
    for (const line of csv.split("\n").slice(1)) {
      const cols = line.trim().split(",");
      if (cols.length < 4) continue;
      const [ecosystem, namespace, name, version] = cols;
      if (ecosystem !== "npm") continue;
      if (namespace === "@tanstack") continue;
      const pkg = namespace ? `${namespace}/${name}` : name;
      if (!pkg || !version) continue;
      (result[pkg] ??= []).push(version);
    }
    return result;
  } catch {
    return {};
  }
}

export const COMPROMISED_PACKAGE_VERSIONS: Record<string, string[]> =
  loadCompromisedPackageVersions();

export const MALICIOUS_GIT_AUTHOR = "claude@users.noreply.github.com";

export const MALICIOUS_COMMIT_HASH = "79ac49eedf774dd4b0cfa308722bc463cfe5885c";

export const NETWORK_IOCS = ["filev2.getsession.org", "getsession.org", "git-tanstack.com"];

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
  "ACTIONS_ID_TOKEN_REQUEST_URL",
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
  "AWS_ROLE_ARN",
  "AWS_WEB_IDENTITY_TOKEN_FILE",
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
