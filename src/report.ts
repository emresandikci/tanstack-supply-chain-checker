import type { Finding } from "./types.ts";

const R = "\x1b[31m";
const Y = "\x1b[33m";
const G = "\x1b[32m";
const B = "\x1b[2m";
const BOLD = "\x1b[1m";
const RESET = "\x1b[0m";
const LINE = `${B}${"─".repeat(56)}${RESET}`;

interface Group {
  title: string;
  color: string;
  categories: string[];
}

const GROUPS: Group[] = [
  {
    title: "Compromised packages",
    color: R,
    categories: [
      "injected-dependency",
      "compromised-version",
      "compromised-installed-package",
      "compromised-package",
      "compromised-package-hash",
    ],
  },
  {
    title: "Malicious files",
    color: R,
    categories: ["malicious-file", "malicious-file-hash", "persistence"],
  },
  {
    title: "Backdoor hooks / tasks",
    color: R,
    categories: [
      "malicious-script",
      "persistence-hooks",
      "persistence-tasks",
      "auto-run-task",
    ],
  },
  {
    title: "Network IOCs in source",
    color: Y,
    categories: ["network-ioc"],
  },
  {
    title: "Unauthorized git commits",
    color: R,
    categories: ["malicious-commit", "known-malicious-commit"],
  },
];

export function printSecuritySummary(findings: Finding[]): void {
  const relevant = GROUPS.filter((g) =>
    g.categories.some((c) => findings.some((f) => f.category === c))
  );
  if (relevant.length === 0) return;

  console.log(LINE);
  console.log(`  ${BOLD}SECURITY SUMMARY${RESET}`);
  console.log();

  for (const group of relevant) {
    const hits = findings.filter((f) => group.categories.includes(f.category));
    console.log(
      `  ${group.color}${BOLD}${group.title} (${hits.length})${RESET}`
    );
    for (const f of hits) {
      const subject = f.label || f.path;
      const loc = f.label ? `${B}${f.path}${RESET}` : "";
      console.log(`    ${group.color}●${RESET} ${BOLD}${subject}${RESET}${loc ? "   " + loc : ""}`);
    }
    console.log();
  }

  console.log(LINE);
  console.log();
}
