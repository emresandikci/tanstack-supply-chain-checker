export type Severity = "critical" | "high" | "medium" | "info";

export interface Finding {
  severity: Severity;
  category: string;
  path: string;
  detail: string;
  fixable: boolean;
}

export interface ScanResult {
  findings: Finding[];
  scannedFiles: number;
  scannedDirs: number;
}
