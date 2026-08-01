export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type OWASPCategory =
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable and Outdated Components'
  | 'A07:2021-Identification and Authentication Failures'
  | 'A08:2021-Software and Data Integrity Failures'
  | 'A09:2021-Security Logging and Monitoring Failures'
  | 'A10:2021-Server-Side Request Forgery (SSRF)';

export interface VulnerabilityFinding {
  id: string;
  title: string;
  severity: Severity;
  owaspCategory: OWASPCategory;
  cwe: string;
  cvssScore: number;
  confidence: number; // e.g. 98
  filePath: string;
  lineNumber: number;
  snippet: string;
  explanation: string;
  rootCause: string;
  whyItMatters: string;
  evidenceChain?: string[];
  remediation: {
    gitDiff: string;
    suggestedCode: string;
    fixSummary: string;
    residualRisk: string;
    validationPassed: boolean;
  };
  falsePositiveConfidence: number;
  suppressedReason?: string;
  aiVerified: boolean;
}

export interface SecurityReport {
  timestamp: string;
  targetRepositoryName: string;
  totalFilesScanned: number;
  totalLinesScanned: number;
  scanDurationMs: number;
  findings: VulnerabilityFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  owaspBreakdown: Record<string, number>;
}

export interface PresetFile {
  name: string;
  path: string;
  language: 'python' | 'typescript' | 'javascript' | 'sql' | 'dockerfile';
  content: string;
}

export interface PresetRepo {
  id: string;
  name: string;
  description: string;
  files: PresetFile[];
}
