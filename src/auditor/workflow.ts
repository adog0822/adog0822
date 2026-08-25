/**
 * Auditor Workflow Engine
 *
 * Complete auditor lifecycle: time-bound sessions, evidence packages,
 * fieldwork sampling, control grading, exception-based testing,
 * cross-framework mapping, and one-click workpaper export.
 *
 * Speaks SOC 2 terminology — Trust Services Criteria, Common Criteria,
 * not engineering jargon. The auditor sees what matters.
 */

import type {
  AuditorSession,
  AuditScope,
  AuditorGrade,
  AuditorMessage,
  ControlId,
  ControlScore,
  EvidenceItem,
  EvidenceStatus,
  Finding,
  UserId,
  WorkspaceId,
} from "../types/index.js";

// ─── Cross-Framework Mapping ───────────────────────────────────────────

export interface FrameworkMapping {
  soc2Control: string;
  iso27001: string[];
  nistCsf: string[];
  nist80053: string[];
  description: string;
}

/**
 * Maps SOC 2 controls to ISO 27001, NIST CSF, and NIST 800-53.
 * One artifact, multiple standards — the auditor validates once.
 */
export const FRAMEWORK_CROSS_MAP: FrameworkMapping[] = [
  {
    soc2Control: "CC1.1",
    iso27001: ["A.5.1", "A.5.2"],
    nistCsf: ["ID.GV-1"],
    nist80053: ["PM-1", "PL-1"],
    description: "Board oversight and governance of information security",
  },
  {
    soc2Control: "CC1.2",
    iso27001: ["A.6.1.1"],
    nistCsf: ["ID.GV-2"],
    nist80053: ["PM-2"],
    description: "Independence and oversight of internal controls",
  },
  {
    soc2Control: "CC1.3",
    iso27001: ["A.6.1.1", "A.6.1.2"],
    nistCsf: ["ID.GV-3"],
    nist80053: ["PM-1", "PM-10"],
    description: "Organizational structure and reporting lines",
  },
  {
    soc2Control: "CC1.4",
    iso27001: ["A.7.1.1", "A.7.2.1"],
    nistCsf: ["PR.IP-11"],
    nist80053: ["PS-1", "PS-2"],
    description: "Competence and accountability of personnel",
  },
  {
    soc2Control: "CC1.5",
    iso27001: ["A.7.2.3"],
    nistCsf: ["PR.IP-11"],
    nist80053: ["PS-8"],
    description: "Accountability enforcement mechanisms",
  },
  {
    soc2Control: "CC2.1",
    iso27001: ["A.8.1.1", "A.8.2.1"],
    nistCsf: ["ID.AM-1", "ID.AM-2"],
    nist80053: ["PM-11", "SI-12"],
    description: "Information quality and lifecycle management",
  },
  {
    soc2Control: "CC2.2",
    iso27001: ["A.7.2.2", "A.6.1.3"],
    nistCsf: ["PR.AT-1"],
    nist80053: ["AT-1", "AT-2"],
    description: "Internal communication of security responsibilities",
  },
  {
    soc2Control: "CC2.3",
    iso27001: ["A.6.1.3", "A.15.1.1"],
    nistCsf: ["ID.GV-4"],
    nist80053: ["PM-15"],
    description: "External communication of policies and obligations",
  },
  {
    soc2Control: "CC3.1",
    iso27001: ["A.18.1.1"],
    nistCsf: ["ID.BE-1", "ID.BE-3"],
    nist80053: ["PM-9", "RA-1"],
    description: "Risk assessment objectives definition",
  },
  {
    soc2Control: "CC3.2",
    iso27001: ["A.12.6.1"],
    nistCsf: ["ID.RA-1", "ID.RA-3"],
    nist80053: ["RA-3"],
    description: "Risk identification and analysis",
  },
  {
    soc2Control: "CC3.3",
    iso27001: ["A.12.6.1"],
    nistCsf: ["ID.RA-5"],
    nist80053: ["RA-3"],
    description: "Fraud risk consideration",
  },
  {
    soc2Control: "CC3.4",
    iso27001: ["A.12.1.2", "A.14.2.3"],
    nistCsf: ["ID.RA-6"],
    nist80053: ["CM-3", "CM-4"],
    description: "Change impact on controls and risk",
  },
  {
    soc2Control: "CC4.1",
    iso27001: ["A.18.2.1", "A.12.7.1"],
    nistCsf: ["DE.DP-1", "DE.DP-4"],
    nist80053: ["CA-7"],
    description: "Ongoing and separate monitoring evaluations",
  },
  {
    soc2Control: "CC4.2",
    iso27001: ["A.18.2.2"],
    nistCsf: ["RS.IM-1"],
    nist80053: ["CA-5"],
    description: "Deficiency evaluation and remediation",
  },
  {
    soc2Control: "CC5.1",
    iso27001: ["A.6.1.2"],
    nistCsf: ["PR.IP-1"],
    nist80053: ["PL-2"],
    description: "Control activity selection and development",
  },
  {
    soc2Control: "CC5.2",
    iso27001: ["A.12.1.1", "A.14.1.1"],
    nistCsf: ["PR.PT-3"],
    nist80053: ["AC-1", "SC-1"],
    description: "Technology general controls and configuration",
  },
  {
    soc2Control: "CC5.3",
    iso27001: ["A.5.1.2", "A.12.1.1"],
    nistCsf: ["PR.IP-1"],
    nist80053: ["PL-1"],
    description: "Policy-based control deployment",
  },
  {
    soc2Control: "CC6.1",
    iso27001: ["A.9.2.1", "A.9.2.2"],
    nistCsf: ["PR.AC-1", "PR.AC-4"],
    nist80053: ["AC-2", "IA-1"],
    description: "Logical access security — identity management",
  },
  {
    soc2Control: "CC6.2",
    iso27001: ["A.9.2.4", "A.9.4.2"],
    nistCsf: ["PR.AC-7"],
    nist80053: ["IA-2", "IA-5"],
    description: "Authentication and authorization mechanisms",
  },
  {
    soc2Control: "CC6.3",
    iso27001: ["A.9.2.2", "A.9.2.5", "A.9.2.6"],
    nistCsf: ["PR.AC-1"],
    nist80053: ["AC-2", "AC-5", "AC-6"],
    description: "Access provisioning, modification, and removal",
  },
  {
    soc2Control: "CC6.6",
    iso27001: ["A.13.1.1", "A.13.1.3"],
    nistCsf: ["PR.AC-5", "PR.DS-5"],
    nist80053: ["SC-7"],
    description: "System boundary and network security controls",
  },
  {
    soc2Control: "CC6.7",
    iso27001: ["A.10.1.1", "A.10.1.2"],
    nistCsf: ["PR.DS-1", "PR.DS-2"],
    nist80053: ["SC-28", "SC-8"],
    description: "Data encryption at rest and in transit",
  },
  {
    soc2Control: "CC6.8",
    iso27001: ["A.12.2.1"],
    nistCsf: ["DE.CM-4"],
    nist80053: ["SI-3"],
    description: "Malicious software prevention and detection",
  },
  {
    soc2Control: "CC7.1",
    iso27001: ["A.12.4.1", "A.16.1.2"],
    nistCsf: ["DE.AE-1", "DE.CM-1"],
    nist80053: ["SI-4", "AU-6"],
    description: "Detection of anomalies and security events",
  },
  {
    soc2Control: "CC7.2",
    iso27001: ["A.12.4.1", "A.12.4.3"],
    nistCsf: ["DE.AE-2", "DE.AE-3"],
    nist80053: ["AU-6", "IR-4"],
    description: "Security event monitoring and analysis",
  },
  {
    soc2Control: "CC7.3",
    iso27001: ["A.16.1.4", "A.16.1.5"],
    nistCsf: ["RS.AN-1", "RS.MI-1"],
    nist80053: ["IR-4", "IR-5"],
    description: "Incident response and evaluation",
  },
  {
    soc2Control: "CC7.4",
    iso27001: ["A.16.1.5", "A.16.1.6"],
    nistCsf: ["RS.MI-2", "RS.IM-2"],
    nist80053: ["IR-6", "IR-8"],
    description: "Incident containment and remediation",
  },
  {
    soc2Control: "CC7.5",
    iso27001: ["A.17.1.1", "A.17.1.2"],
    nistCsf: ["RC.RP-1"],
    nist80053: ["CP-2", "CP-10"],
    description: "Recovery and restoration operations",
  },
  {
    soc2Control: "CC8.1",
    iso27001: ["A.12.1.2", "A.14.2.2"],
    nistCsf: ["PR.IP-3"],
    nist80053: ["CM-3", "SA-10"],
    description: "Infrastructure and software change management",
  },
  {
    soc2Control: "CC9.1",
    iso27001: ["A.12.6.1"],
    nistCsf: ["ID.RA-6"],
    nist80053: ["PM-9"],
    description: "Risk mitigation activities and acceptance",
  },
  {
    soc2Control: "CC9.2",
    iso27001: ["A.15.1.1", "A.15.2.1"],
    nistCsf: ["ID.SC-1", "ID.SC-4"],
    nist80053: ["SA-9", "SA-12"],
    description: "Vendor and third-party risk management",
  },
];

// ─── Auditor Session Management ────────────────────────────────────────

export function createAuditorSession(
  auditorId: UserId,
  workspaceId: WorkspaceId,
  scope: AuditScope,
  durationDays: number = 90
): AuditorSession {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000);

  return {
    auditorId,
    workspaceId,
    auditPeriodStart: scope.auditPeriodStart ?? now.toISOString(),
    auditPeriodEnd: scope.auditPeriodEnd ?? expiresAt.toISOString(),
    scope,
    status: "active",
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
  };
}

export function isSessionValid(session: AuditorSession): boolean {
  if (session.status !== "active") return false;
  return new Date(session.expiresAt) > new Date();
}

// ─── Automated Evidence Packages ───────────────────────────────────────

export interface EvidencePackage {
  controlId: ControlId;
  controlTitle: string;
  category: string;
  status: EvidenceStatus;
  score: number;
  evidenceItems: EvidenceItem[];
  findings: Finding[];
  generatedAt: string;
  auditPeriod: { start: string; end: string };
  crossMappings: FrameworkMapping | undefined;
  auditorSummary: string;
}

/**
 * Generate an automated evidence package for an auditor.
 * Groups evidence by control, computes scores, maps frameworks.
 * Zero uploads — everything is system-generated from live telemetry.
 */
export function generateEvidencePackage(
  controlId: ControlId,
  controlTitle: string,
  category: string,
  evidenceItems: EvidenceItem[],
  controlScore: ControlScore,
  auditPeriod: { start: string; end: string }
): EvidencePackage {
  const controlEvidence = evidenceItems.filter((e) => e.controlId === controlId);

  const crossMapping = FRAMEWORK_CROSS_MAP.find(
    (m) => m.soc2Control === (controlId as string)
  );

  const auditorSummary = buildAuditorSummary(
    controlTitle,
    controlScore,
    controlEvidence.length,
    crossMapping
  );

  return {
    controlId,
    controlTitle,
    category,
    status: controlScore.status,
    score: controlScore.score,
    evidenceItems: controlEvidence,
    findings: controlScore.findings,
    generatedAt: new Date().toISOString(),
    auditPeriod,
    crossMappings: crossMapping,
    auditorSummary,
  };
}

function buildAuditorSummary(
  controlTitle: string,
  score: ControlScore,
  evidenceCount: number,
  crossMapping: FrameworkMapping | undefined
): string {
  const statusText =
    score.status === "pass"
      ? "Operating Effectively"
      : score.status === "warn"
        ? "Operating with Exceptions"
        : score.status === "fail"
          ? "Not Operating Effectively"
          : "Not Applicable";

  let summary = `Control: ${controlTitle}\n`;
  summary += `Assessment: ${statusText} (Score: ${score.score}/100)\n`;
  summary += `Evidence Items Evaluated: ${evidenceCount}\n`;
  summary += `Open Findings: ${score.findings.length}\n`;

  if (crossMapping) {
    summary += `\nCross-Framework Coverage:\n`;
    if (crossMapping.iso27001.length > 0) {
      summary += `  ISO 27001: ${crossMapping.iso27001.join(", ")}\n`;
    }
    if (crossMapping.nistCsf.length > 0) {
      summary += `  NIST CSF: ${crossMapping.nistCsf.join(", ")}\n`;
    }
    if (crossMapping.nist80053.length > 0) {
      summary += `  NIST 800-53: ${crossMapping.nist80053.join(", ")}\n`;
    }
  }

  return summary;
}

// ─── Fieldwork Sampling ────────────────────────────────────────────────

export interface SamplingResult {
  controlId: ControlId;
  totalPopulation: number;
  sampleSize: number;
  anomaliesFound: number;
  anomalyRate: number;
  samplingMethod: "full_population" | "statistical" | "judgmental";
  anomalies: SamplingAnomaly[];
  conclusion: string;
  evaluatedAt: string;
}

export interface SamplingAnomaly {
  resourceId: string;
  resourceName: string;
  expectedState: string;
  actualState: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
}

/**
 * Algorithmic fieldwork sampling: analyze 100% of population,
 * flag anomalies, pre-validate passing controls.
 * The auditor verifies the logic, not the data.
 */
export function performFieldworkSampling(
  controlId: ControlId,
  evidenceItems: EvidenceItem[]
): SamplingResult {
  const controlEvidence = evidenceItems.filter((e) => e.controlId === controlId);
  const totalPopulation = controlEvidence.length;

  const anomalies: SamplingAnomaly[] = [];

  for (const item of controlEvidence) {
    if (item.status === "fail" || item.status === "warn") {
      for (const finding of item.findings) {
        anomalies.push({
          resourceId: item.id as string,
          resourceName: item.resourceName,
          expectedState: finding.remediation,
          actualState: finding.description,
          severity: finding.severity,
          description: finding.title,
        });
      }
    }
  }

  const anomalyRate = totalPopulation > 0 ? anomalies.length / totalPopulation : 0;

  let conclusion: string;
  if (anomalies.length === 0) {
    conclusion = "Full population analysis: No exceptions identified. Control is operating effectively across all evaluated items.";
  } else if (anomalyRate < 0.05) {
    conclusion = `Full population analysis: ${anomalies.length} exception(s) identified in ${totalPopulation} items (${(anomalyRate * 100).toFixed(1)}% exception rate). Control is operating effectively with noted exceptions requiring remediation.`;
  } else if (anomalyRate < 0.15) {
    conclusion = `Full population analysis: ${anomalies.length} exception(s) identified in ${totalPopulation} items (${(anomalyRate * 100).toFixed(1)}% exception rate). Elevated exception rate warrants compensating controls review.`;
  } else {
    conclusion = `Full population analysis: ${anomalies.length} exception(s) identified in ${totalPopulation} items (${(anomalyRate * 100).toFixed(1)}% exception rate). Control is not operating effectively. Significant remediation required.`;
  }

  return {
    controlId,
    totalPopulation,
    sampleSize: totalPopulation,
    anomaliesFound: anomalies.length,
    anomalyRate,
    samplingMethod: "full_population",
    anomalies,
    conclusion,
    evaluatedAt: new Date().toISOString(),
  };
}

// ─── Control Grading ───────────────────────────────────────────────────

export function gradeControl(
  controlId: ControlId,
  grade: AuditorGrade["grade"],
  reasoning: string,
  auditorId: UserId
): AuditorGrade {
  return {
    controlId,
    grade,
    reasoning,
    auditorId,
    gradedAt: new Date().toISOString(),
  };
}

export function isPreValidated(controlScore: ControlScore): boolean {
  return controlScore.score >= 95 && controlScore.findings.length === 0;
}

// ─── Workpaper Export ──────────────────────────────────────────────────

export interface WorkpaperExport {
  format: "aicpa" | "oscal" | "json";
  framework: string;
  auditPeriod: { start: string; end: string };
  controlCount: number;
  packages: EvidencePackage[];
  samplingResults: SamplingResult[];
  grades: AuditorGrade[];
  generatedAt: string;
  generatedBy: UserId;
}

/**
 * One-click workpaper export: all evidence, grades, sampling,
 * and cross-mappings in AICPA or OSCAL format.
 */
export function exportWorkpapers(
  packages: EvidencePackage[],
  samplingResults: SamplingResult[],
  grades: AuditorGrade[],
  auditPeriod: { start: string; end: string },
  format: "aicpa" | "oscal" | "json",
  generatedBy: UserId
): WorkpaperExport {
  return {
    format,
    framework: "SOC 2 Type II",
    auditPeriod,
    controlCount: packages.length,
    packages,
    samplingResults,
    grades,
    generatedAt: new Date().toISOString(),
    generatedBy,
  };
}

// ─── Auditor Messaging ────────────────────────────────────────────────

let messageCounter = 0;

export function createAuditorMessage(
  threadId: string,
  fromId: UserId,
  fromRole: "auditor" | "user",
  content: string,
  attachments?: string[]
): AuditorMessage {
  messageCounter++;
  return {
    id: `msg_${Date.now()}_${messageCounter}`,
    threadId,
    fromId,
    fromRole,
    content,
    attachments,
    createdAt: new Date().toISOString(),
  };
}

// ─── Auditor Dashboard ─────────────────────────────────────────────────

export interface AuditorDashboard {
  totalControls: number;
  gradedControls: number;
  preValidatedControls: number;
  controlsByStatus: Record<EvidenceStatus, number>;
  openRequests: number;
  pendingFindings: number;
  overallScore: number;
  readinessLevel: "not_started" | "in_progress" | "nearly_ready" | "audit_ready";
}

export function buildAuditorDashboard(
  controlScores: ControlScore[],
  grades: AuditorGrade[],
  openRequestCount: number
): AuditorDashboard {
  const statusCounts: Record<EvidenceStatus, number> = {
    pass: 0,
    warn: 0,
    fail: 0,
    info: 0,
    not_applicable: 0,
  };

  let totalScore = 0;
  let pendingFindings = 0;
  let preValidated = 0;

  for (const cs of controlScores) {
    statusCounts[cs.status]++;
    totalScore += cs.score;
    pendingFindings += cs.findings.length;
    if (isPreValidated(cs)) preValidated++;
  }

  const overallScore = controlScores.length > 0
    ? Math.round(totalScore / controlScores.length)
    : 0;

  let readinessLevel: AuditorDashboard["readinessLevel"];
  if (overallScore >= 90 && pendingFindings === 0) {
    readinessLevel = "audit_ready";
  } else if (overallScore >= 70) {
    readinessLevel = "nearly_ready";
  } else if (overallScore > 0) {
    readinessLevel = "in_progress";
  } else {
    readinessLevel = "not_started";
  }

  return {
    totalControls: controlScores.length,
    gradedControls: grades.length,
    preValidatedControls: preValidated,
    controlsByStatus: statusCounts,
    openRequests: openRequestCount,
    pendingFindings,
    overallScore,
    readinessLevel,
  };
}
