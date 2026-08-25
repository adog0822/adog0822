/**
 * Auditor Workflow — Time-bound sessions, evidence packages,
 * fieldwork sampling, control grading, cross-framework mapping
 */
export {
  createAuditorSession,
  isSessionValid,
  generateEvidencePackage,
  performFieldworkSampling,
  gradeControl,
  isPreValidated,
  exportWorkpapers,
  createAuditorMessage,
  buildAuditorDashboard,
  FRAMEWORK_CROSS_MAP,
  type EvidencePackage,
  type SamplingResult,
  type SamplingAnomaly,
  type WorkpaperExport,
  type AuditorDashboard,
  type FrameworkMapping,
} from "./workflow.js";
