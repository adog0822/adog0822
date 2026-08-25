/**
 * Control Templates — 54 pre-approved, customizable control check templates.
 *
 * Each template maps to one or more SOC 2 Common Criteria controls and has
 * configurable parameters so organizations can tune thresholds to their risk
 * appetite. The check function is deterministic: given the same input data
 * and parameters, it always returns the same result.
 */

import type { EvidenceStatus } from "../../types/index.ts";

// ─── Template Types ──────────────────────────────────────────────────

export interface ControlTemplate {
  /** Unique template identifier (e.g., "TPL-001"). */
  id: string;
  /** Human-readable template name. */
  name: string;
  /** What this check evaluates. */
  description: string;
  /** SOC 2 category (CC1–CC9). */
  category: string;
  /** SOC 2 control IDs this template satisfies. */
  controlIds: string[];
  /** Configurable parameters with defaults. */
  parameters: TemplateParameter[];
  /** Whether this template is enabled by default. */
  enabledByDefault: boolean;
  /** Deterministic check function. */
  check: (input: CheckInput, params: Record<string, unknown>) => CheckResult;
}

export interface TemplateParameter {
  key: string;
  label: string;
  type: "number" | "boolean" | "string" | "string[]";
  defaultValue: unknown;
  description: string;
}

export interface CheckInput {
  /** The actual measured value for the check. */
  value: unknown;
  /** Additional context data. */
  context?: Record<string, unknown>;
}

export interface CheckResult {
  status: EvidenceStatus;
  score: number;
  message: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────

function param(
  key: string,
  label: string,
  type: TemplateParameter["type"],
  defaultValue: unknown,
  description: string,
): TemplateParameter {
  return { key, label, type, defaultValue, description };
}

function result(status: EvidenceStatus, score: number, message: string): CheckResult {
  return { status, score, message };
}

function pct(input: CheckInput): number {
  return typeof input.value === "number" ? input.value : 0;
}

function num(input: CheckInput): number {
  return typeof input.value === "number" ? input.value : 0;
}

function bool(input: CheckInput): boolean {
  return Boolean(input.value);
}

function resolveNum(params: Record<string, unknown>, key: string, fallback: number): number {
  const v = params[key];
  return typeof v === "number" ? v : fallback;
}

function resolveBool(params: Record<string, unknown>, key: string, fallback: boolean): boolean {
  const v = params[key];
  return typeof v === "boolean" ? v : fallback;
}

// ─── Template Definitions ────────────────────────────────────────────

export const CONTROL_TEMPLATES: ReadonlyArray<ControlTemplate> = [
  // ── CC6: Logical and Physical Access ──

  // 1
  {
    id: "TPL-001",
    name: "MFA Enabled for All Users",
    description: "Verifies that multi-factor authentication is enabled for all user accounts.",
    category: "CC6",
    controlIds: ["CC6.1", "CC6.2"],
    parameters: [
      param("threshold", "Required MFA Coverage (%)", "number", 100, "Percentage of users that must have MFA enabled."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const threshold = resolveNum(params, "threshold", 100);
      const coverage = pct(input);
      if (coverage >= threshold) return result("pass", 100, `MFA coverage is ${coverage}%, meets threshold of ${threshold}%.`);
      if (coverage >= threshold * 0.8) return result("warn", 60, `MFA coverage is ${coverage}%, below threshold of ${threshold}%.`);
      return result("fail", Math.round(coverage * 0.5), `MFA coverage is only ${coverage}%, well below threshold of ${threshold}%.`);
    },
  },

  // 2
  {
    id: "TPL-002",
    name: "Password Policy Minimum Length",
    description: "Checks that the minimum password length meets the configured standard.",
    category: "CC6",
    controlIds: ["CC6.2"],
    parameters: [
      param("minLength", "Minimum Password Length", "number", 12, "Required minimum password length."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const minLength = resolveNum(params, "minLength", 12);
      const actual = num(input);
      if (actual >= minLength) return result("pass", 100, `Password minimum length is ${actual}, meets requirement of ${minLength}.`);
      if (actual >= minLength - 2) return result("warn", 50, `Password minimum length is ${actual}, below requirement of ${minLength}.`);
      return result("fail", 10, `Password minimum length is only ${actual}, far below requirement of ${minLength}.`);
    },
  },

  // 3
  {
    id: "TPL-003",
    name: "Access Reviews Completed Within Period",
    description: "Verifies that user access reviews are completed within the configured review period.",
    category: "CC6",
    controlIds: ["CC6.3"],
    parameters: [
      param("reviewPeriodDays", "Review Period (days)", "number", 90, "Maximum days between access reviews."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "reviewPeriodDays", 90);
      const daysSinceReview = num(input);
      if (daysSinceReview <= period) return result("pass", 100, `Access review completed ${daysSinceReview} days ago, within ${period}-day period.`);
      if (daysSinceReview <= period * 1.5) return result("warn", 40, `Access review is overdue: ${daysSinceReview} days since last review (limit: ${period} days).`);
      return result("fail", 0, `Access review significantly overdue: ${daysSinceReview} days since last review (limit: ${period} days).`);
    },
  },

  // 4
  {
    id: "TPL-004",
    name: "Encryption at Rest Enabled",
    description: "Confirms that encryption at rest is enabled for data storage services.",
    category: "CC6",
    controlIds: ["CC6.7"],
    parameters: [
      param("services", "Services to Check", "string[]", ["all"], "List of services to verify, or 'all'."),
    ],
    enabledByDefault: true,
    check(input) {
      const enabled = bool(input);
      if (enabled) return result("pass", 100, "Encryption at rest is enabled.");
      return result("fail", 0, "Encryption at rest is NOT enabled.");
    },
  },

  // 5
  {
    id: "TPL-005",
    name: "Encryption in Transit Enforced",
    description: "Verifies that TLS/SSL is enforced for all data in transit.",
    category: "CC6",
    controlIds: ["CC6.7"],
    parameters: [
      param("minTlsVersion", "Minimum TLS Version", "string", "1.2", "Minimum acceptable TLS version."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const minVersion = (params["minTlsVersion"] as string) ?? "1.2";
      const actual = input.value as string;
      if (!actual) return result("fail", 0, "TLS configuration not found.");
      if (actual >= minVersion) return result("pass", 100, `TLS ${actual} in use, meets minimum of ${minVersion}.`);
      return result("fail", 20, `TLS ${actual} in use, below minimum of ${minVersion}.`);
    },
  },

  // 6
  {
    id: "TPL-006",
    name: "SSO Configured for All Applications",
    description: "Checks that single sign-on is configured for all critical applications.",
    category: "CC6",
    controlIds: ["CC6.1"],
    parameters: [
      param("threshold", "SSO Coverage (%)", "number", 100, "Required percentage of apps with SSO."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const threshold = resolveNum(params, "threshold", 100);
      const coverage = pct(input);
      if (coverage >= threshold) return result("pass", 100, `SSO coverage is ${coverage}%.`);
      if (coverage >= 80) return result("warn", 60, `SSO coverage is ${coverage}%, below target of ${threshold}%.`);
      return result("fail", 20, `SSO coverage is only ${coverage}%.`);
    },
  },

  // 7
  {
    id: "TPL-007",
    name: "Least Privilege Access Enforcement",
    description: "Checks that access follows the principle of least privilege; no over-permissioned accounts.",
    category: "CC6",
    controlIds: ["CC6.3"],
    parameters: [
      param("maxAdminPercent", "Max Admin Accounts (%)", "number", 5, "Maximum percentage of accounts with admin privileges."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const maxPct = resolveNum(params, "maxAdminPercent", 5);
      const actual = pct(input);
      if (actual <= maxPct) return result("pass", 100, `Admin accounts are ${actual}% of total, within ${maxPct}% limit.`);
      if (actual <= maxPct * 2) return result("warn", 50, `Admin accounts are ${actual}% of total, above ${maxPct}% limit.`);
      return result("fail", 10, `Admin accounts are ${actual}% of total, significantly above ${maxPct}% limit.`);
    },
  },

  // 8
  {
    id: "TPL-008",
    name: "Inactive Account Deprovisioning",
    description: "Verifies that accounts inactive beyond the threshold are automatically disabled.",
    category: "CC6",
    controlIds: ["CC6.3"],
    parameters: [
      param("maxInactiveDays", "Max Inactive Days", "number", 90, "Days of inactivity before account should be disabled."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const maxDays = resolveNum(params, "maxInactiveDays", 90);
      // input.value = number of accounts inactive beyond threshold
      const count = num(input);
      if (count === 0) return result("pass", 100, `No accounts inactive beyond ${maxDays} days.`);
      if (count <= 3) return result("warn", 50, `${count} account(s) inactive beyond ${maxDays} days.`);
      return result("fail", 10, `${count} accounts inactive beyond ${maxDays} days.`);
    },
  },

  // 9
  {
    id: "TPL-009",
    name: "Physical Access Badge Audit",
    description: "Checks that physical access badges are audited within the review period.",
    category: "CC6",
    controlIds: ["CC6.4"],
    parameters: [
      param("reviewPeriodDays", "Review Period (days)", "number", 90, "Maximum days between badge audits."),
    ],
    enabledByDefault: false,
    check(input, params) {
      const period = resolveNum(params, "reviewPeriodDays", 90);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Badge audit completed ${daysSince} days ago.`);
      if (daysSince <= period * 1.5) return result("warn", 40, `Badge audit overdue: ${daysSince} days ago (limit: ${period}).`);
      return result("fail", 0, `Badge audit significantly overdue: ${daysSince} days (limit: ${period}).`);
    },
  },

  // 10
  {
    id: "TPL-010",
    name: "Data Disposal Certification",
    description: "Verifies that data disposal certificates are on file for decommissioned assets.",
    category: "CC6",
    controlIds: ["CC6.5"],
    parameters: [
      param("requireCertificate", "Require Certificate", "boolean", true, "Whether a certificate of destruction is required."),
    ],
    enabledByDefault: false,
    check(input, params) {
      const required = resolveBool(params, "requireCertificate", true);
      const hasCert = bool(input);
      if (!required) return result("pass", 100, "Certificate of destruction not required per policy.");
      if (hasCert) return result("pass", 100, "Certificate of destruction is on file.");
      return result("fail", 0, "Certificate of destruction is missing for decommissioned asset.");
    },
  },

  // 11
  {
    id: "TPL-011",
    name: "Endpoint Protection Deployed",
    description: "Checks that endpoint protection / antimalware is deployed on all endpoints.",
    category: "CC6",
    controlIds: ["CC6.6"],
    parameters: [
      param("threshold", "Deployment Coverage (%)", "number", 100, "Required endpoint protection coverage."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const threshold = resolveNum(params, "threshold", 100);
      const coverage = pct(input);
      if (coverage >= threshold) return result("pass", 100, `Endpoint protection deployed on ${coverage}% of endpoints.`);
      if (coverage >= 90) return result("warn", 60, `Endpoint protection at ${coverage}%, below target of ${threshold}%.`);
      return result("fail", 20, `Endpoint protection only at ${coverage}%.`);
    },
  },

  // 12
  {
    id: "TPL-012",
    name: "Network Segmentation Verified",
    description: "Confirms production and development environments are properly segmented.",
    category: "CC6",
    controlIds: ["CC6.8"],
    parameters: [
      param("requireSegmentation", "Require Segmentation", "boolean", true, "Require network segmentation between environments."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const required = resolveBool(params, "requireSegmentation", true);
      if (!required) return result("pass", 100, "Segmentation verification not required.");
      const segmented = bool(input);
      if (segmented) return result("pass", 100, "Network segmentation is in place.");
      return result("fail", 0, "Network segmentation is NOT in place between environments.");
    },
  },

  // 13
  {
    id: "TPL-013",
    name: "Password Complexity Requirements",
    description: "Validates that password policies require sufficient complexity (uppercase, lowercase, numbers, symbols).",
    category: "CC6",
    controlIds: ["CC6.2"],
    parameters: [
      param("minComplexityTypes", "Min Complexity Types", "number", 3, "Minimum number of character types required (1-4)."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const minTypes = resolveNum(params, "minComplexityTypes", 3);
      const actual = num(input);
      if (actual >= minTypes) return result("pass", 100, `Password requires ${actual} character types (min: ${minTypes}).`);
      return result("fail", 20, `Password requires only ${actual} character types (min: ${minTypes}).`);
    },
  },

  // 14
  {
    id: "TPL-014",
    name: "Session Timeout Configured",
    description: "Verifies that user sessions time out after the configured period of inactivity.",
    category: "CC6",
    controlIds: ["CC6.1", "CC6.2"],
    parameters: [
      param("maxTimeoutMinutes", "Max Session Timeout (min)", "number", 30, "Maximum idle session timeout in minutes."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const maxTimeout = resolveNum(params, "maxTimeoutMinutes", 30);
      const actual = num(input);
      if (actual <= maxTimeout && actual > 0) return result("pass", 100, `Session timeout is ${actual} minutes (max: ${maxTimeout}).`);
      if (actual === 0) return result("fail", 0, "No session timeout is configured.");
      return result("warn", 40, `Session timeout is ${actual} minutes, exceeds max of ${maxTimeout}.`);
    },
  },

  // ── CC7: System Operations ──

  // 15
  {
    id: "TPL-015",
    name: "Backup Retention Period",
    description: "Confirms backup retention meets the configured minimum number of days.",
    category: "CC7",
    controlIds: ["CC7.5"],
    parameters: [
      param("retentionDays", "Minimum Retention (days)", "number", 30, "Minimum backup retention period in days."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const minDays = resolveNum(params, "retentionDays", 30);
      const actual = num(input);
      if (actual >= minDays) return result("pass", 100, `Backup retention is ${actual} days (min: ${minDays}).`);
      if (actual >= minDays * 0.5) return result("warn", 50, `Backup retention is ${actual} days, below minimum of ${minDays}.`);
      return result("fail", 10, `Backup retention is only ${actual} days (min: ${minDays}).`);
    },
  },

  // 16
  {
    id: "TPL-016",
    name: "Backup Restoration Tested",
    description: "Verifies that backup restoration has been tested within the review period.",
    category: "CC7",
    controlIds: ["CC7.5"],
    parameters: [
      param("testPeriodDays", "Test Period (days)", "number", 90, "Maximum days between backup restoration tests."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "testPeriodDays", 90);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Backup restoration tested ${daysSince} days ago.`);
      if (daysSince <= period * 2) return result("warn", 40, `Backup restoration test overdue: ${daysSince} days ago.`);
      return result("fail", 0, `Backup restoration test significantly overdue: ${daysSince} days.`);
    },
  },

  // 17
  {
    id: "TPL-017",
    name: "Vulnerability Scan Frequency",
    description: "Checks that vulnerability scans are performed at the required frequency.",
    category: "CC7",
    controlIds: ["CC7.1"],
    parameters: [
      param("maxDaysBetweenScans", "Max Days Between Scans", "number", 7, "Maximum days between vulnerability scans."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const maxDays = resolveNum(params, "maxDaysBetweenScans", 7);
      const daysSince = num(input);
      if (daysSince <= maxDays) return result("pass", 100, `Last vulnerability scan was ${daysSince} days ago (max: ${maxDays}).`);
      if (daysSince <= maxDays * 2) return result("warn", 50, `Vulnerability scan overdue: ${daysSince} days (max: ${maxDays}).`);
      return result("fail", 10, `No vulnerability scan for ${daysSince} days (max: ${maxDays}).`);
    },
  },

  // 18
  {
    id: "TPL-018",
    name: "Critical Vulnerability Remediation SLA",
    description: "Verifies that critical vulnerabilities are remediated within the configured SLA.",
    category: "CC7",
    controlIds: ["CC7.1"],
    parameters: [
      param("slaDays", "SLA (days)", "number", 7, "Maximum days to remediate critical vulnerabilities."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const sla = resolveNum(params, "slaDays", 7);
      // input.value = number of critical vulns exceeding SLA
      const count = num(input);
      if (count === 0) return result("pass", 100, `All critical vulnerabilities remediated within ${sla}-day SLA.`);
      if (count <= 2) return result("warn", 40, `${count} critical vulnerability(ies) exceed ${sla}-day SLA.`);
      return result("fail", 0, `${count} critical vulnerabilities exceed ${sla}-day SLA.`);
    },
  },

  // 19
  {
    id: "TPL-019",
    name: "Security Event Monitoring Active",
    description: "Confirms that security event monitoring (SIEM/CloudTrail) is active.",
    category: "CC7",
    controlIds: ["CC7.2"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const active = bool(input);
      if (active) return result("pass", 100, "Security event monitoring is active.");
      return result("fail", 0, "Security event monitoring is NOT active.");
    },
  },

  // 20
  {
    id: "TPL-020",
    name: "Audit Log Retention",
    description: "Verifies that audit logs are retained for the minimum required period.",
    category: "CC7",
    controlIds: ["CC7.2"],
    parameters: [
      param("minRetentionDays", "Min Retention (days)", "number", 365, "Minimum audit log retention in days."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const minDays = resolveNum(params, "minRetentionDays", 365);
      const actual = num(input);
      if (actual >= minDays) return result("pass", 100, `Log retention is ${actual} days (min: ${minDays}).`);
      if (actual >= minDays * 0.5) return result("warn", 50, `Log retention is ${actual} days, below min of ${minDays}.`);
      return result("fail", 10, `Log retention is only ${actual} days (min: ${minDays}).`);
    },
  },

  // 21
  {
    id: "TPL-021",
    name: "Incident Response Plan Reviewed",
    description: "Checks that the incident response plan has been reviewed and updated within the configured period.",
    category: "CC7",
    controlIds: ["CC7.4"],
    parameters: [
      param("reviewPeriodDays", "Review Period (days)", "number", 365, "Maximum days between IR plan reviews."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "reviewPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `IR plan reviewed ${daysSince} days ago (period: ${period}).`);
      return result("fail", 0, `IR plan review overdue: ${daysSince} days since last review (period: ${period}).`);
    },
  },

  // 22
  {
    id: "TPL-022",
    name: "Incident Response Drill Completed",
    description: "Verifies that an incident response tabletop exercise or drill has been completed recently.",
    category: "CC7",
    controlIds: ["CC7.3", "CC7.4"],
    parameters: [
      param("drillPeriodDays", "Drill Period (days)", "number", 365, "Maximum days between IR drills."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "drillPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `IR drill completed ${daysSince} days ago.`);
      return result("fail", 0, `IR drill overdue: ${daysSince} days since last drill (period: ${period}).`);
    },
  },

  // 23
  {
    id: "TPL-023",
    name: "Disaster Recovery Plan Tested",
    description: "Confirms that the DR plan has been tested within the required period.",
    category: "CC7",
    controlIds: ["CC7.5"],
    parameters: [
      param("testPeriodDays", "Test Period (days)", "number", 365, "Maximum days between DR plan tests."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "testPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `DR plan tested ${daysSince} days ago.`);
      return result("fail", 0, `DR plan test overdue: ${daysSince} days (period: ${period}).`);
    },
  },

  // 24
  {
    id: "TPL-024",
    name: "RTO/RPO Defined and Validated",
    description: "Checks that Recovery Time Objective and Recovery Point Objective are defined.",
    category: "CC7",
    controlIds: ["CC7.5"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const defined = bool(input);
      if (defined) return result("pass", 100, "RTO/RPO are defined and documented.");
      return result("fail", 0, "RTO/RPO are NOT defined or documented.");
    },
  },

  // 25
  {
    id: "TPL-025",
    name: "Penetration Test Completed",
    description: "Verifies that an external penetration test has been completed within the period.",
    category: "CC7",
    controlIds: ["CC7.1"],
    parameters: [
      param("testPeriodDays", "Test Period (days)", "number", 365, "Maximum days between penetration tests."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "testPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Penetration test completed ${daysSince} days ago.`);
      return result("fail", 0, `Penetration test overdue: ${daysSince} days (period: ${period}).`);
    },
  },

  // ── CC8: Change Management ──

  // 26
  {
    id: "TPL-026",
    name: "Branch Protection Enabled",
    description: "Confirms that branch protection rules are configured on production branches.",
    category: "CC8",
    controlIds: ["CC8.1"],
    parameters: [
      param("requireReviews", "Require Reviews", "boolean", true, "Whether pull request reviews are required."),
      param("minApprovals", "Min Approvals", "number", 1, "Minimum number of approvals required."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const requireReviews = resolveBool(params, "requireReviews", true);
      const ctx = (input.context ?? {}) as Record<string, unknown>;
      const hasReviews = Boolean(ctx["requireReviews"] ?? input.value);
      const approvals = (ctx["approvalCount"] as number) ?? 0;
      const minApprovals = resolveNum(params, "minApprovals", 1);

      if (!requireReviews) return result("pass", 100, "Review requirement check disabled by policy.");
      if (hasReviews && approvals >= minApprovals) return result("pass", 100, `Branch protection enabled with ${approvals} required approval(s).`);
      if (hasReviews) return result("warn", 60, `Reviews required but only ${approvals} approval(s) (min: ${minApprovals}).`);
      return result("fail", 0, "Branch protection does not require reviews.");
    },
  },

  // 27
  {
    id: "TPL-027",
    name: "CI/CD Pipeline Has Automated Tests",
    description: "Checks that the CI/CD pipeline includes automated test execution before deployment.",
    category: "CC8",
    controlIds: ["CC8.1"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const hasTests = bool(input);
      if (hasTests) return result("pass", 100, "CI/CD pipeline includes automated tests.");
      return result("fail", 0, "CI/CD pipeline does NOT include automated tests.");
    },
  },

  // 28
  {
    id: "TPL-028",
    name: "Change Approval Required Before Deployment",
    description: "Verifies that changes require explicit approval before production deployment.",
    category: "CC8",
    controlIds: ["CC8.1"],
    parameters: [
      param("requireApproval", "Require Approval", "boolean", true, "Require explicit approval for production deployments."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const required = resolveBool(params, "requireApproval", true);
      if (!required) return result("pass", 100, "Approval requirement disabled by policy.");
      const hasApproval = bool(input);
      if (hasApproval) return result("pass", 100, "Production deployments require explicit approval.");
      return result("fail", 0, "Production deployments do NOT require approval.");
    },
  },

  // 29
  {
    id: "TPL-029",
    name: "Rollback Procedure Documented",
    description: "Confirms that rollback procedures are documented for production deployments.",
    category: "CC8",
    controlIds: ["CC8.1"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const documented = bool(input);
      if (documented) return result("pass", 100, "Rollback procedures are documented.");
      return result("fail", 0, "Rollback procedures are NOT documented.");
    },
  },

  // 30
  {
    id: "TPL-030",
    name: "Separation of Development and Production",
    description: "Verifies that development and production environments are logically separated.",
    category: "CC8",
    controlIds: ["CC8.1"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const separated = bool(input);
      if (separated) return result("pass", 100, "Dev and prod environments are separated.");
      return result("fail", 0, "Dev and prod environments are NOT separated.");
    },
  },

  // ── CC9: Risk Mitigation ──

  // 31
  {
    id: "TPL-031",
    name: "Vendor Risk Assessments Current",
    description: "Checks that vendor risk assessments are completed and current within the configured period.",
    category: "CC9",
    controlIds: ["CC9.2"],
    parameters: [
      param("maxAgeDays", "Max Assessment Age (days)", "number", 365, "Maximum days since last vendor risk assessment."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const maxAge = resolveNum(params, "maxAgeDays", 365);
      const daysSince = num(input);
      if (daysSince <= maxAge) return result("pass", 100, `Vendor assessment is ${daysSince} days old (max: ${maxAge}).`);
      if (daysSince <= maxAge * 1.5) return result("warn", 40, `Vendor assessment is overdue: ${daysSince} days (max: ${maxAge}).`);
      return result("fail", 0, `Vendor assessment is significantly overdue: ${daysSince} days.`);
    },
  },

  // 32
  {
    id: "TPL-032",
    name: "Vendor SOC Reports on File",
    description: "Verifies that SOC 2 or equivalent reports are obtained from critical vendors.",
    category: "CC9",
    controlIds: ["CC9.2"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const onFile = bool(input);
      if (onFile) return result("pass", 100, "Vendor SOC report is on file.");
      return result("fail", 0, "Vendor SOC report is NOT on file.");
    },
  },

  // 33
  {
    id: "TPL-033",
    name: "Vendor Contracts Include Security Requirements",
    description: "Checks that vendor contracts include data protection and security clauses.",
    category: "CC9",
    controlIds: ["CC9.2"],
    parameters: [],
    enabledByDefault: false,
    check(input) {
      const included = bool(input);
      if (included) return result("pass", 100, "Vendor contract includes security requirements.");
      return result("fail", 0, "Vendor contract does NOT include security requirements.");
    },
  },

  // 34
  {
    id: "TPL-034",
    name: "Risk Treatment Plans Documented",
    description: "Confirms that risk treatment plans exist for identified risks.",
    category: "CC9",
    controlIds: ["CC9.1"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const documented = bool(input);
      if (documented) return result("pass", 100, "Risk treatment plans are documented.");
      return result("fail", 0, "Risk treatment plans are NOT documented.");
    },
  },

  // 35
  {
    id: "TPL-035",
    name: "Cyber Insurance Coverage Active",
    description: "Verifies that cyber insurance coverage is active and current.",
    category: "CC9",
    controlIds: ["CC9.1"],
    parameters: [],
    enabledByDefault: false,
    check(input) {
      const active = bool(input);
      if (active) return result("pass", 100, "Cyber insurance coverage is active.");
      return result("warn", 30, "Cyber insurance coverage is not confirmed.");
    },
  },

  // ── CC1: Control Environment ──

  // 36
  {
    id: "TPL-036",
    name: "Code of Conduct Acknowledged",
    description: "Checks that all employees have acknowledged the code of conduct within the period.",
    category: "CC1",
    controlIds: ["CC1.1"],
    parameters: [
      param("acknowledgmentPeriodDays", "Acknowledgment Period (days)", "number", 365, "Maximum days between code of conduct acknowledgments."),
      param("threshold", "Acknowledgment Rate (%)", "number", 100, "Required acknowledgment percentage."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const threshold = resolveNum(params, "threshold", 100);
      const rate = pct(input);
      if (rate >= threshold) return result("pass", 100, `Code of conduct acknowledged by ${rate}% of employees.`);
      if (rate >= 90) return result("warn", 60, `Code of conduct acknowledged by ${rate}% (target: ${threshold}%).`);
      return result("fail", 20, `Only ${rate}% acknowledged the code of conduct (target: ${threshold}%).`);
    },
  },

  // 37
  {
    id: "TPL-037",
    name: "Background Checks Completed",
    description: "Verifies that background checks are completed for all new hires.",
    category: "CC1",
    controlIds: ["CC1.4"],
    parameters: [
      param("threshold", "Completion Rate (%)", "number", 100, "Required completion percentage."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const threshold = resolveNum(params, "threshold", 100);
      const rate = pct(input);
      if (rate >= threshold) return result("pass", 100, `Background checks completed for ${rate}% of new hires.`);
      return result("fail", 20, `Background checks completed for only ${rate}% (target: ${threshold}%).`);
    },
  },

  // 38
  {
    id: "TPL-038",
    name: "Organizational Chart Current",
    description: "Confirms the organizational chart has been updated within the review period.",
    category: "CC1",
    controlIds: ["CC1.3"],
    parameters: [
      param("reviewPeriodDays", "Review Period (days)", "number", 365, "Maximum days since org chart update."),
    ],
    enabledByDefault: false,
    check(input, params) {
      const period = resolveNum(params, "reviewPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Org chart updated ${daysSince} days ago.`);
      return result("fail", 0, `Org chart is ${daysSince} days old (max: ${period}).`);
    },
  },

  // 39
  {
    id: "TPL-039",
    name: "Security Training Completed",
    description: "Checks that security awareness training is completed by all employees.",
    category: "CC1",
    controlIds: ["CC1.4"],
    parameters: [
      param("threshold", "Completion Rate (%)", "number", 100, "Required training completion percentage."),
      param("trainingPeriodDays", "Training Period (days)", "number", 365, "Maximum days between required training."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const threshold = resolveNum(params, "threshold", 100);
      const rate = pct(input);
      if (rate >= threshold) return result("pass", 100, `Security training completed by ${rate}% of employees.`);
      if (rate >= 90) return result("warn", 60, `Security training at ${rate}% (target: ${threshold}%).`);
      return result("fail", 20, `Security training at only ${rate}% (target: ${threshold}%).`);
    },
  },

  // 40
  {
    id: "TPL-040",
    name: "Board Meeting Minutes Available",
    description: "Verifies that board meeting minutes are documented and available for the audit period.",
    category: "CC1",
    controlIds: ["CC1.2"],
    parameters: [
      param("minMeetingsPerYear", "Min Meetings/Year", "number", 4, "Minimum board meetings per year."),
    ],
    enabledByDefault: false,
    check(input, params) {
      const minMeetings = resolveNum(params, "minMeetingsPerYear", 4);
      const actualMeetings = num(input);
      if (actualMeetings >= minMeetings) return result("pass", 100, `${actualMeetings} board meetings documented (min: ${minMeetings}).`);
      return result("fail", 20, `Only ${actualMeetings} board meetings documented (min: ${minMeetings}).`);
    },
  },

  // 41
  {
    id: "TPL-041",
    name: "Control Ownership Assigned",
    description: "Checks that every SOC 2 control has an assigned owner.",
    category: "CC1",
    controlIds: ["CC1.5"],
    parameters: [
      param("threshold", "Assignment Rate (%)", "number", 100, "Required percentage of controls with owners."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const threshold = resolveNum(params, "threshold", 100);
      const rate = pct(input);
      if (rate >= threshold) return result("pass", 100, `${rate}% of controls have assigned owners.`);
      if (rate >= 80) return result("warn", 50, `${rate}% of controls have owners (target: ${threshold}%).`);
      return result("fail", 10, `Only ${rate}% of controls have owners (target: ${threshold}%).`);
    },
  },

  // ── CC2: Communication and Information ──

  // 42
  {
    id: "TPL-042",
    name: "Data Classification Policy Exists",
    description: "Confirms a data classification policy is documented and current.",
    category: "CC2",
    controlIds: ["CC2.1"],
    parameters: [
      param("reviewPeriodDays", "Review Period (days)", "number", 365, "Maximum days since policy review."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "reviewPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Data classification policy reviewed ${daysSince} days ago.`);
      return result("fail", 0, `Data classification policy review overdue: ${daysSince} days (period: ${period}).`);
    },
  },

  // 43
  {
    id: "TPL-043",
    name: "Security Awareness Program Active",
    description: "Verifies an ongoing security awareness program is in place.",
    category: "CC2",
    controlIds: ["CC2.2"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const active = bool(input);
      if (active) return result("pass", 100, "Security awareness program is active.");
      return result("fail", 0, "No active security awareness program.");
    },
  },

  // 44
  {
    id: "TPL-044",
    name: "Privacy Notice Published",
    description: "Checks that a customer-facing privacy notice is published and current.",
    category: "CC2",
    controlIds: ["CC2.3"],
    parameters: [
      param("reviewPeriodDays", "Review Period (days)", "number", 365, "Maximum days since privacy notice review."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "reviewPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Privacy notice reviewed ${daysSince} days ago.`);
      return result("fail", 0, `Privacy notice review overdue: ${daysSince} days.`);
    },
  },

  // 45
  {
    id: "TPL-045",
    name: "Breach Notification Procedure Exists",
    description: "Verifies that a breach notification procedure is documented.",
    category: "CC2",
    controlIds: ["CC2.3"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const exists = bool(input);
      if (exists) return result("pass", 100, "Breach notification procedure is documented.");
      return result("fail", 0, "Breach notification procedure is NOT documented.");
    },
  },

  // ── CC3: Risk Assessment ──

  // 46
  {
    id: "TPL-046",
    name: "Risk Register Maintained",
    description: "Confirms a risk register is maintained and reviewed periodically.",
    category: "CC3",
    controlIds: ["CC3.1", "CC3.2"],
    parameters: [
      param("reviewPeriodDays", "Review Period (days)", "number", 90, "Maximum days between risk register reviews."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "reviewPeriodDays", 90);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Risk register reviewed ${daysSince} days ago.`);
      if (daysSince <= period * 2) return result("warn", 40, `Risk register review overdue: ${daysSince} days.`);
      return result("fail", 0, `Risk register significantly overdue: ${daysSince} days.`);
    },
  },

  // 47
  {
    id: "TPL-047",
    name: "Annual Risk Assessment Completed",
    description: "Checks that an enterprise-wide risk assessment has been completed within the period.",
    category: "CC3",
    controlIds: ["CC3.2"],
    parameters: [
      param("assessmentPeriodDays", "Assessment Period (days)", "number", 365, "Maximum days between risk assessments."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "assessmentPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Risk assessment completed ${daysSince} days ago.`);
      return result("fail", 0, `Risk assessment overdue: ${daysSince} days (period: ${period}).`);
    },
  },

  // 48
  {
    id: "TPL-048",
    name: "Fraud Risk Assessment Completed",
    description: "Verifies that a fraud risk assessment has been performed.",
    category: "CC3",
    controlIds: ["CC3.3"],
    parameters: [
      param("assessmentPeriodDays", "Assessment Period (days)", "number", 365, "Maximum days between fraud risk assessments."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "assessmentPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Fraud risk assessment completed ${daysSince} days ago.`);
      return result("fail", 0, `Fraud risk assessment overdue: ${daysSince} days.`);
    },
  },

  // 49
  {
    id: "TPL-049",
    name: "Significant Change Impact Assessment",
    description: "Confirms that significant changes are assessed for impact on internal controls.",
    category: "CC3",
    controlIds: ["CC3.4"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const assessed = bool(input);
      if (assessed) return result("pass", 100, "Significant changes have been assessed for control impact.");
      return result("fail", 0, "Significant changes have NOT been assessed for control impact.");
    },
  },

  // ── CC4: Monitoring Activities ──

  // 50
  {
    id: "TPL-050",
    name: "Continuous Monitoring Dashboards Active",
    description: "Checks that continuous compliance monitoring dashboards are configured and active.",
    category: "CC4",
    controlIds: ["CC4.1"],
    parameters: [],
    enabledByDefault: true,
    check(input) {
      const active = bool(input);
      if (active) return result("pass", 100, "Continuous monitoring dashboards are active.");
      return result("fail", 0, "Continuous monitoring is NOT active.");
    },
  },

  // 51
  {
    id: "TPL-051",
    name: "Internal Audit Completed",
    description: "Verifies that an internal audit of controls has been completed within the period.",
    category: "CC4",
    controlIds: ["CC4.1"],
    parameters: [
      param("auditPeriodDays", "Audit Period (days)", "number", 365, "Maximum days between internal audits."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "auditPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `Internal audit completed ${daysSince} days ago.`);
      return result("fail", 0, `Internal audit overdue: ${daysSince} days (period: ${period}).`);
    },
  },

  // 52
  {
    id: "TPL-052",
    name: "Deficiency Tracking and Remediation",
    description: "Confirms that identified deficiencies are tracked and remediated within SLA.",
    category: "CC4",
    controlIds: ["CC4.2"],
    parameters: [
      param("slaDays", "Remediation SLA (days)", "number", 30, "Maximum days to remediate a deficiency."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const sla = resolveNum(params, "slaDays", 30);
      // input.value = number of deficiencies exceeding SLA
      const count = num(input);
      if (count === 0) return result("pass", 100, `All deficiencies remediated within ${sla}-day SLA.`);
      if (count <= 2) return result("warn", 50, `${count} deficiency(ies) exceed ${sla}-day SLA.`);
      return result("fail", 10, `${count} deficiencies exceed ${sla}-day SLA.`);
    },
  },

  // ── CC5: Control Activities ──

  // 53
  {
    id: "TPL-053",
    name: "Information Security Policy Suite Complete",
    description: "Checks that the required set of information security policies exists and is current.",
    category: "CC5",
    controlIds: ["CC5.3"],
    parameters: [
      param("requiredPolicies", "Required Policies", "string[]", [
        "Information Security",
        "Access Control",
        "Data Classification",
        "Incident Response",
        "Business Continuity",
        "Change Management",
        "Acceptable Use",
        "Vendor Management",
      ], "List of required policy names."),
      param("reviewPeriodDays", "Review Period (days)", "number", 365, "Maximum days since policy review."),
    ],
    enabledByDefault: true,
    check(input, params) {
      // input.value = number of policies meeting criteria
      const policyCount = num(input);
      const required = (params["requiredPolicies"] as string[]) ?? [];
      const total = required.length;
      if (total === 0) return result("pass", 100, "No policies required per configuration.");
      const rate = Math.round((policyCount / total) * 100);
      if (rate >= 100) return result("pass", 100, `All ${total} required policies are current.`);
      if (rate >= 80) return result("warn", 50, `${policyCount}/${total} required policies are current.`);
      return result("fail", 10, `Only ${policyCount}/${total} required policies are current.`);
    },
  },

  // 54
  {
    id: "TPL-054",
    name: "Technology General Controls Documented",
    description: "Verifies that IT general controls (ITGC) are documented and reviewed.",
    category: "CC5",
    controlIds: ["CC5.1", "CC5.2"],
    parameters: [
      param("reviewPeriodDays", "Review Period (days)", "number", 365, "Maximum days since ITGC review."),
    ],
    enabledByDefault: true,
    check(input, params) {
      const period = resolveNum(params, "reviewPeriodDays", 365);
      const daysSince = num(input);
      if (daysSince <= period) return result("pass", 100, `ITGC documentation reviewed ${daysSince} days ago.`);
      return result("fail", 0, `ITGC documentation review overdue: ${daysSince} days.`);
    },
  },
];

// ─── Template Lookup ─────────────────────────────────────────────────

const _byId = new Map<string, ControlTemplate>();
const _byCategory = new Map<string, ControlTemplate[]>();
const _byControlId = new Map<string, ControlTemplate[]>();

for (const tpl of CONTROL_TEMPLATES) {
  _byId.set(tpl.id, tpl);

  const catList = _byCategory.get(tpl.category) ?? [];
  catList.push(tpl);
  _byCategory.set(tpl.category, catList);

  for (const cid of tpl.controlIds) {
    const cidList = _byControlId.get(cid) ?? [];
    cidList.push(tpl);
    _byControlId.set(cid, cidList);
  }
}

/** Get a template by its ID (e.g. "TPL-001"). */
export function getTemplateById(id: string): ControlTemplate | undefined {
  return _byId.get(id);
}

/** Get all templates in a given SOC 2 category (e.g. "CC6"). */
export function getTemplatesByCategory(category: string): ReadonlyArray<ControlTemplate> {
  return _byCategory.get(category) ?? [];
}

/** Get all templates that map to a specific control ID (e.g. "CC6.2"). */
export function getTemplatesForControl(controlId: string): ReadonlyArray<ControlTemplate> {
  return _byControlId.get(controlId) ?? [];
}

/** Get all templates that are enabled by default. */
export function getEnabledTemplates(): ControlTemplate[] {
  return CONTROL_TEMPLATES.filter((t) => t.enabledByDefault);
}

/** Total number of templates. */
export const TEMPLATE_COUNT = CONTROL_TEMPLATES.length;

// ─── Template Executor ───────────────────────────────────────────────

export interface TemplateExecution {
  templateId: string;
  templateName: string;
  controlIds: string[];
  result: CheckResult;
  parametersUsed: Record<string, unknown>;
}

/**
 * Execute a template check with optional parameter overrides.
 *
 * If no overrides are given, the template's default parameter values are used.
 */
export function executeTemplate(
  template: ControlTemplate,
  input: CheckInput,
  parameterOverrides?: Record<string, unknown>,
): TemplateExecution {
  // Build effective parameters: defaults + overrides
  const effectiveParams: Record<string, unknown> = {};
  for (const p of template.parameters) {
    effectiveParams[p.key] = p.defaultValue;
  }
  if (parameterOverrides) {
    for (const [k, v] of Object.entries(parameterOverrides)) {
      effectiveParams[k] = v;
    }
  }

  const checkResult = template.check(input, effectiveParams);

  return {
    templateId: template.id,
    templateName: template.name,
    controlIds: template.controlIds,
    result: checkResult,
    parametersUsed: effectiveParams,
  };
}

/**
 * Execute all enabled templates (or a specified subset) against a map
 * of template-id → input, returning results for each.
 */
export function executeTemplates(
  inputs: Map<string, CheckInput>,
  parameterOverrides?: Map<string, Record<string, unknown>>,
  templateFilter?: (template: ControlTemplate) => boolean,
): TemplateExecution[] {
  const filter = templateFilter ?? ((t) => t.enabledByDefault);
  const results: TemplateExecution[] = [];

  for (const template of CONTROL_TEMPLATES) {
    if (!filter(template)) continue;
    const input = inputs.get(template.id);
    if (!input) continue;

    const overrides = parameterOverrides?.get(template.id);
    results.push(executeTemplate(template, input, overrides));
  }

  return results;
}
