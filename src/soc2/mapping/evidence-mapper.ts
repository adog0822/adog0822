/**
 * Evidence Mapper — maps cloud resources and API findings to SOC 2 controls.
 *
 * Takes raw API response data from integrations (AWS, GitHub, Okta, etc.)
 * and produces EvidenceItem objects mapped to the relevant SOC 2 control(s).
 */

import type {
  ControlId,
  EvidenceId,
  EvidenceItem,
  EvidenceStatus,
  Finding,
  IntegrationService,
  SourceEvidenceTrace,
  WorkspaceId,
} from "../../types/index.ts";
import { getControlById } from "../controls/registry.ts";

// ─── Raw API Data Types ──────────────────────────────────────────────

/** A generic shape for raw data arriving from integration collectors. */
export interface RawApiData {
  service: IntegrationService;
  resourceType: string;
  resourceName: string;
  region?: string;
  accountId?: string;
  data: Record<string, unknown>;
  collectedAt: string;
}

// ─── Mapping Rule Types ──────────────────────────────────────────────

export interface MappingRule {
  /** Unique rule identifier. */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Integration service this rule applies to. */
  service: IntegrationService;
  /** Resource type pattern this rule matches (case-insensitive). */
  resourceType: string;
  /** SOC 2 control IDs this rule maps to. */
  controlIds: string[];
  /** Keywords that trigger this rule when found in the raw data. */
  keywords: string[];
  /** Evaluate the raw data and produce findings + a score. */
  evaluate: (data: Record<string, unknown>) => EvaluationResult;
}

export interface EvaluationResult {
  score: number; // 0–100
  status: EvidenceStatus;
  findings: Finding[];
}

// ─── Built-In Mapping Rules ──────────────────────────────────────────

function finding(
  severity: Finding["severity"],
  title: string,
  description: string,
  remediation: string,
  auditorQuestion: string,
): Finding {
  return { severity, title, description, remediation, auditorQuestion };
}

export const MAPPING_RULES: ReadonlyArray<MappingRule> = [
  // ── AWS IAM MFA ────────────────────────────────────────────────────
  {
    id: "aws-iam-mfa",
    name: "AWS IAM MFA Enforcement",
    service: "aws",
    resourceType: "iam-user",
    controlIds: ["CC6.1", "CC6.2"],
    keywords: ["MFA", "multi-factor", "IAM", "authentication"],
    evaluate(data) {
      const mfaEnabled = Boolean(data["mfaEnabled"]);
      const isRoot = Boolean(data["isRoot"]);
      if (mfaEnabled) {
        return {
          score: 100,
          status: "pass",
          findings: [
            finding(
              "info",
              "MFA enabled",
              "Multi-factor authentication is enabled for this IAM user.",
              "No action required.",
              "Can you demonstrate that MFA is enforced for all IAM users?",
            ),
          ],
        };
      }
      return {
        score: 0,
        status: "fail",
        findings: [
          finding(
            isRoot ? "critical" : "high",
            `MFA not enabled${isRoot ? " (root account)" : ""}`,
            `Multi-factor authentication is not enabled for this ${isRoot ? "root" : "IAM"} user.`,
            `Enable MFA for this user immediately. Use a hardware token or virtual MFA device.`,
            "How do you ensure all users, including root, have MFA enabled?",
          ),
        ],
      };
    },
  },

  // ── GitHub 2FA ─────────────────────────────────────────────────────
  {
    id: "github-2fa",
    name: "GitHub Organization 2FA Enforcement",
    service: "github",
    resourceType: "org-settings",
    controlIds: ["CC6.2"],
    keywords: ["2FA", "two-factor", "GitHub", "authentication"],
    evaluate(data) {
      const twoFactorRequired = Boolean(data["two_factor_requirement_enabled"]);
      if (twoFactorRequired) {
        return {
          score: 100,
          status: "pass",
          findings: [
            finding(
              "info",
              "GitHub 2FA enforced",
              "Two-factor authentication is required for all organization members.",
              "No action required.",
              "Is 2FA enforced organization-wide on GitHub?",
            ),
          ],
        };
      }
      return {
        score: 0,
        status: "fail",
        findings: [
          finding(
            "high",
            "GitHub 2FA not enforced",
            "Two-factor authentication is not required for organization members.",
            "Enable the organization-level 2FA requirement under Settings > Authentication security.",
            "How do you enforce multi-factor authentication for all developers with code access?",
          ),
        ],
      };
    },
  },

  // ── AWS CloudTrail ─────────────────────────────────────────────────
  {
    id: "aws-cloudtrail",
    name: "AWS CloudTrail Logging",
    service: "aws",
    resourceType: "cloudtrail",
    controlIds: ["CC7.2"],
    keywords: ["CloudTrail", "audit log", "logging", "monitoring", "trail"],
    evaluate(data) {
      const isMultiRegion = Boolean(data["IsMultiRegionTrail"]);
      const isLogging = Boolean(data["IsLogging"]);
      const hasLogValidation = Boolean(data["LogFileValidationEnabled"]);

      const issues: Finding[] = [];
      let score = 0;

      if (!isLogging) {
        issues.push(
          finding(
            "critical",
            "CloudTrail logging disabled",
            "CloudTrail is not actively logging API calls.",
            "Enable logging on this CloudTrail trail immediately.",
            "Can you demonstrate that all API activity is logged?",
          ),
        );
        return { score: 0, status: "fail", findings: issues };
      }
      score += 40;

      if (!isMultiRegion) {
        issues.push(
          finding(
            "high",
            "CloudTrail not multi-region",
            "CloudTrail is only logging in a single region, leaving other regions unmonitored.",
            "Enable multi-region logging for complete coverage.",
            "Is API logging enabled across all AWS regions?",
          ),
        );
      } else {
        score += 30;
      }

      if (!hasLogValidation) {
        issues.push(
          finding(
            "medium",
            "Log file validation disabled",
            "CloudTrail log file integrity validation is not enabled.",
            "Enable log file validation to detect tampering.",
            "How do you ensure the integrity of your audit logs?",
          ),
        );
      } else {
        score += 30;
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "CloudTrail properly configured",
            "CloudTrail is multi-region with log validation enabled.",
            "No action required.",
            "Show me your CloudTrail configuration including multi-region and log validation settings.",
          ),
        );
      }

      return {
        score,
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── AWS S3 Encryption ──────────────────────────────────────────────
  {
    id: "aws-s3-encryption",
    name: "AWS S3 Bucket Encryption",
    service: "aws",
    resourceType: "s3-bucket",
    controlIds: ["CC6.7"],
    keywords: ["encryption", "S3", "bucket", "encryption at rest", "SSE", "KMS"],
    evaluate(data) {
      const encryption = data["ServerSideEncryptionConfiguration"] as
        | Record<string, unknown>
        | undefined;
      const publicAccessBlocked = Boolean(data["PublicAccessBlockEnabled"]);

      const issues: Finding[] = [];
      let score = 0;

      if (encryption) {
        const algorithm = (encryption["SSEAlgorithm"] as string) ?? "";
        if (algorithm.includes("aws:kms")) {
          score += 60;
          issues.push(
            finding(
              "info",
              "S3 encrypted with KMS",
              "S3 bucket uses AWS KMS for server-side encryption.",
              "No action required.",
              "What encryption method is used for data at rest in S3?",
            ),
          );
        } else if (algorithm.includes("AES256")) {
          score += 50;
          issues.push(
            finding(
              "low",
              "S3 encrypted with SSE-S3",
              "S3 bucket uses SSE-S3 (AES-256). Consider upgrading to KMS for key management.",
              "Consider using SSE-KMS for customer-managed key control.",
              "Do you use customer-managed encryption keys for your data stores?",
            ),
          );
        }
      } else {
        issues.push(
          finding(
            "critical",
            "S3 bucket not encrypted",
            "Server-side encryption is not enabled on this S3 bucket.",
            "Enable default encryption using SSE-KMS or SSE-S3.",
            "How do you ensure all data at rest is encrypted?",
          ),
        );
      }

      if (publicAccessBlocked) {
        score += 40;
      } else {
        issues.push(
          finding(
            "high",
            "S3 public access not blocked",
            "Public access block is not fully enabled on this bucket.",
            "Enable the S3 Block Public Access setting at the bucket level.",
            "How do you prevent accidental public exposure of data?",
          ),
        );
      }

      return {
        score,
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── Okta SSO Configuration ─────────────────────────────────────────
  {
    id: "okta-sso",
    name: "Okta SSO Configuration",
    service: "okta",
    resourceType: "sso-config",
    controlIds: ["CC6.1", "CC6.3"],
    keywords: ["SSO", "Okta", "single sign-on", "identity provider", "SAML"],
    evaluate(data) {
      const ssoEnabled = Boolean(data["ssoEnabled"]);
      const mfaPolicyActive = Boolean(data["mfaPolicyActive"]);
      const sessionLifetimeMinutes = (data["sessionLifetimeMinutes"] as number) ?? Infinity;

      const issues: Finding[] = [];
      let score = 0;

      if (!ssoEnabled) {
        return {
          score: 0,
          status: "fail",
          findings: [
            finding(
              "critical",
              "SSO not configured",
              "Single sign-on is not enabled in Okta.",
              "Configure SSO with SAML or OIDC for all critical applications.",
              "Do you use a centralized identity provider with SSO?",
            ),
          ],
        };
      }
      score += 40;

      if (mfaPolicyActive) {
        score += 30;
      } else {
        issues.push(
          finding(
            "high",
            "Okta MFA policy not active",
            "MFA is not enforced via Okta authentication policies.",
            "Create and enable an MFA policy requiring a second factor for all users.",
            "Is MFA enforced at the identity provider level?",
          ),
        );
      }

      if (sessionLifetimeMinutes <= 480) {
        score += 30;
      } else {
        issues.push(
          finding(
            "medium",
            "Long session lifetime",
            `Okta session lifetime is ${sessionLifetimeMinutes} minutes. Sessions over 8 hours increase risk.`,
            "Set session lifetime to 8 hours (480 minutes) or less.",
            "What are your session timeout policies?",
          ),
        );
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "Okta SSO properly configured",
            "SSO, MFA, and session controls are configured appropriately.",
            "No action required.",
            "Walk me through your Okta SSO configuration including MFA and session policies.",
          ),
        );
      }

      return {
        score,
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── GitHub Branch Protection ───────────────────────────────────────
  {
    id: "github-branch-protection",
    name: "GitHub Branch Protection Rules",
    service: "github",
    resourceType: "branch-protection",
    controlIds: ["CC8.1"],
    keywords: ["branch protection", "code review", "pull request", "merge", "CI/CD"],
    evaluate(data) {
      const enforced = Boolean(data["enforce_admins"]);
      const requireReviews = Boolean(data["required_pull_request_reviews"]);
      const requiredApprovals = (data["required_approving_review_count"] as number) ?? 0;
      const requireStatusChecks = Boolean(data["required_status_checks"]);
      const requireLinearHistory = Boolean(data["required_linear_history"]);

      const issues: Finding[] = [];
      let score = 0;

      if (requireReviews) {
        score += 30;
        if (requiredApprovals >= 2) {
          score += 10;
        } else {
          issues.push(
            finding(
              "low",
              "Only one approval required",
              `Branch protection requires ${requiredApprovals} approval(s). Two or more is recommended.`,
              "Increase required approving review count to at least 2.",
              "How many code review approvals are required before merging?",
            ),
          );
        }
      } else {
        issues.push(
          finding(
            "high",
            "Pull request reviews not required",
            "Branch protection does not require pull request reviews before merging.",
            "Enable required pull request reviews on the default branch.",
            "Are code reviews mandatory before changes can be deployed to production?",
          ),
        );
      }

      if (requireStatusChecks) {
        score += 25;
      } else {
        issues.push(
          finding(
            "medium",
            "Status checks not required",
            "Branch protection does not require status checks (CI) to pass before merging.",
            "Add required status checks for your CI pipeline.",
            "Are automated tests required to pass before code can be merged?",
          ),
        );
      }

      if (enforced) {
        score += 20;
      } else {
        issues.push(
          finding(
            "medium",
            "Branch protection not enforced for admins",
            "Administrators can bypass branch protection rules.",
            "Enable 'Include administrators' to enforce rules for all users.",
            "Can anyone, including administrators, bypass your change management controls?",
          ),
        );
      }

      if (requireLinearHistory) {
        score += 15;
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "Branch protection fully configured",
            "All recommended branch protection settings are enabled.",
            "No action required.",
            "Show me your branch protection configuration for production branches.",
          ),
        );
      }

      return {
        score,
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── AWS Backup Configuration ───────────────────────────────────────
  {
    id: "aws-backup",
    name: "AWS Backup Configuration",
    service: "aws",
    resourceType: "backup-plan",
    controlIds: ["CC7.5"],
    keywords: ["backup", "recovery", "retention", "disaster recovery", "restore"],
    evaluate(data) {
      const hasBackupPlan = Boolean(data["BackupPlanId"]);
      const retentionDays = (data["Lifecycle"]
        ? (data["Lifecycle"] as Record<string, unknown>)["DeleteAfterDays"]
        : data["RetentionDays"]) as number | undefined;
      const crossRegion = Boolean(data["CopyActions"] && (data["CopyActions"] as unknown[]).length > 0);

      const issues: Finding[] = [];
      let score = 0;

      if (!hasBackupPlan) {
        return {
          score: 0,
          status: "fail",
          findings: [
            finding(
              "critical",
              "No backup plan configured",
              "No AWS Backup plan is associated with this resource.",
              "Create an AWS Backup plan with appropriate retention and cross-region copy.",
              "How do you ensure backups are taken for all critical systems?",
            ),
          ],
        };
      }
      score += 30;

      if (retentionDays !== undefined && retentionDays >= 30) {
        score += 35;
      } else {
        issues.push(
          finding(
            "medium",
            `Backup retention too short`,
            `Backup retention is ${retentionDays ?? "not set"} days. Minimum 30 days recommended.`,
            "Set backup retention to at least 30 days.",
            "What is your backup retention period and how was it determined?",
          ),
        );
      }

      if (crossRegion) {
        score += 35;
      } else {
        issues.push(
          finding(
            "medium",
            "No cross-region backup copy",
            "Backups are not copied to a secondary region for disaster recovery.",
            "Add a cross-region copy action to your backup plan.",
            "Are backups replicated to a geographically separate location?",
          ),
        );
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "Backup plan properly configured",
            "Backup plan exists with adequate retention and cross-region replication.",
            "No action required.",
            "Show me your backup configuration including retention and cross-region settings.",
          ),
        );
      }

      return {
        score,
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── AWS IAM Password Policy ────────────────────────────────────────
  {
    id: "aws-iam-password-policy",
    name: "AWS IAM Password Policy",
    service: "aws",
    resourceType: "iam-password-policy",
    controlIds: ["CC6.2"],
    keywords: ["password", "password policy", "complexity", "rotation"],
    evaluate(data) {
      const minLength = (data["MinimumPasswordLength"] as number) ?? 0;
      const requireUppercase = Boolean(data["RequireUppercaseCharacters"]);
      const requireLowercase = Boolean(data["RequireLowercaseCharacters"]);
      const requireNumbers = Boolean(data["RequireNumbers"]);
      const requireSymbols = Boolean(data["RequireSymbols"]);
      const maxAge = (data["MaxPasswordAge"] as number) ?? 0;

      const issues: Finding[] = [];
      let score = 0;

      if (minLength >= 14) {
        score += 30;
      } else if (minLength >= 12) {
        score += 20;
        issues.push(
          finding(
            "low",
            "Password minimum length could be stronger",
            `Password minimum length is ${minLength}. 14+ characters is recommended.`,
            "Increase minimum password length to 14 characters.",
            "What is your password complexity policy?",
          ),
        );
      } else {
        issues.push(
          finding(
            "high",
            "Weak password minimum length",
            `Password minimum length is ${minLength}. 12 characters is the minimum; 14+ is recommended.`,
            "Increase minimum password length to at least 14 characters.",
            "What is your password complexity policy?",
          ),
        );
      }

      const complexityCount = [requireUppercase, requireLowercase, requireNumbers, requireSymbols].filter(Boolean).length;
      score += complexityCount * 10;

      if (complexityCount < 4) {
        issues.push(
          finding(
            "medium",
            "Incomplete password complexity requirements",
            `Only ${complexityCount}/4 complexity requirements are enabled (uppercase, lowercase, numbers, symbols).`,
            "Enable all four password complexity requirements.",
            "What character types are required in passwords?",
          ),
        );
      }

      if (maxAge > 0 && maxAge <= 90) {
        score += 20;
      } else if (maxAge > 90) {
        score += 10;
        issues.push(
          finding(
            "low",
            "Password rotation period is long",
            `Password maximum age is ${maxAge} days. 90 days or less is recommended.`,
            "Set password maximum age to 90 days.",
            "How often are passwords required to be rotated?",
          ),
        );
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "Password policy meets standards",
            "IAM password policy meets or exceeds all recommended settings.",
            "No action required.",
            "Walk me through your IAM password policy configuration.",
          ),
        );
      }

      return {
        score: Math.min(score, 100),
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── AWS VPC Security Groups ────────────────────────────────────────
  {
    id: "aws-vpc-security-groups",
    name: "AWS VPC Security Group Configuration",
    service: "aws",
    resourceType: "security-group",
    controlIds: ["CC6.6", "CC6.8"],
    keywords: ["security group", "VPC", "network", "firewall", "inbound", "ingress"],
    evaluate(data) {
      const ingressRules = (data["IpPermissions"] as unknown[]) ?? [];
      const issues: Finding[] = [];
      let score = 100;

      let hasOpenSsh = false;
      let hasOpenRdp = false;
      let hasOpenAll = false;

      for (const rule of ingressRules) {
        const r = rule as Record<string, unknown>;
        const fromPort = r["FromPort"] as number;
        const toPort = r["ToPort"] as number;
        const ipRanges = (r["IpRanges"] as Array<Record<string, string>>) ?? [];

        for (const range of ipRanges) {
          if (range["CidrIp"] === "0.0.0.0/0" || range["CidrIp"] === "::/0") {
            if (fromPort === 22 && toPort === 22) hasOpenSsh = true;
            if (fromPort === 3389 && toPort === 3389) hasOpenRdp = true;
            if (fromPort === 0 && toPort === 65535) hasOpenAll = true;
          }
        }
      }

      if (hasOpenAll) {
        score = 0;
        issues.push(
          finding(
            "critical",
            "All ports open to the internet",
            "Security group allows all traffic (0-65535) from 0.0.0.0/0.",
            "Restrict inbound rules to only necessary ports and known CIDR blocks.",
            "How do you ensure network access is restricted to the minimum necessary?",
          ),
        );
      }

      if (hasOpenSsh) {
        score = Math.min(score, 20);
        issues.push(
          finding(
            "critical",
            "SSH open to the internet",
            "Port 22 (SSH) is accessible from 0.0.0.0/0.",
            "Restrict SSH access to specific trusted IP ranges or use a bastion host / SSM.",
            "How is remote administrative access to servers controlled?",
          ),
        );
      }

      if (hasOpenRdp) {
        score = Math.min(score, 20);
        issues.push(
          finding(
            "critical",
            "RDP open to the internet",
            "Port 3389 (RDP) is accessible from 0.0.0.0/0.",
            "Restrict RDP access to specific trusted IP ranges or use a VPN.",
            "How is remote desktop access controlled and monitored?",
          ),
        );
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "Security group properly configured",
            "No overly permissive inbound rules detected.",
            "No action required.",
            "How are your network security groups configured and reviewed?",
          ),
        );
      }

      return {
        score,
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── AWS KMS Key Configuration ──────────────────────────────────────
  {
    id: "aws-kms",
    name: "AWS KMS Key Configuration",
    service: "aws",
    resourceType: "kms-key",
    controlIds: ["CC6.7"],
    keywords: ["KMS", "key management", "encryption key", "CMK", "customer managed key"],
    evaluate(data) {
      const keyState = data["KeyState"] as string;
      const rotationEnabled = Boolean(data["KeyRotationEnabled"]);
      const keyManager = data["KeyManager"] as string;

      const issues: Finding[] = [];
      let score = 0;

      if (keyState !== "Enabled") {
        return {
          score: 0,
          status: "fail",
          findings: [
            finding(
              "high",
              "KMS key not in Enabled state",
              `KMS key is in '${keyState}' state.`,
              "Review and re-enable the key if it is still required.",
              "How do you manage the lifecycle of encryption keys?",
            ),
          ],
        };
      }
      score += 40;

      if (rotationEnabled) {
        score += 40;
      } else {
        issues.push(
          finding(
            "medium",
            "KMS key rotation not enabled",
            "Automatic key rotation is not enabled for this customer-managed KMS key.",
            "Enable automatic key rotation (annually) for this KMS key.",
            "Is automatic key rotation enabled for your encryption keys?",
          ),
        );
      }

      if (keyManager === "CUSTOMER") {
        score += 20;
      } else {
        issues.push(
          finding(
            "low",
            "AWS-managed key in use",
            "This key is managed by AWS, not customer-managed. Customer-managed keys provide more control.",
            "Consider using customer-managed KMS keys for sensitive workloads.",
            "Do you use customer-managed or AWS-managed encryption keys?",
          ),
        );
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "KMS key properly configured",
            "Customer-managed key with rotation enabled.",
            "No action required.",
            "Describe your encryption key management practices.",
          ),
        );
      }

      return {
        score,
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── Okta Access Review ─────────────────────────────────────────────
  {
    id: "okta-access-review",
    name: "Okta User Access Review",
    service: "okta",
    resourceType: "access-review",
    controlIds: ["CC6.3"],
    keywords: ["access review", "user review", "recertification", "provisioning"],
    evaluate(data) {
      const lastReviewDate = data["lastReviewDate"] as string | undefined;
      const reviewCompletionPercent = (data["reviewCompletionPercent"] as number) ?? 0;
      const inactiveUsersCount = (data["inactiveUsersCount"] as number) ?? 0;

      const issues: Finding[] = [];
      let score = 0;

      if (!lastReviewDate) {
        return {
          score: 0,
          status: "fail",
          findings: [
            finding(
              "high",
              "No access review completed",
              "No user access review has been completed in Okta.",
              "Initiate a user access review covering all applications and entitlements.",
              "How frequently do you conduct user access reviews?",
            ),
          ],
        };
      }

      const daysSinceReview = Math.floor(
        (Date.now() - new Date(lastReviewDate).getTime()) / (1000 * 60 * 60 * 24),
      );

      if (daysSinceReview <= 90) {
        score += 50;
      } else if (daysSinceReview <= 180) {
        score += 30;
        issues.push(
          finding(
            "medium",
            "Access review overdue",
            `Last access review was ${daysSinceReview} days ago. Quarterly reviews are recommended.`,
            "Complete a user access review within the next 30 days.",
            "When was the last user access review completed?",
          ),
        );
      } else {
        issues.push(
          finding(
            "high",
            "Access review significantly overdue",
            `Last access review was ${daysSinceReview} days ago.`,
            "Immediately schedule and complete a user access review.",
            "When was the last user access review completed?",
          ),
        );
      }

      if (reviewCompletionPercent >= 100) {
        score += 30;
      } else {
        issues.push(
          finding(
            "medium",
            "Incomplete access review",
            `Access review is only ${reviewCompletionPercent}% complete.`,
            "Complete the outstanding access review items.",
            "Are all user access reviews completed for every application?",
          ),
        );
      }

      if (inactiveUsersCount === 0) {
        score += 20;
      } else {
        issues.push(
          finding(
            "medium",
            "Inactive users detected",
            `${inactiveUsersCount} inactive user(s) still have active accounts.`,
            "Deactivate inactive user accounts.",
            "How do you handle accounts for users who have left or are inactive?",
          ),
        );
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "Access reviews current",
            "User access reviews are completed on schedule with no inactive users.",
            "No action required.",
            "Walk me through your most recent access review results.",
          ),
        );
      }

      return {
        score: Math.min(score, 100),
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },

  // ── AWS GuardDuty ──────────────────────────────────────────────────
  {
    id: "aws-guardduty",
    name: "AWS GuardDuty Threat Detection",
    service: "aws",
    resourceType: "guardduty",
    controlIds: ["CC6.6", "CC7.1", "CC7.2"],
    keywords: ["GuardDuty", "threat detection", "anomaly", "IDS"],
    evaluate(data) {
      const enabled = Boolean(data["Enabled"]);
      const s3Protection = Boolean(data["S3LogsEnabled"]);

      if (!enabled) {
        return {
          score: 0,
          status: "fail",
          findings: [
            finding(
              "high",
              "GuardDuty not enabled",
              "AWS GuardDuty threat detection is not enabled.",
              "Enable GuardDuty in all regions to detect threats automatically.",
              "What automated threat detection capabilities do you have in place?",
            ),
          ],
        };
      }

      const issues: Finding[] = [];
      let score = 70;

      if (s3Protection) {
        score += 30;
      } else {
        issues.push(
          finding(
            "medium",
            "GuardDuty S3 protection not enabled",
            "S3 data event monitoring is not enabled in GuardDuty.",
            "Enable S3 protection in GuardDuty for data-plane threat detection.",
            "Does your threat detection cover data access patterns in S3?",
          ),
        );
      }

      if (issues.length === 0) {
        issues.push(
          finding(
            "info",
            "GuardDuty fully enabled",
            "GuardDuty is enabled with S3 protection.",
            "No action required.",
            "What threats has GuardDuty detected in the past 90 days?",
          ),
        );
      }

      return {
        score,
        status: score >= 70 ? "pass" : score >= 40 ? "warn" : "fail",
        findings: issues,
      };
    },
  },
];

// ─── Rule Lookup ─────────────────────────────────────────────────────

const _rulesByServiceResource = new Map<string, MappingRule[]>();

for (const rule of MAPPING_RULES) {
  const key = `${rule.service}:${rule.resourceType}`;
  const list = _rulesByServiceResource.get(key) ?? [];
  list.push(rule);
  _rulesByServiceResource.set(key, list);
}

/** Find all mapping rules applicable to a service + resource type pair. */
export function getRulesForResource(
  service: IntegrationService,
  resourceType: string,
): ReadonlyArray<MappingRule> {
  return _rulesByServiceResource.get(`${service}:${resourceType}`) ?? [];
}

// ─── Evidence Mapper ─────────────────────────────────────────────────

let _evidenceCounter = 0;

function generateEvidenceId(): EvidenceId {
  _evidenceCounter += 1;
  return `evi_${Date.now()}_${_evidenceCounter}` as EvidenceId;
}

/** Reset the internal counter (useful for deterministic testing). */
export function resetEvidenceCounter(): void {
  _evidenceCounter = 0;
}

/**
 * Map a single raw API data item to zero or more EvidenceItems.
 * One raw item can produce multiple evidence items when the applicable
 * rule maps to multiple controls.
 */
export function mapRawDataToEvidence(
  raw: RawApiData,
  workspaceId: WorkspaceId,
  sourceTrace: SourceEvidenceTrace,
): EvidenceItem[] {
  const rules = getRulesForResource(raw.service, raw.resourceType);
  if (rules.length === 0) return [];

  const results: EvidenceItem[] = [];
  const now = new Date().toISOString();

  for (const rule of rules) {
    const evaluation = rule.evaluate(raw.data);

    for (const controlIdStr of rule.controlIds) {
      const ctrl = getControlById(controlIdStr);
      if (!ctrl) continue;

      results.push({
        id: generateEvidenceId(),
        workspaceId,
        controlId: controlIdStr as ControlId,
        controlTitle: ctrl.title,
        service: raw.service,
        resourceName: raw.resourceName,
        status: evaluation.status,
        score: evaluation.score,
        findings: evaluation.findings,
        sourceTrace,
        metadata: {
          ruleId: rule.id,
          ruleName: rule.name,
          resourceType: raw.resourceType,
          region: raw.region,
          accountId: raw.accountId,
          collectedAt: raw.collectedAt,
        },
        createdAt: now,
        updatedAt: now,
        blacklisted: false,
        deleted: false,
      });
    }
  }

  return results;
}

/**
 * Map a batch of raw API data items to evidence items.
 * Convenience wrapper over mapRawDataToEvidence.
 */
export function mapBatchToEvidence(
  items: RawApiData[],
  workspaceId: WorkspaceId,
  sourceTrace: SourceEvidenceTrace,
): EvidenceItem[] {
  return items.flatMap((item) => mapRawDataToEvidence(item, workspaceId, sourceTrace));
}
