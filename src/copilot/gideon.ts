/**
 * Gideon — LoxeAI's Compliance Co-Pilot
 *
 * Like GitHub Copilot for compliance. When a user highlights any text
 * on the platform, Gideon translates it into three perspectives:
 *   1. Plain English — what does this actually mean?
 *   2. What Engineers Should Hear — actionable technical guidance
 *   3. Why Auditors Care — SOC 2 Trust Services Criteria context
 *
 * Also surfaces related controls and suggests next actions.
 *
 * Architecture: Read-only from external systems, write-only to its
 * own workspace. The human is always the gatekeeper.
 */

import type {
  GideonQuery,
  GideonResponse,
  ControlId,
  Soc2Category,
} from "../types/index.js";

// ─── SOC 2 Keyword → Control Mapping ──────────────────────────────────

interface KeywordControlMapping {
  keywords: string[];
  controlIds: ControlId[];
  category: Soc2Category;
  domain: string;
}

const KEYWORD_CONTROL_MAP: KeywordControlMapping[] = [
  {
    keywords: ["mfa", "multi-factor", "two-factor", "2fa", "authentication", "login", "sso", "single sign-on", "password"],
    controlIds: ["CC6.1" as ControlId, "CC6.2" as ControlId],
    category: "CC6",
    domain: "Authentication & Identity",
  },
  {
    keywords: ["access", "permission", "role", "privilege", "rbac", "iam", "user account", "provisioning", "deprovisioning"],
    controlIds: ["CC6.1" as ControlId, "CC6.3" as ControlId],
    category: "CC6",
    domain: "Access Control",
  },
  {
    keywords: ["encryption", "encrypt", "aes", "tls", "ssl", "kms", "key management", "at rest", "in transit"],
    controlIds: ["CC6.7" as ControlId],
    category: "CC6",
    domain: "Data Protection",
  },
  {
    keywords: ["firewall", "network", "vpc", "security group", "nacl", "ingress", "egress", "boundary"],
    controlIds: ["CC6.6" as ControlId],
    category: "CC6",
    domain: "Network Security",
  },
  {
    keywords: ["logging", "audit log", "cloudtrail", "monitoring", "detection", "alert", "siem"],
    controlIds: ["CC7.1" as ControlId, "CC7.2" as ControlId],
    category: "CC7",
    domain: "Monitoring & Detection",
  },
  {
    keywords: ["incident", "breach", "response plan", "escalation", "containment", "recovery"],
    controlIds: ["CC7.3" as ControlId, "CC7.4" as ControlId],
    category: "CC7",
    domain: "Incident Response",
  },
  {
    keywords: ["backup", "disaster recovery", "rto", "rpo", "business continuity", "failover", "restore"],
    controlIds: ["CC7.5" as ControlId],
    category: "CC7",
    domain: "Recovery & Continuity",
  },
  {
    keywords: ["change management", "deploy", "release", "ci/cd", "pull request", "code review", "branch protection"],
    controlIds: ["CC8.1" as ControlId],
    category: "CC8",
    domain: "Change Management",
  },
  {
    keywords: ["vendor", "third party", "subservice", "supply chain", "sla", "contract", "due diligence"],
    controlIds: ["CC9.2" as ControlId],
    category: "CC9",
    domain: "Vendor Management",
  },
  {
    keywords: ["risk", "risk assessment", "threat", "vulnerability", "risk register", "risk appetite"],
    controlIds: ["CC3.1" as ControlId, "CC3.2" as ControlId],
    category: "CC3",
    domain: "Risk Assessment",
  },
  {
    keywords: ["policy", "procedure", "standard", "governance", "board", "committee", "oversight"],
    controlIds: ["CC1.1" as ControlId, "CC5.3" as ControlId],
    category: "CC1",
    domain: "Governance & Policy",
  },
  {
    keywords: ["training", "awareness", "onboarding", "background check", "competence", "hr"],
    controlIds: ["CC1.4" as ControlId, "CC2.2" as ControlId],
    category: "CC1",
    domain: "People & Training",
  },
  {
    keywords: ["malware", "antivirus", "endpoint", "edr", "mdm", "device"],
    controlIds: ["CC6.8" as ControlId],
    category: "CC6",
    domain: "Endpoint Protection",
  },
];

// ─── Gideon Core ───────────────────────────────────────────────────────

/**
 * Identify SOC 2 controls related to the selected text.
 * Deterministic keyword matching — no probabilistic drift.
 */
export function identifyRelatedControls(text: string): ControlId[] {
  const lower = text.toLowerCase();
  const matched = new Set<ControlId>();

  for (const mapping of KEYWORD_CONTROL_MAP) {
    for (const kw of mapping.keywords) {
      if (lower.includes(kw)) {
        for (const id of mapping.controlIds) {
          matched.add(id);
        }
        break;
      }
    }
  }

  return Array.from(matched);
}

/**
 * Identify the compliance domain(s) for the selected text.
 */
function identifyDomains(text: string): string[] {
  const lower = text.toLowerCase();
  const domains = new Set<string>();

  for (const mapping of KEYWORD_CONTROL_MAP) {
    for (const kw of mapping.keywords) {
      if (lower.includes(kw)) {
        domains.add(mapping.domain);
        break;
      }
    }
  }

  return Array.from(domains);
}

/**
 * Generate the "Plain English" translation.
 * Takes compliance/technical jargon and makes it human.
 */
export function translateToPlainEnglish(text: string): string {
  const domains = identifyDomains(text);
  const controls = identifyRelatedControls(text);

  if (domains.length === 0) {
    return "This text doesn't map to a specific SOC 2 compliance area. It may be general business context. If you think it's compliance-related, try selecting a more specific passage.";
  }

  const domainList = domains.join(" and ");
  const controlList = controls.join(", ");

  return `This relates to ${domainList}. In simple terms, it's about the safeguards your company has (or needs) to protect systems and data. It maps to SOC 2 control(s) ${controlList}. An auditor will want to see that these safeguards exist, are documented, and are actually working — not just written down.`;
}

/**
 * Generate the "What Engineers Should Hear" perspective.
 * Actionable, specific, technical.
 */
export function translateForEngineers(text: string): string {
  const domains = identifyDomains(text);
  const suggestions: string[] = [];

  for (const domain of domains) {
    switch (domain) {
      case "Authentication & Identity":
        suggestions.push(
          "Ensure MFA is enforced for all user accounts, including service accounts where possible.",
          "SSO should be configured as the primary authentication method.",
          "Password policies must meet minimum complexity requirements (12+ chars, rotation not required per NIST 800-63B)."
        );
        break;
      case "Access Control":
        suggestions.push(
          "Implement least-privilege access. Review IAM policies for overly broad wildcards.",
          "Automate access provisioning/deprovisioning tied to HR onboarding/offboarding.",
          "Quarterly access reviews should be documented and exceptions remediated within 30 days."
        );
        break;
      case "Data Protection":
        suggestions.push(
          "Enable encryption at rest (AES-256) for all data stores — RDS, S3, EBS, DynamoDB.",
          "Enforce TLS 1.2+ for all data in transit. Disable older protocols.",
          "Key rotation should be automated via KMS with annual rotation at minimum."
        );
        break;
      case "Network Security":
        suggestions.push(
          "Lock down security groups to specific CIDRs. No 0.0.0.0/0 on sensitive ports.",
          "Enable VPC Flow Logs for network traffic visibility.",
          "Use private subnets for databases and internal services. Public subnets for ALBs only."
        );
        break;
      case "Monitoring & Detection":
        suggestions.push(
          "CloudTrail must be enabled in all regions with log file validation.",
          "Set up alerts for root account usage, IAM changes, and security group modifications.",
          "Centralize logs — CloudWatch, Datadog, or your SIEM of choice."
        );
        break;
      case "Incident Response":
        suggestions.push(
          "Document a runbook with clear escalation paths and communication plans.",
          "Define severity levels (P1-P4) with target response and resolution times.",
          "Conduct tabletop exercises at least annually and document the results."
        );
        break;
      case "Recovery & Continuity":
        suggestions.push(
          "Define RTO (Recovery Time Objective) and RPO (Recovery Point Objective) for each service.",
          "Automate backups with cross-region replication for critical data.",
          "Test disaster recovery procedures at least annually. Document the test results."
        );
        break;
      case "Change Management":
        suggestions.push(
          "Require pull request reviews (2+ approvers) before merging to main.",
          "Enable branch protection rules — no force pushes, require status checks.",
          "Maintain a change log. CI/CD pipeline should enforce linting, testing, and security scans."
        );
        break;
      case "Vendor Management":
        suggestions.push(
          "Maintain a vendor inventory with risk ratings and review dates.",
          "Require SOC 2 reports or equivalent from vendors handling sensitive data.",
          "Ensure vendor contracts include data processing agreements and breach notification clauses."
        );
        break;
      case "Risk Assessment":
        suggestions.push(
          "Maintain a risk register — threats, likelihood, impact, and mitigation plans.",
          "Conduct annual risk assessments. Document methodology and findings.",
          "Map identified risks to specific controls and monitor mitigation progress."
        );
        break;
      case "Governance & Policy":
        suggestions.push(
          "Policies should be versioned, reviewed annually, and accessible to all employees.",
          "Store policies in a version-controlled system (Git, Notion, Confluence).",
          "Track policy acknowledgment — every employee should sign off within 30 days of hire."
        );
        break;
      case "People & Training":
        suggestions.push(
          "Security awareness training must be completed within 30 days of hire and annually.",
          "Background checks should be completed before granting system access.",
          "Document the offboarding process — access revocation should happen within 24 hours of termination."
        );
        break;
      case "Endpoint Protection":
        suggestions.push(
          "Deploy an MDM solution (Jamf, Kandji, Intune) for all company devices.",
          "Enforce disk encryption (FileVault, BitLocker) and screen lock policies.",
          "Maintain an up-to-date device inventory with compliance status."
        );
        break;
      default:
        suggestions.push("Review the specific SOC 2 control requirements mapped to this area.");
    }
  }

  return suggestions.join("\n\n");
}

/**
 * Generate the "Why Auditors Care" perspective.
 * SOC 2 Trust Services Criteria language. What they'll test.
 */
export function translateForAuditors(text: string): string {
  const domains = identifyDomains(text);
  const perspectives: string[] = [];

  for (const domain of domains) {
    switch (domain) {
      case "Authentication & Identity":
        perspectives.push(
          "TSC CC6.1/CC6.2: The auditor will inspect authentication configurations, verify MFA enrollment rates, and test that unauthorized access attempts are blocked. They'll request a screenshot of your IdP settings and a population extract of all user accounts with their MFA status."
        );
        break;
      case "Access Control":
        perspectives.push(
          "TSC CC6.3: The auditor will request a complete user access listing, compare it against HR records, and verify that terminated employees had access revoked timely. They'll test a sample of access changes to confirm proper authorization workflows."
        );
        break;
      case "Data Protection":
        perspectives.push(
          "TSC CC6.7: The auditor will verify encryption configurations for data at rest and in transit. They'll check KMS key policies, inspect TLS certificates, and confirm that no sensitive data is transmitted over unencrypted channels."
        );
        break;
      case "Monitoring & Detection":
        perspectives.push(
          "TSC CC7.1/CC7.2: The auditor will verify that monitoring tools are configured, review a sample of alerts to confirm they were investigated, and check that audit logs are tamper-evident and retained for the required period."
        );
        break;
      case "Change Management":
        perspectives.push(
          "TSC CC8.1: The auditor will sample changes deployed during the audit period, verify each had proper authorization (peer review, testing, approval), and confirm that emergency changes followed the documented exception process."
        );
        break;
      case "Vendor Management":
        perspectives.push(
          "TSC CC9.2: The auditor will request your vendor inventory, verify that critical vendors have been assessed, review SOC 2 bridge letters or equivalent reports, and confirm that vendor risk is monitored on an ongoing basis."
        );
        break;
      default:
        perspectives.push(
          `The auditor will evaluate controls in the ${domain} domain against the Trust Services Criteria to determine if they are suitably designed and operating effectively throughout the audit period.`
        );
    }
  }

  return perspectives.join("\n\n");
}

/**
 * Generate suggested next actions based on the context.
 */
export function suggestActions(text: string): string[] {
  const domains = identifyDomains(text);
  const actions: string[] = [];

  for (const domain of domains) {
    switch (domain) {
      case "Authentication & Identity":
        actions.push("Run an access review to verify MFA enrollment rates");
        actions.push("Check IdP configuration against SOC 2 requirements");
        break;
      case "Access Control":
        actions.push("Generate an access review report");
        actions.push("Cross-reference user list with HR termination records");
        break;
      case "Data Protection":
        actions.push("Scan for unencrypted data stores");
        actions.push("Verify TLS configuration across all endpoints");
        break;
      case "Monitoring & Detection":
        actions.push("Verify CloudTrail is enabled in all regions");
        actions.push("Review alert response times for the audit period");
        break;
      case "Change Management":
        actions.push("Audit recent deployments for proper review process");
        actions.push("Check branch protection rules are enforced");
        break;
      case "Vendor Management":
        actions.push("Review vendor risk assessment due dates");
        actions.push("Request updated SOC 2 reports from critical vendors");
        break;
      case "Recovery & Continuity":
        actions.push("Verify backup configurations and test restore procedures");
        actions.push("Document RTO/RPO for critical systems");
        break;
      default:
        actions.push(`Review ${domain} controls for completeness`);
    }
  }

  return actions.slice(0, 5);
}

// ─── Main Gideon Response ──────────────────────────────────────────────

/**
 * Ask Gideon: the full compliance co-pilot response.
 *
 * Takes any selected text and returns three perspectives,
 * related controls, and suggested next actions.
 */
export function askGideon(query: GideonQuery): GideonResponse {
  const text = `${query.selectedText} ${query.pageContext}`;

  return {
    plainEnglish: translateToPlainEnglish(text),
    engineerPerspective: translateForEngineers(text),
    auditorPerspective: translateForAuditors(text),
    relatedControls: identifyRelatedControls(text),
    suggestedActions: suggestActions(text),
  };
}
