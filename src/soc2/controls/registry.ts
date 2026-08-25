/**
 * SOC 2 Control Registry — All 33 Common Criteria (CC1–CC9)
 *
 * Each control maps to AICPA 2017 Trust Services Criteria for SOC 2 Type II.
 * Controls are organized by category with evidence requirements, keywords for
 * automated matching, and risk domain classification.
 */

import type {
  Soc2Control,
  Soc2Category,
  ControlId,
  RiskDomain,
} from "../../types/index.ts";

// ─── Helper ───────────────────────────────────────────────────────────

function control(
  number: string,
  category: Soc2Category,
  title: string,
  description: string,
  keywords: string[],
  riskDomain: RiskDomain,
  evidenceRequirements: string[],
  automatable: boolean,
  customizable: boolean,
): Soc2Control {
  return {
    id: number as ControlId,
    category,
    number,
    title,
    description,
    keywords,
    riskDomain,
    evidenceRequirements,
    automatable,
    customizable,
  };
}

// ─── CC1: Control Environment ─────────────────────────────────────────

const CC1_CONTROLS: Soc2Control[] = [
  control(
    "CC1.1",
    "CC1",
    "COSO Principle 1 — Integrity and Ethical Values",
    "The entity demonstrates a commitment to integrity and ethical values. Management sets the tone at the top through a code of conduct, ethics policies, and enforcement mechanisms.",
    ["ethics", "code of conduct", "integrity", "tone at the top", "compliance program", "whistleblower"],
    "governance",
    [
      "Code of conduct / ethics policy document",
      "Employee acknowledgment records",
      "Ethics training completion records",
      "Whistleblower hotline or reporting mechanism",
      "Disciplinary action records for policy violations",
    ],
    false,
    true,
  ),
  control(
    "CC1.2",
    "CC1",
    "COSO Principle 2 — Board Independence and Oversight",
    "The board of directors demonstrates independence from management and exercises oversight of the development and performance of internal controls.",
    ["board", "oversight", "governance", "audit committee", "independence", "directors"],
    "governance",
    [
      "Board charter and committee charters",
      "Meeting minutes and attendance records",
      "Board member independence assessments",
      "Audit committee reports",
      "Board review of risk assessment results",
    ],
    false,
    true,
  ),
  control(
    "CC1.3",
    "CC1",
    "COSO Principle 3 — Management Structure and Authority",
    "Management establishes, with board oversight, structures, reporting lines, and appropriate authorities and responsibilities in the pursuit of objectives.",
    ["org structure", "reporting lines", "authority", "delegation", "management", "organizational chart", "RACI"],
    "governance",
    [
      "Organizational chart",
      "RACI matrix for compliance functions",
      "Delegation of authority documentation",
      "Job descriptions for key roles",
      "Reporting line documentation",
    ],
    false,
    true,
  ),
  control(
    "CC1.4",
    "CC1",
    "COSO Principle 4 — Commitment to Competence",
    "The entity demonstrates a commitment to attract, develop, and retain competent individuals in alignment with objectives.",
    ["competence", "training", "hiring", "onboarding", "skills", "development", "HR", "performance review"],
    "governance",
    [
      "Hiring and onboarding procedures",
      "Training program documentation and completion records",
      "Performance evaluation process and records",
      "Competency requirements for key roles",
      "Background check policy and evidence",
    ],
    false,
    true,
  ),
  control(
    "CC1.5",
    "CC1",
    "COSO Principle 5 — Accountability for Internal Control",
    "The entity holds individuals accountable for their internal control responsibilities in the pursuit of objectives.",
    ["accountability", "responsibility", "performance", "remediation", "metrics", "KPI"],
    "governance",
    [
      "Accountability framework documentation",
      "Control ownership assignments",
      "Performance metrics tied to control objectives",
      "Evidence of corrective actions for control failures",
      "Regular reporting on control effectiveness to management",
    ],
    false,
    true,
  ),
];

// ─── CC2: Communication and Information ───────────────────────────────

const CC2_CONTROLS: Soc2Control[] = [
  control(
    "CC2.1",
    "CC2",
    "COSO Principle 13 — Quality Information",
    "The entity obtains or generates and uses relevant, quality information to support the functioning of internal controls.",
    ["information quality", "data integrity", "logging", "audit trail", "records management", "data classification"],
    "communication",
    [
      "Data classification policy",
      "Information quality controls documentation",
      "Logging and monitoring configurations",
      "Data retention and destruction policies",
      "System-generated reports used for decision-making",
    ],
    true,
    true,
  ),
  control(
    "CC2.2",
    "CC2",
    "COSO Principle 14 — Internal Communication",
    "The entity internally communicates information, including objectives and responsibilities for internal control, necessary to support the functioning of internal controls.",
    ["internal communication", "policy distribution", "training", "awareness", "intranet", "team communication"],
    "communication",
    [
      "Internal communication policies and channels",
      "Security awareness training program and completion rates",
      "Policy acknowledgment records",
      "Internal newsletters or bulletins on security topics",
      "Meeting minutes from security/compliance meetings",
    ],
    false,
    true,
  ),
  control(
    "CC2.3",
    "CC2",
    "COSO Principle 15 — External Communication",
    "The entity communicates with external parties regarding matters affecting the functioning of internal controls.",
    ["external communication", "customer notification", "breach notification", "SLA", "service description", "privacy notice"],
    "communication",
    [
      "External communication policies",
      "Breach notification procedures",
      "Service-level agreements (SLAs)",
      "Customer-facing privacy notices and terms of service",
      "Third-party communication records (e.g., regulator correspondence)",
    ],
    false,
    true,
  ),
];

// ─── CC3: Risk Assessment ─────────────────────────────────────────────

const CC3_CONTROLS: Soc2Control[] = [
  control(
    "CC3.1",
    "CC3",
    "COSO Principle 6 — Risk Assessment Objectives",
    "The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks relating to objectives.",
    ["risk objectives", "compliance objectives", "operational objectives", "risk appetite", "risk tolerance"],
    "risk_assessment",
    [
      "Documented organizational objectives",
      "Risk appetite and tolerance statements",
      "Compliance requirement inventory",
      "Risk assessment methodology documentation",
      "Linkage between objectives and identified risks",
    ],
    false,
    true,
  ),
  control(
    "CC3.2",
    "CC3",
    "COSO Principle 7 — Risk Identification and Analysis",
    "The entity identifies risks to the achievement of its objectives across the entity and analyzes risks as a basis for determining how the risks should be managed.",
    ["risk identification", "risk analysis", "risk register", "threat assessment", "vulnerability", "risk matrix"],
    "risk_assessment",
    [
      "Risk register with identified risks",
      "Risk assessment results and scoring",
      "Threat and vulnerability assessments",
      "Risk heat maps or matrices",
      "Risk treatment plans",
    ],
    true,
    true,
  ),
  control(
    "CC3.3",
    "CC3",
    "COSO Principle 8 — Fraud Risk Assessment",
    "The entity considers the potential for fraud in assessing risks to the achievement of objectives.",
    ["fraud", "fraud risk", "insider threat", "segregation of duties", "anti-fraud", "collusion"],
    "risk_assessment",
    [
      "Fraud risk assessment documentation",
      "Segregation of duties matrix",
      "Anti-fraud program documentation",
      "Insider threat assessment",
      "Fraud risk factors and mitigation strategies",
    ],
    false,
    true,
  ),
  control(
    "CC3.4",
    "CC3",
    "COSO Principle 9 — Change Impact on Internal Controls",
    "The entity identifies and assesses changes that could significantly impact the system of internal control.",
    ["change impact", "change assessment", "significant changes", "business changes", "regulatory changes", "technology changes"],
    "risk_assessment",
    [
      "Change management risk assessment process",
      "Impact analysis for significant changes",
      "Documentation of changes to business, technology, or regulations",
      "Control reassessment following significant changes",
      "Management review of change impacts",
    ],
    false,
    true,
  ),
];

// ─── CC4: Monitoring Activities ───────────────────────────────────────

const CC4_CONTROLS: Soc2Control[] = [
  control(
    "CC4.1",
    "CC4",
    "COSO Principle 16 — Ongoing and Separate Evaluations",
    "The entity selects, develops, and performs ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning.",
    ["monitoring", "evaluation", "internal audit", "self-assessment", "continuous monitoring", "SOC report"],
    "monitoring",
    [
      "Internal audit program and schedule",
      "Continuous monitoring tools and dashboards",
      "Self-assessment results",
      "Penetration testing reports",
      "Compliance scanning results",
    ],
    true,
    true,
  ),
  control(
    "CC4.2",
    "CC4",
    "COSO Principle 17 — Communication of Deficiencies",
    "The entity evaluates and communicates internal control deficiencies in a timely manner to those parties responsible for taking corrective action, including senior management and the board of directors, as appropriate.",
    ["deficiency", "remediation", "corrective action", "exception", "finding", "gap", "audit finding"],
    "monitoring",
    [
      "Deficiency tracking and remediation process",
      "Exception and finding management records",
      "Management reporting on control deficiencies",
      "Corrective action plans with timelines",
      "Board or committee communication on significant deficiencies",
    ],
    true,
    true,
  ),
];

// ─── CC5: Control Activities ──────────────────────────────────────────

const CC5_CONTROLS: Soc2Control[] = [
  control(
    "CC5.1",
    "CC5",
    "COSO Principle 10 — Control Activity Selection and Development",
    "The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels.",
    ["control selection", "control design", "risk mitigation", "preventive controls", "detective controls"],
    "governance",
    [
      "Control catalog with mapping to risks",
      "Control design documentation",
      "Risk-control matrix",
      "Rationale for control selection",
      "Preventive and detective control inventory",
    ],
    false,
    true,
  ),
  control(
    "CC5.2",
    "CC5",
    "COSO Principle 11 — Technology General Controls",
    "The entity also selects and develops general control activities over technology to support the achievement of objectives.",
    ["technology controls", "ITGC", "general controls", "system configuration", "infrastructure", "platform security"],
    "governance",
    [
      "IT general controls (ITGC) documentation",
      "Technology infrastructure security configurations",
      "System hardening standards",
      "Database and platform security controls",
      "Automated control configurations (IaC, SCM)",
    ],
    true,
    true,
  ),
  control(
    "CC5.3",
    "CC5",
    "COSO Principle 12 — Control Deployment Through Policies",
    "The entity deploys control activities through policies that establish what is expected and procedures that put policies into action.",
    ["policy", "procedure", "standard", "guideline", "policy management", "policy review"],
    "governance",
    [
      "Information security policy suite",
      "Policy review and approval records",
      "Procedure documents supporting each policy",
      "Policy distribution and acknowledgment records",
      "Policy exception management process",
    ],
    false,
    true,
  ),
];

// ─── CC6: Logical and Physical Access ─────────────────────────────────

const CC6_CONTROLS: Soc2Control[] = [
  control(
    "CC6.1",
    "CC6",
    "Logical Access — Identity Management and SSO",
    "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events. Includes SSO, identity federation, and centralized identity management.",
    ["identity management", "SSO", "single sign-on", "identity provider", "IdP", "IAM", "directory", "SAML", "OIDC"],
    "identity_and_access",
    [
      "SSO / IdP configuration evidence",
      "Identity management platform setup (Okta, Azure AD, etc.)",
      "IAM policy documentation",
      "User directory and group structure",
      "Identity federation configuration",
    ],
    true,
    true,
  ),
  control(
    "CC6.2",
    "CC6",
    "Logical Access — Authentication Mechanisms",
    "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users. Multi-factor authentication is required for system access.",
    ["MFA", "multi-factor", "authentication", "2FA", "password policy", "credentials", "login"],
    "identity_and_access",
    [
      "MFA enforcement evidence across all systems",
      "Password policy configuration",
      "User registration and provisioning process",
      "Authentication mechanism documentation",
      "Failed login monitoring and lockout configuration",
    ],
    true,
    true,
  ),
  control(
    "CC6.3",
    "CC6",
    "Logical Access — Role-Based Access and Provisioning",
    "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the principle of least privilege.",
    ["RBAC", "role-based access", "least privilege", "provisioning", "deprovisioning", "access request", "access review"],
    "identity_and_access",
    [
      "Role-based access control (RBAC) configuration",
      "Access provisioning and deprovisioning procedures",
      "Least privilege implementation evidence",
      "Periodic access review results",
      "Access request and approval workflow records",
    ],
    true,
    true,
  ),
  control(
    "CC6.4",
    "CC6",
    "Logical Access — Physical Access Restrictions",
    "The entity restricts physical access to facilities and protected information assets to authorized personnel.",
    ["physical access", "data center", "badge", "biometric", "facility", "server room", "visitor"],
    "logical_access",
    [
      "Physical access control system configuration",
      "Facility access logs and badge records",
      "Data center access procedures",
      "Visitor management process",
      "Physical security audit results",
    ],
    false,
    true,
  ),
  control(
    "CC6.5",
    "CC6",
    "Logical Access — Data Disposal and Destruction",
    "The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished and is no longer required.",
    ["data disposal", "data destruction", "decommission", "media sanitization", "end of life", "wipe"],
    "logical_access",
    [
      "Data disposal and destruction policy",
      "Media sanitization records",
      "Certificate of destruction records",
      "Asset decommissioning procedures",
      "Data lifecycle management documentation",
    ],
    false,
    true,
  ),
  control(
    "CC6.6",
    "CC6",
    "Logical Access — External Threat Protection",
    "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software to meet the entity's objectives.",
    ["malware", "antivirus", "endpoint protection", "firewall", "IDS", "IPS", "WAF", "threat detection"],
    "logical_access",
    [
      "Endpoint protection / antimalware deployment evidence",
      "Firewall and network segmentation configurations",
      "Intrusion detection/prevention system (IDS/IPS) configuration",
      "Web application firewall (WAF) configurations",
      "Threat detection and response procedures",
    ],
    true,
    true,
  ),
  control(
    "CC6.7",
    "CC6",
    "Logical Access — Encryption of Data",
    "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives. Encryption at rest and in transit.",
    ["encryption", "TLS", "SSL", "encryption at rest", "encryption in transit", "KMS", "key management", "S3 encryption", "AES"],
    "logical_access",
    [
      "Encryption at rest configuration (all data stores)",
      "Encryption in transit configuration (TLS/SSL)",
      "Key management system (KMS) configuration",
      "Certificate management process",
      "Data classification and handling procedures",
    ],
    true,
    true,
  ),
  control(
    "CC6.8",
    "CC6",
    "Logical Access — Unauthorized Access Prevention",
    "The entity implements controls to prevent or detect and act upon the introduction of unauthorized changes to software or infrastructure components to meet the entity's objectives.",
    ["unauthorized access", "access control list", "network segmentation", "VPC", "security groups", "NACL", "zero trust"],
    "logical_access",
    [
      "Network access control lists (NACLs) and security groups",
      "VPC configuration and network segmentation",
      "Zero trust architecture documentation",
      "Unauthorized access detection mechanisms",
      "Access anomaly detection and alerting",
    ],
    true,
    true,
  ),
];

// ─── CC7: System Operations ──────────────────────────────────────────

const CC7_CONTROLS: Soc2Control[] = [
  control(
    "CC7.1",
    "CC7",
    "System Operations — Vulnerability Detection",
    "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities, and susceptibilities to newly discovered vulnerabilities.",
    ["vulnerability", "scanning", "CVE", "patch management", "vulnerability assessment", "security scanning"],
    "system_operations",
    [
      "Vulnerability scanning tool configuration and schedule",
      "Vulnerability scan results and trending",
      "Patch management policy and evidence",
      "CVE tracking and remediation timelines",
      "Third-party penetration test results",
    ],
    true,
    true,
  ),
  control(
    "CC7.2",
    "CC7",
    "System Operations — Security Event Monitoring",
    "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events.",
    ["monitoring", "SIEM", "CloudTrail", "audit log", "alerting", "anomaly detection", "security events", "log management"],
    "system_operations",
    [
      "SIEM or log management platform configuration",
      "CloudTrail / audit logging configuration",
      "Alert rules and escalation procedures",
      "Security event monitoring dashboards",
      "Log retention and integrity controls",
    ],
    true,
    true,
  ),
  control(
    "CC7.3",
    "CC7",
    "System Operations — Security Incident Evaluation",
    "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures.",
    ["incident evaluation", "triage", "incident classification", "security incident", "event analysis", "SOC"],
    "system_operations",
    [
      "Incident classification and triage procedures",
      "Incident evaluation criteria and decision matrix",
      "Incident records with evaluation outcomes",
      "Security operations center (SOC) procedures",
      "Evidence of incident escalation decisions",
    ],
    false,
    true,
  ),
  control(
    "CC7.4",
    "CC7",
    "System Operations — Incident Response",
    "The entity responds to identified security incidents by executing a defined incident response program to understand, contain, remediate, and communicate security incidents, as appropriate.",
    ["incident response", "IR plan", "containment", "remediation", "post-mortem", "communication plan", "CSIRT"],
    "system_operations",
    [
      "Incident response plan document",
      "Incident response team roles and responsibilities",
      "Incident response playbooks",
      "Incident response drill/exercise records",
      "Post-incident review (post-mortem) records",
    ],
    false,
    true,
  ),
  control(
    "CC7.5",
    "CC7",
    "System Operations — Disaster Recovery and Business Continuity",
    "The entity identifies, develops, and implements activities to recover from identified security incidents. Includes backup, disaster recovery planning, and business continuity.",
    ["disaster recovery", "BCP", "backup", "recovery", "RTO", "RPO", "business continuity", "failover", "restoration"],
    "system_operations",
    [
      "Business continuity plan (BCP) document",
      "Disaster recovery plan (DRP) and test results",
      "Backup configuration and retention evidence",
      "RTO/RPO definitions and validation",
      "DR drill/exercise records and results",
    ],
    true,
    true,
  ),
];

// ─── CC8: Change Management ──────────────────────────────────────────

const CC8_CONTROLS: Soc2Control[] = [
  control(
    "CC8.1",
    "CC8",
    "Change Management — Infrastructure and Software Changes",
    "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.",
    [
      "change management", "change control", "branch protection", "code review",
      "pull request", "CI/CD", "deployment", "release management", "CAB",
      "testing", "approval workflow",
    ],
    "change_management",
    [
      "Change management policy and process documentation",
      "Branch protection rules and code review requirements",
      "CI/CD pipeline configuration with automated testing",
      "Change approval records (pull request approvals)",
      "Deployment logs and rollback procedures",
    ],
    true,
    true,
  ),
];

// ─── CC9: Risk Mitigation ─────────────────────────────────────────────

const CC9_CONTROLS: Soc2Control[] = [
  control(
    "CC9.1",
    "CC9",
    "Risk Mitigation — Risk Mitigation Activities",
    "The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
    ["risk mitigation", "risk treatment", "risk response", "contingency", "insurance", "risk transfer"],
    "risk_mitigation",
    [
      "Risk treatment plans and mitigation strategies",
      "Risk acceptance documentation with rationale",
      "Insurance coverage documentation (cyber, E&O)",
      "Contingency plans for key risk scenarios",
      "Risk mitigation effectiveness reviews",
    ],
    false,
    true,
  ),
  control(
    "CC9.2",
    "CC9",
    "Risk Mitigation — Vendor and Third-Party Risk Management",
    "The entity assesses and manages risks associated with vendors and business partners. Includes vendor due diligence, ongoing monitoring, and contractual safeguards.",
    [
      "vendor management", "third-party risk", "TPRM", "vendor assessment",
      "supply chain", "subprocessor", "vendor due diligence", "SLA",
    ],
    "risk_mitigation",
    [
      "Vendor risk management policy",
      "Vendor risk assessment questionnaires and results",
      "Vendor SOC 2 / ISO 27001 reports on file",
      "Vendor contract review with security requirements",
      "Ongoing vendor monitoring and reassessment evidence",
    ],
    false,
    true,
  ),
];

// ─── Aggregate Registry ──────────────────────────────────────────────

/**
 * Complete SOC 2 Common Criteria control registry.
 * 33 controls across 9 categories (CC1–CC9).
 */
export const SOC2_CONTROL_REGISTRY: ReadonlyArray<Soc2Control> = Object.freeze([
  ...CC1_CONTROLS,
  ...CC2_CONTROLS,
  ...CC3_CONTROLS,
  ...CC4_CONTROLS,
  ...CC5_CONTROLS,
  ...CC6_CONTROLS,
  ...CC7_CONTROLS,
  ...CC8_CONTROLS,
  ...CC9_CONTROLS,
]);

// ─── Lookup Helpers ──────────────────────────────────────────────────

const _byId = new Map<string, Soc2Control>();
const _byCategory = new Map<Soc2Category, Soc2Control[]>();

for (const ctrl of SOC2_CONTROL_REGISTRY) {
  _byId.set(ctrl.number, ctrl);
  const list = _byCategory.get(ctrl.category) ?? [];
  list.push(ctrl);
  _byCategory.set(ctrl.category, list);
}

/** Retrieve a control by its number (e.g. "CC6.1"). Returns undefined if not found. */
export function getControlById(id: string): Soc2Control | undefined {
  return _byId.get(id);
}

/** Retrieve all controls in a given category (e.g. "CC6"). */
export function getControlsByCategory(category: Soc2Category): ReadonlyArray<Soc2Control> {
  return _byCategory.get(category) ?? [];
}

/** Return every category with its human-readable name. */
export function getCategoryNames(): ReadonlyArray<{ category: Soc2Category; name: string }> {
  return [
    { category: "CC1", name: "Control Environment" },
    { category: "CC2", name: "Communication and Information" },
    { category: "CC3", name: "Risk Assessment" },
    { category: "CC4", name: "Monitoring Activities" },
    { category: "CC5", name: "Control Activities" },
    { category: "CC6", name: "Logical and Physical Access" },
    { category: "CC7", name: "System Operations" },
    { category: "CC8", name: "Change Management" },
    { category: "CC9", name: "Risk Mitigation" },
  ];
}

/** Search controls by keyword (case-insensitive, matches against keywords array). */
export function searchControlsByKeyword(keyword: string): Soc2Control[] {
  const lower = keyword.toLowerCase();
  return SOC2_CONTROL_REGISTRY.filter((c) =>
    c.keywords.some((k) => k.toLowerCase().includes(lower)),
  );
}

/** Total number of controls in the registry. */
export const CONTROL_COUNT = SOC2_CONTROL_REGISTRY.length;
