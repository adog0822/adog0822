/**
 * LoxeAI Onboarding Question Bank
 *
 * The complete question set for SOC 2 onboarding, organized by section.
 * Designed around the simplicity pillar: easy, quick, painless, intuitive.
 */

import type { OnboardingQuestion, OnboardingSection } from "../types/index";

// ─── Section 1: Company Basics ────────────────────────────────────────

const companyBasics: OnboardingQuestion[] = [
  {
    id: "company_name",
    section: "company_basics",
    order: 1,
    question: "What's your company name?",
    description: "We'll use this across your compliance workspace.",
    type: "text",
    placeholder: "Acme Inc.",
    required: true,
  },
  {
    id: "employee_count",
    section: "company_basics",
    order: 2,
    question: "How many employees?",
    description: "This helps Gideon scope the right controls for your team size.",
    type: "single-select",
    options: [
      { value: "1-10", label: "1–10" },
      { value: "11-50", label: "11–50" },
      { value: "51-200", label: "51–200" },
      { value: "201-500", label: "201–500" },
      { value: "500+", label: "500+" },
    ],
    required: true,
  },
  {
    id: "industry",
    section: "company_basics",
    order: 3,
    question: "What industry are you in?",
    description: "We'll tailor policies and controls to your sector.",
    type: "dropdown",
    options: [
      { value: "saas", label: "SaaS" },
      { value: "fintech", label: "Fintech" },
      { value: "healthcare", label: "Healthcare" },
      { value: "ecommerce", label: "E-commerce" },
      { value: "ai_ml", label: "AI/ML" },
      { value: "other", label: "Other" },
    ],
    required: true,
  },
  {
    id: "primary_motivation",
    section: "company_basics",
    order: 4,
    question: "What's your primary motivation?",
    description: "Knowing your “why” helps us prioritize the right milestones.",
    type: "single-select",
    options: [
      { value: "enterprise_sales", label: "Enterprise sales", description: "Prospects are asking for SOC 2" },
      { value: "investor_requirement", label: "Investor requirement", description: "Due diligence needs it" },
      { value: "customer_trust", label: "Customer trust", description: "Build confidence with existing customers" },
      { value: "regulatory", label: "Regulatory", description: "Legal or contractual obligation" },
    ],
    required: true,
  },
  {
    id: "target_timeline",
    section: "company_basics",
    order: 5,
    question: "Target timeline?",
    description: "Gideon will build a schedule that matches your pace.",
    type: "single-select",
    options: [
      { value: "30_days", label: "30 days", description: "Aggressive — we'll fast-track everything" },
      { value: "60_days", label: "60 days", description: "Ambitious but comfortable" },
      { value: "90_days", label: "90 days", description: "Standard pace with room to breathe" },
      { value: "6_months_plus", label: "6+ months", description: "No rush — methodical approach" },
    ],
    required: true,
  },
];

// ─── Section 2: Data & Scope ──────────────────────────────────────────

const dataAndScope: OnboardingQuestion[] = [
  {
    id: "sensitive_data_types",
    section: "data_and_scope",
    order: 1,
    question: "What types of sensitive data do you handle?",
    description: "This determines which controls and policies apply to you.",
    type: "multi-select",
    options: [
      { value: "pii", label: "PII", description: "Names, emails, addresses, SSNs" },
      { value: "phi", label: "PHI", description: "Protected health information" },
      { value: "financial", label: "Financial", description: "Bank accounts, transactions" },
      { value: "ip", label: "Intellectual Property", description: "Trade secrets, proprietary code" },
      { value: "payment_pci", label: "Payment / PCI", description: "Credit cards, payment data" },
      { value: "none", label: "None specifically", description: "No classified sensitive data" },
    ],
    required: true,
  },
  {
    id: "data_residency",
    section: "data_and_scope",
    order: 2,
    question: "Where do you store/process this data?",
    description: "Data residency affects your compliance requirements.",
    type: "multi-select",
    options: [
      { value: "us_only", label: "US only" },
      { value: "eu", label: "EU" },
      { value: "global", label: "Global" },
      { value: "on_premises", label: "On-premises" },
    ],
    required: true,
  },
  {
    id: "product_scope",
    section: "data_and_scope",
    order: 3,
    question: "Do you have multiple products or business units?",
    description: "We can scope your audit to just what matters.",
    type: "single-select",
    options: [
      { value: "single_product", label: "Single product", description: "One core product or service" },
      { value: "multiple_products", label: "Multiple products", description: "Several distinct products" },
      { value: "multiple_business_units", label: "Multiple business units", description: "Separate teams or divisions" },
    ],
    required: true,
  },
];

// ─── Section 3: Infrastructure ────────────────────────────────────────

const infrastructure: OnboardingQuestion[] = [
  {
    id: "cloud_providers",
    section: "infrastructure",
    order: 1,
    question: "Where is your production environment hosted?",
    description: "Select all that apply — Gideon can start scanning immediately.",
    type: "multi-select",
    options: [
      {
        value: "aws",
        label: "AWS",
        icon: "☁️",
        triggersAgent: { type: "cloud_scan", integrationKey: "aws", requiresSetup: true },
      },
      {
        value: "gcp",
        label: "Google Cloud",
        icon: "☁️",
        triggersAgent: { type: "cloud_scan", integrationKey: "gcp", requiresSetup: true },
      },
      {
        value: "azure",
        label: "Microsoft Azure",
        icon: "☁️",
        triggersAgent: { type: "cloud_scan", integrationKey: "azure", requiresSetup: true },
      },
      {
        value: "on_premises",
        label: "On-Premises",
        icon: "🏢",
      },
      {
        value: "vercel",
        label: "Vercel",
        icon: "▲",
        triggersAgent: { type: "cloud_scan", integrationKey: "vercel" },
      },
      {
        value: "heroku",
        label: "Heroku",
        icon: "🟪",
        triggersAgent: { type: "cloud_scan", integrationKey: "heroku" },
      },
      {
        value: "other",
        label: "Other",
        icon: "…",
      },
    ],
    required: true,
  },
  {
    id: "databases",
    section: "infrastructure",
    order: 2,
    question: "What databases do you use?",
    description: "Helps us check encryption-at-rest and backup controls.",
    type: "multi-select",
    options: [
      { value: "postgresql", label: "PostgreSQL" },
      { value: "mysql", label: "MySQL" },
      { value: "mongodb", label: "MongoDB" },
      { value: "dynamodb", label: "DynamoDB" },
      { value: "redis", label: "Redis" },
      { value: "other", label: "Other" },
    ],
    required: true,
  },
  {
    id: "iac_tools",
    section: "infrastructure",
    order: 3,
    question: "How do you manage infrastructure?",
    description: "Infrastructure-as-code is a strong signal for auditors.",
    type: "multi-select",
    options: [
      { value: "terraform", label: "Terraform" },
      { value: "cloudformation", label: "CloudFormation" },
      { value: "pulumi", label: "Pulumi" },
      { value: "manual", label: "Manual" },
      { value: "other", label: "Other" },
    ],
    required: true,
  },
];

// ─── Section 4: Integrations ──────────────────────────────────────────

const integrations: OnboardingQuestion[] = [
  {
    id: "identity_provider",
    section: "integrations",
    order: 1,
    question: "What's your identity provider?",
    description: "SSO and MFA are core SOC 2 requirements.",
    type: "multi-select",
    options: [
      {
        value: "okta",
        label: "Okta",
        icon: "🔐",
        triggersAgent: { type: "integration_connect", integrationKey: "okta" },
      },
      {
        value: "google_workspace",
        label: "Google Workspace",
        icon: "🔐",
        triggersAgent: { type: "integration_connect", integrationKey: "google_workspace" },
      },
      {
        value: "microsoft_entra",
        label: "Microsoft Entra ID",
        icon: "🔐",
        triggersAgent: { type: "integration_connect", integrationKey: "microsoft_entra" },
      },
      {
        value: "auth0",
        label: "Auth0",
        icon: "🔐",
        triggersAgent: { type: "integration_connect", integrationKey: "auth0" },
      },
      {
        value: "none",
        label: "None",
        icon: "❌",
      },
    ],
    required: true,
  },
  {
    id: "code_repositories",
    section: "integrations",
    order: 2,
    question: "What code repositories do you use?",
    description: "We'll verify branch protection and access controls.",
    type: "multi-select",
    options: [
      {
        value: "github",
        label: "GitHub",
        triggersAgent: { type: "integration_connect", integrationKey: "github" },
      },
      {
        value: "gitlab",
        label: "GitLab",
        triggersAgent: { type: "integration_connect", integrationKey: "gitlab" },
      },
      {
        value: "bitbucket",
        label: "Bitbucket",
        triggersAgent: { type: "integration_connect", integrationKey: "bitbucket" },
      },
    ],
    required: true,
  },
  {
    id: "project_management",
    section: "integrations",
    order: 3,
    question: "What project management tools?",
    description: "Change management evidence can come straight from here.",
    type: "multi-select",
    options: [
      { value: "jira", label: "Jira" },
      { value: "linear", label: "Linear" },
      { value: "asana", label: "Asana" },
      { value: "notion", label: "Notion" },
      { value: "other", label: "Other" },
    ],
    required: true,
  },
  {
    id: "hr_platform",
    section: "integrations",
    order: 4,
    question: "What HR/People platform?",
    description: "Automates onboarding/offboarding evidence collection.",
    type: "multi-select",
    options: [
      { value: "rippling", label: "Rippling" },
      { value: "gusto", label: "Gusto" },
      { value: "bamboohr", label: "BambooHR" },
      { value: "deel", label: "Deel" },
      { value: "adp", label: "ADP" },
      { value: "none", label: "None" },
    ],
    required: true,
  },
  {
    id: "device_compliance",
    section: "integrations",
    order: 5,
    question: "How do you manage device compliance?",
    description: "MDM is a key control for endpoint security.",
    type: "multi-select",
    options: [
      { value: "jamf", label: "Jamf" },
      { value: "kandji", label: "Kandji" },
      { value: "intune", label: "Intune" },
      { value: "none", label: "None" },
    ],
    required: true,
  },
  {
    id: "other_integrations",
    section: "integrations",
    order: 6,
    question: "Any other integrations?",
    description: "Select anything else your team uses day-to-day.",
    type: "multi-select",
    options: [
      { value: "cloudflare", label: "Cloudflare" },
      { value: "datadog", label: "Datadog" },
      { value: "pagerduty", label: "PagerDuty" },
      { value: "slack", label: "Slack" },
      { value: "other", label: "Other" },
    ],
    required: false,
  },
];

// ─── Section 5: Team & Ownership ──────────────────────────────────────

const teamAndOwnership: OnboardingQuestion[] = [
  {
    id: "compliance_officer",
    section: "team_and_ownership",
    order: 1,
    question: "Who is the primary Compliance Officer/Admin?",
    description: "They'll be the main point of contact for audit readiness.",
    type: "text",
    placeholder: "Jane Smith — jane@company.com",
    required: true,
  },
  {
    id: "infra_security_owner",
    section: "team_and_ownership",
    order: 2,
    question: "Who owns infrastructure security?",
    description: "Responsible for cloud configs, network security, and monitoring.",
    type: "text",
    placeholder: "John Doe — john@company.com",
    required: true,
  },
  {
    id: "hr_operations_owner",
    section: "team_and_ownership",
    order: 3,
    question: "Who owns HR and personnel operations?",
    description: "Handles background checks, onboarding, and security training.",
    type: "text",
    placeholder: "Alex Chen — alex@company.com",
    required: true,
  },
];

// ─── Section 6: Compliance Goals ──────────────────────────────────────

const complianceGoals: OnboardingQuestion[] = [
  {
    id: "compliance_status",
    section: "compliance_goals",
    order: 1,
    question: "Have you started any compliance work?",
    description: "No wrong answer — we meet you wherever you are.",
    type: "single-select",
    options: [
      { value: "starting_fresh", label: "Starting fresh", description: "Brand new to compliance" },
      { value: "some_policies", label: "Some policies exist", description: "A few docs, but nothing formal" },
      { value: "partially_compliant", label: "Partially compliant", description: "Some controls in place" },
      { value: "recertifying", label: "Re-certifying", description: "Renewing an existing SOC 2" },
    ],
    required: true,
  },
  {
    id: "biggest_concerns",
    section: "compliance_goals",
    order: 2,
    question: "What's your biggest concern?",
    description: "We'll tackle these head-on in your compliance plan.",
    type: "multi-select",
    options: [
      { value: "time", label: "Time", description: "We need this done fast" },
      { value: "cost", label: "Cost", description: "Budget is tight" },
      { value: "complexity", label: "Complexity", description: "SOC 2 feels overwhelming" },
      { value: "auditor_selection", label: "Auditor selection", description: "Not sure who to pick" },
      { value: "technical_gaps", label: "Technical gaps", description: "Know we have holes to fill" },
    ],
    required: true,
  },
  {
    id: "third_party_vendors",
    section: "compliance_goals",
    order: 3,
    question: "Do you have any third-party vendors that access your data?",
    description: "Vendor management is a key SOC 2 control area.",
    type: "single-select",
    options: [
      { value: "none", label: "None" },
      { value: "1-5", label: "1–5 vendors" },
      { value: "6-20", label: "6–20 vendors" },
      { value: "20+", label: "20+ vendors" },
    ],
    required: true,
  },
];

// ─── Section Ordering ─────────────────────────────────────────────────

/** Ordered list of onboarding sections as the user progresses through them. */
export const SECTION_ORDER: readonly OnboardingSection[] = [
  "company_basics",
  "data_and_scope",
  "infrastructure",
  "integrations",
  "team_and_ownership",
  "compliance_goals",
] as const;

/** Human-readable section titles for display. */
export const SECTION_TITLES: Record<OnboardingSection, string> = {
  company_basics: "Company Basics",
  data_and_scope: "Data & Scope",
  infrastructure: "Infrastructure",
  integrations: "Integrations",
  team_and_ownership: "Team & Ownership",
  compliance_goals: "Compliance Goals",
};

// ─── Aggregated Question Bank ─────────────────────────────────────────

/** All onboarding questions grouped by section, ordered for sequential flow. */
export const QUESTION_BANK: Record<OnboardingSection, OnboardingQuestion[]> = {
  company_basics: companyBasics,
  data_and_scope: dataAndScope,
  infrastructure,
  integrations,
  team_and_ownership: teamAndOwnership,
  compliance_goals: complianceGoals,
};

/** Flat array of every question, useful for lookups and validation. */
export const ALL_QUESTIONS: OnboardingQuestion[] = SECTION_ORDER.flatMap(
  (section) => QUESTION_BANK[section]
);

/**
 * Look up a question by its ID.
 * Returns undefined if the ID is not found.
 */
export function getQuestionById(id: string): OnboardingQuestion | undefined {
  return ALL_QUESTIONS.find((q) => q.id === id);
}

/**
 * Get all questions for a given section, sorted by order.
 */
export function getQuestionsForSection(section: OnboardingSection): OnboardingQuestion[] {
  return QUESTION_BANK[section].slice().sort((a, b) => a.order - b.order);
}
