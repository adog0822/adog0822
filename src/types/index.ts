/**
 * LoxeAI GRC Platform — Core Type Definitions
 *
 * Three pillars: Simplicity · Verifiability · Customization
 */

// ─── Identity & Workspace ──────────────────────────────────────────────

export type WorkspaceId = string & { readonly __brand: "WorkspaceId" };
export type UserId = string & { readonly __brand: "UserId" };
export type EvidenceId = string & { readonly __brand: "EvidenceId" };
export type ControlId = string & { readonly __brand: "ControlId" };
export type IntentId = string & { readonly __brand: "IntentId" };

export type UserRole = "owner" | "admin" | "member" | "auditor" | "guest";

export interface User {
  id: UserId;
  email: string;
  name: string;
  role: UserRole;
  workspaceIds: WorkspaceId[];
  createdAt: string;
}

export interface Workspace {
  id: WorkspaceId;
  name: string;
  plan: "starter" | "growth" | "enterprise";
  settings: WorkspaceSettings;
  createdAt: string;
}

export interface WorkspaceSettings {
  theme: ThemeConfig;
  ibacParameters: Record<string, IbacParameter>;
  customFields: CustomFieldDefinition[];
  integrations: IntegrationConfig[];
}

export interface ThemeConfig {
  primaryColor: string;
  accentColor: string;
  mode: "light" | "dark" | "system";
  logoUrl?: string;
}

export interface CustomFieldDefinition {
  key: string;
  label: string;
  type: "text" | "number" | "boolean" | "select" | "multi-select" | "date";
  options?: string[];
  required: boolean;
}

// ─── Onboarding ────────────────────────────────────────────────────────

export type QuestionType = "single-select" | "multi-select" | "dropdown" | "text" | "number";

export interface OnboardingQuestion {
  id: string;
  section: OnboardingSection;
  order: number;
  question: string;
  description?: string;
  type: QuestionType;
  options?: OnboardingOption[];
  placeholder?: string;
  required: boolean;
  triggersAgent?: AgentTrigger;
  dependsOn?: { questionId: string; value: string | string[] };
}

export interface OnboardingOption {
  value: string;
  label: string;
  icon?: string;
  description?: string;
  triggersAgent?: AgentTrigger;
}

export type OnboardingSection =
  | "company_basics"
  | "data_and_scope"
  | "infrastructure"
  | "integrations"
  | "team_and_ownership"
  | "compliance_goals";

export interface AgentTrigger {
  type: "cloud_scan" | "integration_connect" | "policy_generate" | "evidence_collect";
  integrationKey: string;
  requiresSetup?: boolean;
}

export interface OnboardingResponse {
  questionId: string;
  value: string | string[] | number;
  answeredAt: string;
  agentTriggered?: boolean;
}

export interface OnboardingSession {
  workspaceId: WorkspaceId;
  responses: OnboardingResponse[];
  currentSection: OnboardingSection;
  completedSections: OnboardingSection[];
  backgroundAgents: BackgroundAgentStatus[];
  startedAt: string;
  completedAt?: string;
}

export interface BackgroundAgentStatus {
  id: string;
  type: AgentTrigger["type"];
  integration: string;
  status: "pending" | "running" | "completed" | "failed";
  progress: number;
  evidenceCount: number;
  startedAt: string;
  completedAt?: string;
  error?: string;
}

// ─── IBAC (Intent-Based Access Control) ────────────────────────────────

export type IbacAction =
  | "read"
  | "create"
  | "modify"
  | "delete"
  | "execute"
  | "export"
  | "share"
  | "approve"
  | "escalate";

export type IbacResource =
  | "policy"
  | "evidence"
  | "control"
  | "integration"
  | "workspace"
  | "user"
  | "vendor"
  | "report"
  | "custom_field"
  | "firewall_template"
  | "access_review";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface IntentObject {
  id: IntentId;
  action: IbacAction;
  resource: IbacResource;
  resourceId?: string;
  context: IntentContext;
  riskLevel: RiskLevel;
  rawPrompt: string;
  parsedAt: string;
}

export interface IntentContext {
  workspaceId: WorkspaceId;
  userId: UserId;
  environment?: string;
  targetEntities?: string[];
  reasoning: string;
  metadata: Record<string, unknown>;
}

export type IbacDecision = "allow" | "deny" | "escalate" | "step_up_auth";

export interface IbacEvaluation {
  intentId: IntentId;
  decision: IbacDecision;
  matchedControls: MatchedControl[];
  evaluatedAt: string;
  evidenceHash: string;
  escalationRequired?: EscalationRequest;
}

export interface MatchedControl {
  controlTemplateId: string;
  controlName: string;
  parameters: Record<string, unknown>;
  result: "pass" | "fail" | "requires_approval";
  reason: string;
}

export interface EscalationRequest {
  approverId: UserId;
  reason: string;
  expiresAt: string;
  approved?: boolean;
  approvedAt?: string;
}

export interface IbacParameter {
  key: string;
  label: string;
  type: "boolean" | "number" | "string" | "string[]";
  value: unknown;
  description: string;
  controlTemplateId: string;
}

export interface IbacControlTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  defaultParameters: Record<string, unknown>;
  evaluationLogic: string;
  riskThreshold: RiskLevel;
  requiresApproval: boolean;
  enabled: boolean;
}

// ─── Cryptographic Evidence Pipeline ───────────────────────────────────

export interface EvidenceItem {
  id: EvidenceId;
  workspaceId: WorkspaceId;
  controlId: ControlId;
  controlTitle: string;
  service: IntegrationService;
  resourceName: string;
  status: EvidenceStatus;
  score: number;
  findings: Finding[];
  sourceTrace: SourceEvidenceTrace;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  blacklisted: boolean;
  deleted: boolean;
}

export type EvidenceStatus = "pass" | "warn" | "fail" | "info" | "not_applicable";
export type IntegrationService = "aws" | "gcp" | "azure" | "github" | "okta" | "cloudflare" | "jira" | "rippling" | "custom";

export interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  remediation: string;
  auditorQuestion: string;
}

export interface SourceEvidenceTrace {
  apiCalls: ApiCallRecord[];
  chainHash: string;
  previousHash: string;
  timestamp: string;
  collectorVersion: string;
}

export interface ApiCallRecord {
  service: string;
  operation: string;
  region: string;
  accountId: string;
  timestamp: string;
  parameters: Record<string, unknown>;
  requestId: string;
  statusCode: number;
  responseSha256: string;
  rateLimitRemaining?: string;
}

export interface EvidenceHash {
  evidenceId: EvidenceId;
  contentHash: string;
  previousHash: string;
  timestamp: string;
  algorithm: "SHA-256";
  chainPosition: number;
}

// ─── SOC 2 Controls ────────────────────────────────────────────────────

export type Soc2Category = "CC1" | "CC2" | "CC3" | "CC4" | "CC5" | "CC6" | "CC7" | "CC8" | "CC9";

export interface Soc2Control {
  id: ControlId;
  category: Soc2Category;
  number: string;
  title: string;
  description: string;
  keywords: string[];
  riskDomain: RiskDomain;
  evidenceRequirements: string[];
  automatable: boolean;
  customizable: boolean;
}

export type RiskDomain =
  | "governance"
  | "communication"
  | "risk_assessment"
  | "monitoring"
  | "logical_access"
  | "identity_and_access"
  | "system_operations"
  | "change_management"
  | "risk_mitigation";

export interface ControlScore {
  controlId: ControlId;
  workspaceId: WorkspaceId;
  score: number;
  status: EvidenceStatus;
  evidenceCount: number;
  lastEvaluated: string;
  findings: Finding[];
}

// ─── Integrations ──────────────────────────────────────────────────────

export interface IntegrationConfig {
  key: string;
  service: IntegrationService;
  name: string;
  icon: string;
  status: "connected" | "pending" | "disconnected" | "error";
  credentials?: IntegrationCredentials;
  lastSyncAt?: string;
  evidenceCount: number;
}

export interface IntegrationCredentials {
  type: "role_arn" | "oauth" | "api_key" | "service_account";
  externalId?: string;
  roleArn?: string;
  accessToken?: string;
  refreshToken?: string;
  expiresAt?: string;
}

export interface AwsSetupConfig {
  externalId: string;
  roleName: string;
  templateUrl: string;
  templateYaml: string;
  readOnlyPolicies: string[];
}

// ─── Auditor ───────────────────────────────────────────────────────────

export interface AuditorSession {
  auditorId: UserId;
  workspaceId: WorkspaceId;
  auditPeriodStart: string;
  auditPeriodEnd: string;
  scope: AuditScope;
  status: "active" | "completed" | "expired";
  createdAt: string;
  expiresAt: string;
}

export interface AuditScope {
  frameworks: string[];
  systems: string[];
  controlIds: ControlId[];
}

export interface AuditorGrade {
  controlId: ControlId;
  grade: "effective" | "effective_with_exceptions" | "ineffective";
  reasoning: string;
  auditorId: UserId;
  gradedAt: string;
}

export interface AuditorMessage {
  id: string;
  threadId: string;
  fromId: UserId;
  fromRole: "auditor" | "user";
  content: string;
  attachments?: string[];
  createdAt: string;
}

// ─── Gideon Co-Pilot ───────────────────────────────────────────────────

export interface GideonQuery {
  selectedText: string;
  pageContext: string;
  userId: UserId;
  workspaceId: WorkspaceId;
}

export interface GideonResponse {
  plainEnglish: string;
  engineerPerspective: string;
  auditorPerspective: string;
  relatedControls: ControlId[];
  suggestedActions: string[];
}

// ─── Remediation ───────────────────────────────────────────────────────

export interface RemediationItem {
  id: string;
  evidenceId: EvidenceId;
  controlId: ControlId;
  title: string;
  description: string;
  priority: "critical" | "high" | "medium" | "low";
  status: "open" | "in_progress" | "resolved" | "accepted_risk";
  assigneeId?: UserId;
  dueDate?: string;
  createdAt: string;
  resolvedAt?: string;
}
