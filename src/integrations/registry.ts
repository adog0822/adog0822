// =============================================================================
// LoxeAI — Integration Registry
// Defines all supported integrations with metadata, scans, and setup instructions
// =============================================================================

import type { IntegrationDefinition } from '../types/index';

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

export const INTEGRATION_REGISTRY: IntegrationDefinition[] = [
  // -------------------------------------------------------------------------
  // Cloud Infrastructure
  // -------------------------------------------------------------------------
  {
    key: 'aws',
    name: 'Amazon Web Services',
    icon: '☁️',
    serviceType: 'cloud_infrastructure',
    description: 'Scan AWS accounts for IAM, encryption, logging, network, and backup compliance.',
    credentialType: 'aws',
    scans: [
      {
        key: 'iam-users',
        name: 'IAM Users & MFA',
        description: 'List IAM users, check MFA enrollment, password policies, and access key age.',
        controls: ['CC6.1', 'CC6.2', 'CC6.3'],
        estimatedDurationSeconds: 30,
      },
      {
        key: 'iam-policies',
        name: 'IAM Policies',
        description: 'Check for overly permissive policies and admin access.',
        controls: ['CC6.1', 'CC5.2'],
        estimatedDurationSeconds: 20,
      },
      {
        key: 'cloudtrail',
        name: 'CloudTrail',
        description: 'Verify CloudTrail is enabled, multi-region, with log file validation.',
        controls: ['CC7.2', 'CC4.1'],
        estimatedDurationSeconds: 10,
      },
      {
        key: 's3-buckets',
        name: 'S3 Bucket Security',
        description: 'Check encryption, public access blocks, versioning, and access logging.',
        controls: ['CC6.7', 'CC6.1'],
        estimatedDurationSeconds: 45,
      },
      {
        key: 'vpc-config',
        name: 'VPC Configuration',
        description: 'Check security groups, NACLs, and VPC flow logs.',
        controls: ['CC6.6', 'CC6.1'],
        estimatedDurationSeconds: 25,
      },
      {
        key: 'rds-instances',
        name: 'RDS Instances',
        description: 'Check encryption at rest, backup retention, public access, and Multi-AZ.',
        controls: ['CC6.7', 'CC7.5'],
        estimatedDurationSeconds: 15,
      },
      {
        key: 'kms-keys',
        name: 'KMS Key Management',
        description: 'Verify key rotation status and usage policies.',
        controls: ['CC6.7'],
        estimatedDurationSeconds: 15,
      },
      {
        key: 'guardduty',
        name: 'GuardDuty',
        description: 'Verify threat detection service is enabled.',
        controls: ['CC7.1'],
        estimatedDurationSeconds: 5,
      },
      {
        key: 'aws-config',
        name: 'AWS Config',
        description: 'Check configuration recording and delivery channel setup.',
        controls: ['CC4.1', 'CC7.2'],
        estimatedDurationSeconds: 10,
      },
      {
        key: 'backups',
        name: 'AWS Backup',
        description: 'Review backup plans, retention policies, and vault encryption.',
        controls: ['CC7.5'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC4.1', 'CC5.2', 'CC6.1', 'CC6.2', 'CC6.3', 'CC6.6', 'CC6.7', 'CC7.1', 'CC7.2', 'CC7.5'],
    setupInstructions: `## AWS Integration Setup

### Prerequisites
- An AWS account with organizational access
- Permission to create IAM roles

### Steps

1. **Create a cross-account IAM role** in each AWS account you want to scan:
   \`\`\`json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "AWS": "arn:aws:iam::LOXEAI_ACCOUNT:root" },
       "Action": "sts:AssumeRole",
       "Condition": {
         "StringEquals": { "sts:ExternalId": "YOUR_EXTERNAL_ID" }
       }
     }]
   }
   \`\`\`

2. **Attach the SecurityAudit managed policy** to the role for read-only access.

3. **Enter the Role ARN and External ID** in LoxeAI.

### Permissions Required
- \`SecurityAudit\` (AWS managed policy) — provides read-only access to security configurations
- No write permissions are needed`,
  },

  {
    key: 'gcp',
    name: 'Google Cloud Platform',
    icon: '🌐',
    serviceType: 'cloud_infrastructure',
    description: 'Scan GCP projects for IAM, compute, storage, and logging compliance.',
    credentialType: 'oauth',
    scans: [
      {
        key: 'gcp-iam',
        name: 'IAM & Service Accounts',
        description: 'Check IAM bindings, service account keys, and organization policies.',
        controls: ['CC6.1', 'CC6.2', 'CC6.3'],
        estimatedDurationSeconds: 30,
      },
      {
        key: 'gcp-logging',
        name: 'Cloud Logging & Monitoring',
        description: 'Verify audit logging, log sinks, and alerting policies.',
        controls: ['CC7.2', 'CC4.1'],
        estimatedDurationSeconds: 20,
      },
      {
        key: 'gcp-storage',
        name: 'Cloud Storage',
        description: 'Check bucket encryption, access controls, and retention policies.',
        controls: ['CC6.7', 'CC6.1'],
        estimatedDurationSeconds: 25,
      },
      {
        key: 'gcp-compute',
        name: 'Compute & Networking',
        description: 'Check firewall rules, VPC configuration, and instance settings.',
        controls: ['CC6.6', 'CC6.1'],
        estimatedDurationSeconds: 25,
      },
      {
        key: 'gcp-sql',
        name: 'Cloud SQL',
        description: 'Check database encryption, backup configuration, and network access.',
        controls: ['CC6.7', 'CC7.5'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC4.1', 'CC6.1', 'CC6.2', 'CC6.3', 'CC6.6', 'CC6.7', 'CC7.2', 'CC7.5'],
    setupInstructions: `## GCP Integration Setup

### Steps
1. Create a service account with **Viewer** and **Security Reviewer** roles.
2. Generate a JSON key for the service account.
3. Upload the key file in LoxeAI.`,
  },

  {
    key: 'azure',
    name: 'Microsoft Azure',
    icon: '🔷',
    serviceType: 'cloud_infrastructure',
    description: 'Scan Azure subscriptions for identity, networking, storage, and monitoring compliance.',
    credentialType: 'oauth',
    scans: [
      {
        key: 'azure-ad',
        name: 'Entra ID (Azure AD)',
        description: 'Check conditional access policies, MFA enforcement, and user management.',
        controls: ['CC6.1', 'CC6.2', 'CC6.3'],
        estimatedDurationSeconds: 30,
      },
      {
        key: 'azure-networking',
        name: 'Networking & NSGs',
        description: 'Check network security groups, virtual networks, and Azure Firewall.',
        controls: ['CC6.6', 'CC6.1'],
        estimatedDurationSeconds: 25,
      },
      {
        key: 'azure-storage',
        name: 'Storage Accounts',
        description: 'Check encryption, access policies, and network rules.',
        controls: ['CC6.7', 'CC6.1'],
        estimatedDurationSeconds: 20,
      },
      {
        key: 'azure-monitor',
        name: 'Azure Monitor & Defender',
        description: 'Check activity logs, diagnostic settings, and Defender for Cloud.',
        controls: ['CC7.1', 'CC7.2', 'CC4.1'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC4.1', 'CC6.1', 'CC6.2', 'CC6.3', 'CC6.6', 'CC6.7', 'CC7.1', 'CC7.2'],
    setupInstructions: `## Azure Integration Setup

### Steps
1. Register an application in Microsoft Entra ID.
2. Grant the **Reader** and **Security Reader** roles at the subscription level.
3. Enter the Tenant ID, Client ID, and Client Secret in LoxeAI.`,
  },

  // -------------------------------------------------------------------------
  // Source Control
  // -------------------------------------------------------------------------
  {
    key: 'github',
    name: 'GitHub',
    icon: '🐙',
    serviceType: 'source_control',
    description: 'Scan GitHub organizations for branch protection, access controls, and security features.',
    credentialType: 'github',
    scans: [
      {
        key: 'org-settings',
        name: 'Organization Settings',
        description: 'Check 2FA requirement and default repository permissions.',
        controls: ['CC6.2'],
        estimatedDurationSeconds: 5,
      },
      {
        key: 'repo-protection',
        name: 'Branch Protection',
        description: 'Check branch protection rules, required reviews, and status checks.',
        controls: ['CC8.1'],
        estimatedDurationSeconds: 30,
      },
      {
        key: 'access-permissions',
        name: 'Access Permissions',
        description: 'Review team structure, user access, and outside collaborators.',
        controls: ['CC6.3'],
        estimatedDurationSeconds: 15,
      },
      {
        key: 'audit-log',
        name: 'Audit Log',
        description: 'Check audit log availability and retention.',
        controls: ['CC7.2', 'CC4.1'],
        estimatedDurationSeconds: 10,
      },
      {
        key: 'secrets-scanning',
        name: 'Security Scanning',
        description: 'Check secret scanning, push protection, and Dependabot alerts.',
        controls: ['CC7.1'],
        estimatedDurationSeconds: 30,
      },
    ],
    controlsCovered: ['CC4.1', 'CC6.2', 'CC6.3', 'CC7.1', 'CC7.2', 'CC8.1'],
    setupInstructions: `## GitHub Integration Setup

### Steps
1. Install the LoxeAI GitHub App on your organization.
2. Grant access to all repositories (or select specific ones).
3. The app requires read-only access to: organization settings, repositories, teams, audit log, secret scanning alerts, and Dependabot alerts.`,
  },

  {
    key: 'gitlab',
    name: 'GitLab',
    icon: '🦊',
    serviceType: 'source_control',
    description: 'Scan GitLab groups for merge request policies, access controls, and security features.',
    credentialType: 'oauth',
    scans: [
      {
        key: 'gitlab-group-settings',
        name: 'Group Settings',
        description: 'Check 2FA enforcement and group-level settings.',
        controls: ['CC6.2'],
        estimatedDurationSeconds: 5,
      },
      {
        key: 'gitlab-merge-policies',
        name: 'Merge Request Policies',
        description: 'Check protected branches and merge request approval rules.',
        controls: ['CC8.1'],
        estimatedDurationSeconds: 30,
      },
      {
        key: 'gitlab-access',
        name: 'Access Management',
        description: 'Review group membership, roles, and access levels.',
        controls: ['CC6.3'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC6.2', 'CC6.3', 'CC8.1'],
    setupInstructions: `## GitLab Integration Setup

### Steps
1. Create a Group Access Token with **Reporter** role.
2. Enable the following scopes: \`read_api\`, \`read_repository\`.
3. Enter the token and group URL in LoxeAI.`,
  },

  // -------------------------------------------------------------------------
  // Identity Providers
  // -------------------------------------------------------------------------
  {
    key: 'okta',
    name: 'Okta',
    icon: '🔐',
    serviceType: 'identity_provider',
    description: 'Scan Okta organization for authentication policies, MFA, and user lifecycle management.',
    credentialType: 'api_key',
    scans: [
      {
        key: 'okta-policies',
        name: 'Authentication Policies',
        description: 'Check sign-on policies, MFA requirements, and session settings.',
        controls: ['CC6.1', 'CC6.2'],
        estimatedDurationSeconds: 15,
      },
      {
        key: 'okta-users',
        name: 'User Lifecycle',
        description: 'Check for inactive users, deprovisioning, and user status.',
        controls: ['CC6.2', 'CC6.3'],
        estimatedDurationSeconds: 20,
      },
      {
        key: 'okta-apps',
        name: 'Application Assignments',
        description: 'Review application access, SSO configurations, and provisioning.',
        controls: ['CC6.1', 'CC6.3'],
        estimatedDurationSeconds: 25,
      },
      {
        key: 'okta-logs',
        name: 'System Log',
        description: 'Check audit log availability and security event monitoring.',
        controls: ['CC7.2', 'CC4.1'],
        estimatedDurationSeconds: 10,
      },
    ],
    controlsCovered: ['CC4.1', 'CC6.1', 'CC6.2', 'CC6.3', 'CC7.2'],
    setupInstructions: `## Okta Integration Setup

### Steps
1. Create an API token in Okta Admin Console under Security > API > Tokens.
2. The token must be created by an Okta admin (Super Admin or Read-Only Admin role).
3. Enter the API token and your Okta domain in LoxeAI.`,
  },

  {
    key: 'google-workspace',
    name: 'Google Workspace',
    icon: '📧',
    serviceType: 'identity_provider',
    description: 'Scan Google Workspace for identity, authentication, and access management compliance.',
    credentialType: 'oauth',
    scans: [
      {
        key: 'gws-users',
        name: 'User Management',
        description: 'Check user accounts, 2SV enrollment, and admin roles.',
        controls: ['CC6.1', 'CC6.2', 'CC6.3'],
        estimatedDurationSeconds: 20,
      },
      {
        key: 'gws-security',
        name: 'Security Settings',
        description: 'Check login challenges, session management, and password policies.',
        controls: ['CC6.1', 'CC6.2'],
        estimatedDurationSeconds: 15,
      },
      {
        key: 'gws-audit',
        name: 'Admin Audit Log',
        description: 'Check audit log availability and admin activity monitoring.',
        controls: ['CC7.2', 'CC4.1'],
        estimatedDurationSeconds: 10,
      },
    ],
    controlsCovered: ['CC4.1', 'CC6.1', 'CC6.2', 'CC6.3', 'CC7.2'],
    setupInstructions: `## Google Workspace Integration Setup

### Steps
1. Set up a service account in Google Cloud Console with domain-wide delegation.
2. Grant the following scopes: Admin SDK Directory API (readonly), Reports API.
3. Authorize the service account in the Google Workspace Admin Console.
4. Upload the service account key in LoxeAI.`,
  },

  {
    key: 'microsoft-entra-id',
    name: 'Microsoft Entra ID',
    icon: '🔵',
    serviceType: 'identity_provider',
    description: 'Scan Microsoft Entra ID (Azure AD) for identity, conditional access, and MFA compliance.',
    credentialType: 'oauth',
    scans: [
      {
        key: 'entra-users',
        name: 'User & Group Management',
        description: 'Check user accounts, group memberships, and role assignments.',
        controls: ['CC6.1', 'CC6.2', 'CC6.3'],
        estimatedDurationSeconds: 25,
      },
      {
        key: 'entra-conditional-access',
        name: 'Conditional Access Policies',
        description: 'Review conditional access policies and MFA requirements.',
        controls: ['CC6.1', 'CC6.2'],
        estimatedDurationSeconds: 15,
      },
      {
        key: 'entra-sign-ins',
        name: 'Sign-In Logs',
        description: 'Check sign-in log retention and risk-based sign-in policies.',
        controls: ['CC7.2', 'CC4.1'],
        estimatedDurationSeconds: 10,
      },
    ],
    controlsCovered: ['CC4.1', 'CC6.1', 'CC6.2', 'CC6.3', 'CC7.2'],
    setupInstructions: `## Microsoft Entra ID Integration Setup

### Steps
1. Register an application in Microsoft Entra ID.
2. Grant **Directory.Read.All** and **AuditLog.Read.All** application permissions.
3. Grant admin consent for the permissions.
4. Enter the Tenant ID, Client ID, and Client Secret in LoxeAI.`,
  },

  // -------------------------------------------------------------------------
  // CDN & Security
  // -------------------------------------------------------------------------
  {
    key: 'cloudflare',
    name: 'Cloudflare',
    icon: '🛡️',
    serviceType: 'cdn_security',
    description: 'Scan Cloudflare zones for WAF, DDoS protection, and TLS configuration.',
    credentialType: 'api_key',
    scans: [
      {
        key: 'cf-waf',
        name: 'WAF Configuration',
        description: 'Check Web Application Firewall rules and managed rulesets.',
        controls: ['CC6.6', 'CC7.1'],
        estimatedDurationSeconds: 15,
      },
      {
        key: 'cf-tls',
        name: 'TLS/SSL Settings',
        description: 'Check TLS version, HSTS, and certificate settings.',
        controls: ['CC6.7'],
        estimatedDurationSeconds: 10,
      },
      {
        key: 'cf-access',
        name: 'Access Policies',
        description: 'Review Zero Trust access policies and authentication rules.',
        controls: ['CC6.1', 'CC6.6'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC6.1', 'CC6.6', 'CC6.7', 'CC7.1'],
    setupInstructions: `## Cloudflare Integration Setup

### Steps
1. Create an API token in the Cloudflare dashboard under My Profile > API Tokens.
2. Use the "Read all resources" template or create a custom token with read permissions.
3. Enter the API token in LoxeAI.`,
  },

  // -------------------------------------------------------------------------
  // Project Management
  // -------------------------------------------------------------------------
  {
    key: 'jira',
    name: 'Jira',
    icon: '📋',
    serviceType: 'project_management',
    description: 'Scan Jira projects for change management workflows and issue tracking compliance.',
    credentialType: 'api_key',
    scans: [
      {
        key: 'jira-workflows',
        name: 'Workflow Compliance',
        description: 'Check that change management workflows require approvals and testing stages.',
        controls: ['CC8.1'],
        estimatedDurationSeconds: 20,
      },
      {
        key: 'jira-access',
        name: 'Project Access',
        description: 'Review project permissions and role assignments.',
        controls: ['CC6.3'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC6.3', 'CC8.1'],
    setupInstructions: `## Jira Integration Setup

### Steps
1. Create an API token at https://id.atlassian.com/manage-profile/security/api-tokens.
2. Enter your Atlassian email and the API token in LoxeAI.
3. Provide your Jira instance URL (e.g., https://yourcompany.atlassian.net).`,
  },

  // -------------------------------------------------------------------------
  // Communication
  // -------------------------------------------------------------------------
  {
    key: 'slack',
    name: 'Slack',
    icon: '💬',
    serviceType: 'communication',
    description: 'Scan Slack workspace for security settings, retention, and access controls.',
    credentialType: 'oauth',
    scans: [
      {
        key: 'slack-security',
        name: 'Workspace Security',
        description: 'Check 2FA enforcement, session duration, and approved apps.',
        controls: ['CC6.2'],
        estimatedDurationSeconds: 10,
      },
      {
        key: 'slack-retention',
        name: 'Message Retention',
        description: 'Check message and file retention policies.',
        controls: ['CC7.2'],
        estimatedDurationSeconds: 5,
      },
    ],
    controlsCovered: ['CC6.2', 'CC7.2'],
    setupInstructions: `## Slack Integration Setup

### Steps
1. Install the LoxeAI app from the Slack App Directory.
2. Authorize with a Workspace Owner or Admin account.
3. The app requires read-only access to workspace settings and audit logs.`,
  },

  // -------------------------------------------------------------------------
  // HR Platforms
  // -------------------------------------------------------------------------
  {
    key: 'rippling',
    name: 'Rippling',
    icon: '👥',
    serviceType: 'hr_platform',
    description: 'Scan Rippling for employee lifecycle management, onboarding, and offboarding compliance.',
    credentialType: 'api_key',
    scans: [
      {
        key: 'rippling-employees',
        name: 'Employee Lifecycle',
        description: 'Check onboarding completeness, offboarding timeliness, and access deprovisioning.',
        controls: ['CC6.2', 'CC6.3'],
        estimatedDurationSeconds: 20,
      },
      {
        key: 'rippling-policies',
        name: 'HR Policies',
        description: 'Verify background check policies and security awareness training.',
        controls: ['CC1.4'],
        estimatedDurationSeconds: 10,
      },
    ],
    controlsCovered: ['CC1.4', 'CC6.2', 'CC6.3'],
    setupInstructions: `## Rippling Integration Setup

### Steps
1. Navigate to Rippling Admin > Platform > API.
2. Create an API key with read-only permissions.
3. Enter the API key in LoxeAI.`,
  },

  {
    key: 'gusto',
    name: 'Gusto',
    icon: '💰',
    serviceType: 'hr_platform',
    description: 'Scan Gusto for employee management and HR compliance evidence.',
    credentialType: 'oauth',
    scans: [
      {
        key: 'gusto-employees',
        name: 'Employee Management',
        description: 'Check employee records, onboarding status, and termination processes.',
        controls: ['CC6.2', 'CC6.3'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC6.2', 'CC6.3'],
    setupInstructions: `## Gusto Integration Setup

### Steps
1. Contact Gusto support to enable API access for your account.
2. Authorize LoxeAI via OAuth in the Gusto admin panel.
3. Read-only access to employee data is required.`,
  },

  // -------------------------------------------------------------------------
  // Device Management
  // -------------------------------------------------------------------------
  {
    key: 'jamf',
    name: 'Jamf Pro',
    icon: '💻',
    serviceType: 'device_management',
    description: 'Scan Jamf Pro for endpoint security, encryption, and patch management compliance.',
    credentialType: 'api_key',
    scans: [
      {
        key: 'jamf-devices',
        name: 'Device Compliance',
        description: 'Check FileVault encryption, OS updates, and firewall status on managed devices.',
        controls: ['CC6.7', 'CC6.8'],
        estimatedDurationSeconds: 30,
      },
      {
        key: 'jamf-policies',
        name: 'Security Policies',
        description: 'Review configuration profiles, passcode requirements, and screen lock policies.',
        controls: ['CC6.1', 'CC6.8'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC6.1', 'CC6.7', 'CC6.8'],
    setupInstructions: `## Jamf Pro Integration Setup

### Steps
1. Create an API role with read-only permissions in Jamf Pro.
2. Create an API client under Settings > API Roles and Clients.
3. Enter the Client ID, Client Secret, and your Jamf Pro URL in LoxeAI.`,
  },

  {
    key: 'kandji',
    name: 'Kandji',
    icon: '🔒',
    serviceType: 'device_management',
    description: 'Scan Kandji for Apple device management, security compliance, and patch status.',
    credentialType: 'api_key',
    scans: [
      {
        key: 'kandji-devices',
        name: 'Device Inventory',
        description: 'Check encryption status, OS versions, and compliance blueprint status.',
        controls: ['CC6.7', 'CC6.8'],
        estimatedDurationSeconds: 25,
      },
      {
        key: 'kandji-blueprints',
        name: 'Blueprint Compliance',
        description: 'Review security blueprints and library item assignments.',
        controls: ['CC6.1', 'CC6.8'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC6.1', 'CC6.7', 'CC6.8'],
    setupInstructions: `## Kandji Integration Setup

### Steps
1. Navigate to Settings > Access in Kandji.
2. Create an API token with read-only permissions.
3. Enter the API token and your Kandji subdomain in LoxeAI.`,
  },

  // -------------------------------------------------------------------------
  // Monitoring
  // -------------------------------------------------------------------------
  {
    key: 'datadog',
    name: 'Datadog',
    icon: '🐕',
    serviceType: 'monitoring',
    description: 'Scan Datadog for monitoring coverage, alerting, and log management compliance.',
    credentialType: 'api_key',
    scans: [
      {
        key: 'dd-monitors',
        name: 'Monitor Coverage',
        description: 'Check that critical services have monitors with appropriate thresholds and notifications.',
        controls: ['CC7.1', 'CC7.2'],
        estimatedDurationSeconds: 20,
      },
      {
        key: 'dd-logs',
        name: 'Log Management',
        description: 'Review log pipeline configuration, retention, and archival settings.',
        controls: ['CC7.2', 'CC4.1'],
        estimatedDurationSeconds: 15,
      },
    ],
    controlsCovered: ['CC4.1', 'CC7.1', 'CC7.2'],
    setupInstructions: `## Datadog Integration Setup

### Steps
1. Create an API key and Application key in Datadog under Organization Settings > API Keys.
2. The Application key should have read-only permissions.
3. Enter both keys and your Datadog site (e.g., datadoghq.com) in LoxeAI.`,
  },

  // -------------------------------------------------------------------------
  // Incident Management
  // -------------------------------------------------------------------------
  {
    key: 'pagerduty',
    name: 'PagerDuty',
    icon: '🚨',
    serviceType: 'incident_management',
    description: 'Scan PagerDuty for incident response procedures, escalation policies, and on-call coverage.',
    credentialType: 'api_key',
    scans: [
      {
        key: 'pd-escalation',
        name: 'Escalation Policies',
        description: 'Check that escalation policies have adequate coverage and notification rules.',
        controls: ['CC7.3', 'CC7.4'],
        estimatedDurationSeconds: 10,
      },
      {
        key: 'pd-services',
        name: 'Service Configuration',
        description: 'Review service integrations, urgency settings, and incident handling rules.',
        controls: ['CC7.1', 'CC7.3'],
        estimatedDurationSeconds: 15,
      },
      {
        key: 'pd-oncall',
        name: 'On-Call Schedules',
        description: 'Verify on-call coverage and rotation policies.',
        controls: ['CC7.3'],
        estimatedDurationSeconds: 10,
      },
    ],
    controlsCovered: ['CC7.1', 'CC7.3', 'CC7.4'],
    setupInstructions: `## PagerDuty Integration Setup

### Steps
1. Create a read-only API key in PagerDuty under Integrations > API Access Keys.
2. Use a "General Access" API key (v2) with read-only scope.
3. Enter the API key in LoxeAI.`,
  },
];

// ---------------------------------------------------------------------------
// Registry Lookup Helpers
// ---------------------------------------------------------------------------

/**
 * Get an integration definition by key.
 */
export function getIntegrationDefinition(key: string): IntegrationDefinition | undefined {
  return INTEGRATION_REGISTRY.find((i) => i.key === key);
}

/**
 * Get all integrations that cover a specific SOC 2 control.
 */
export function getIntegrationsForControl(controlId: string): IntegrationDefinition[] {
  return INTEGRATION_REGISTRY.filter((i) =>
    i.controlsCovered.includes(controlId as IntegrationDefinition['controlsCovered'][number]),
  );
}

/**
 * Get all integrations of a given service type.
 */
export function getIntegrationsByType(serviceType: IntegrationDefinition['serviceType']): IntegrationDefinition[] {
  return INTEGRATION_REGISTRY.filter((i) => i.serviceType === serviceType);
}

/**
 * List all unique SOC 2 controls covered across all integrations.
 */
export function getAllCoveredControls(): string[] {
  const controls = new Set<string>();
  for (const integration of INTEGRATION_REGISTRY) {
    for (const controlId of integration.controlsCovered) {
      controls.add(controlId);
    }
  }
  return Array.from(controls).sort();
}
