// =============================================================================
// LoxeAI — GitHub Security Scanner
// Collects SOC 2 compliance evidence from GitHub organization settings
// =============================================================================

import {
  type ApiCallRecord,
  type EvidenceItem,
  type EvidenceSeverity,
  type EvidenceStatus,
  type GitHubCredentials,
  type Soc2ControlId,
  type SourceEvidenceTrace,
  type ScanResult,
} from '../../types/index';

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

async function sha256(data: string): Promise<string> {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    const buf = new TextEncoder().encode(data);
    const hash = await globalThis.crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  const { createHash } = await import('crypto');
  return createHash('sha256').update(data).digest('hex');
}

function generateId(prefix: string): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

// ---------------------------------------------------------------------------
// GitHub Client Interface
// ---------------------------------------------------------------------------

export interface GitHubApiResponse {
  data: Record<string, unknown>;
  requestId: string;
  httpStatus: number;
}

/**
 * Abstraction over the GitHub REST/GraphQL API.
 * Each method maps to a specific GitHub API endpoint.
 */
export interface GitHubClient {
  // Organization
  getOrg(org: string): Promise<GitHubApiResponse>;
  getOrgMembershipSettings(org: string): Promise<GitHubApiResponse>;

  // Repositories
  listOrgRepos(org: string): Promise<GitHubApiResponse>;
  getBranchProtection(owner: string, repo: string, branch: string): Promise<GitHubApiResponse>;
  getRepo(owner: string, repo: string): Promise<GitHubApiResponse>;

  // Access
  listOrgMembers(org: string): Promise<GitHubApiResponse>;
  listOrgTeams(org: string): Promise<GitHubApiResponse>;
  listOutsideCollaborators(org: string): Promise<GitHubApiResponse>;
  getTeamMembers(org: string, teamSlug: string): Promise<GitHubApiResponse>;

  // Audit
  getAuditLog(org: string): Promise<GitHubApiResponse>;

  // Security
  listSecretScanningAlerts(owner: string, repo: string): Promise<GitHubApiResponse>;
  listDependabotAlerts(owner: string, repo: string): Promise<GitHubApiResponse>;
  getSecuritySettings(owner: string, repo: string): Promise<GitHubApiResponse>;
}

// ---------------------------------------------------------------------------
// API Call Tracker
// ---------------------------------------------------------------------------

class ApiCallTracker {
  private calls: ApiCallRecord[] = [];

  record(
    service: string,
    operation: string,
    response: GitHubApiResponse,
    responseSha256: string,
  ): void {
    this.calls.push({
      service,
      operation,
      timestamp: new Date().toISOString(),
      requestId: response.requestId,
      responseSha256,
      httpStatus: response.httpStatus,
    });
  }

  getCalls(): ApiCallRecord[] {
    return [...this.calls];
  }
}

// ---------------------------------------------------------------------------
// Evidence Builder
// ---------------------------------------------------------------------------

interface FindingInput {
  scanType: string;
  title: string;
  description: string;
  controls: Soc2ControlId[];
  status: EvidenceStatus;
  severity: EvidenceSeverity;
  resource: string;
  rawData: Record<string, unknown>;
  remediation: string;
  auditorQuestions: string[];
}

async function buildEvidenceItem(
  finding: FindingInput,
  tracker: ApiCallTracker,
  integrationId: string,
  startTime: string,
  previousHash: string,
): Promise<EvidenceItem> {
  const now = new Date().toISOString();
  const rawDataStr = JSON.stringify(finding.rawData);
  const evidenceHash = await sha256(rawDataStr + now + previousHash);

  const trace: SourceEvidenceTrace = {
    traceId: generateId('trace'),
    integrationId,
    collectedAt: startTime,
    completedAt: now,
    collectorIdentity: integrationId,
    apiCalls: tracker.getCalls(),
    evidenceHash,
    previousHash,
  };

  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  return {
    id: generateId('ev'),
    source: 'github',
    scanType: finding.scanType,
    title: finding.title,
    description: finding.description,
    controls: finding.controls,
    status: finding.status,
    severity: finding.severity,
    resource: finding.resource,
    rawData: finding.rawData,
    remediation: finding.remediation,
    auditorQuestions: finding.auditorQuestions,
    sourceTrace: trace,
    collectedAt: now,
    expiresAt,
  };
}

// ---------------------------------------------------------------------------
// GitHub Scanner — 5 scan functions
// ---------------------------------------------------------------------------

export class GitHubScanner {
  private client: GitHubClient;
  private credentials: GitHubCredentials;
  private integrationId: string;

  constructor(client: GitHubClient, credentials: GitHubCredentials, integrationId: string) {
    this.client = client;
    this.credentials = credentials;
    this.integrationId = integrationId;
  }

  /** Run all scans */
  async runAllScans(): Promise<ScanResult[]> {
    const scanFns: Array<() => Promise<ScanResult>> = [
      () => this.scanOrgSettings(),
      () => this.scanRepoProtection(),
      () => this.scanAccessPermissions(),
      () => this.scanAuditLog(),
      () => this.scanSecrets(),
    ];
    const results: ScanResult[] = [];
    for (const fn of scanFns) {
      try {
        results.push(await fn());
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err);
        results.push({
          scanKey: 'unknown',
          success: false,
          error,
          evidence: [],
          durationMs: 0,
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
        });
      }
    }
    return results;
  }

  // -----------------------------------------------------------------------
  // 1. Org Settings — 2FA requirement, default permissions
  // -----------------------------------------------------------------------
  async scanOrgSettings(): Promise<ScanResult> {
    const scanKey = 'org-settings';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const orgResp = await this.client.getOrg(this.credentials.org);
      const orgHash = await sha256(JSON.stringify(orgResp.data));
      tracker.record('github', 'GET /orgs/{org}', orgResp, orgHash);

      const membershipResp = await this.client.getOrgMembershipSettings(this.credentials.org);
      const memHash = await sha256(JSON.stringify(membershipResp.data));
      tracker.record('github', 'GET /orgs/{org}/settings', membershipResp, memHash);

      const twoFactorRequired = orgResp.data.two_factor_requirement_enabled as boolean;
      const defaultPermission = orgResp.data.default_repository_permission as string;
      const membersCanCreateRepos = orgResp.data.members_can_create_repositories as boolean;

      // 2FA check
      const mfaItem = await buildEvidenceItem(
        {
          scanType: scanKey,
          title: 'GitHub Organization 2FA Requirement',
          description: twoFactorRequired
            ? `Organization ${this.credentials.org} requires two-factor authentication for all members.`
            : `Organization ${this.credentials.org} does NOT require two-factor authentication.`,
          controls: ['CC6.2'],
          status: twoFactorRequired ? 'pass' : 'fail',
          severity: twoFactorRequired ? 'info' : 'critical',
          resource: `https://github.com/${this.credentials.org}`,
          rawData: { org: this.credentials.org, twoFactorRequired },
          remediation: twoFactorRequired
            ? 'No action needed.'
            : 'Enable "Require two-factor authentication" in Organization Settings > Authentication security.',
          auditorQuestions: [
            'Is 2FA enforced for all organization members?',
            'What 2FA methods are accepted?',
            'How are non-compliant members handled?',
          ],
        },
        tracker,
        this.integrationId,
        startedAt,
        previousHash,
      );
      previousHash = mfaItem.sourceTrace.evidenceHash;
      evidence.push(mfaItem);

      // Default permissions
      const isPermissive = defaultPermission === 'write' || defaultPermission === 'admin';
      const permItem = await buildEvidenceItem(
        {
          scanType: scanKey,
          title: 'GitHub Default Repository Permission',
          description: `Default repository permission for organization members is "${defaultPermission}".`,
          controls: ['CC6.2'],
          status: isPermissive ? 'fail' : 'pass',
          severity: isPermissive ? 'high' : 'info',
          resource: `https://github.com/${this.credentials.org}`,
          rawData: { defaultPermission, membersCanCreateRepos },
          remediation: isPermissive
            ? 'Set default repository permission to "read" or "none". Grant write/admin access per-team or per-repo.'
            : 'No action needed.',
          auditorQuestions: [
            'How are repository permissions managed?',
            'Is there a process for granting elevated access?',
            'Are permissions reviewed periodically?',
          ],
        },
        tracker,
        this.integrationId,
        startedAt,
        previousHash,
      );
      previousHash = permItem.sourceTrace.evidenceHash;
      evidence.push(permItem);

      return {
        scanKey,
        success: true,
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    } catch (err) {
      return {
        scanKey,
        success: false,
        error: err instanceof Error ? err.message : String(err),
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    }
  }

  // -----------------------------------------------------------------------
  // 2. Repository Branch Protection — required reviews, status checks
  // -----------------------------------------------------------------------
  async scanRepoProtection(): Promise<ScanResult> {
    const scanKey = 'repo-protection';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const reposResp = await this.client.listOrgRepos(this.credentials.org);
      const reposHash = await sha256(JSON.stringify(reposResp.data));
      tracker.record('github', 'GET /orgs/{org}/repos', reposResp, reposHash);

      const repos = (reposResp.data.repositories as Array<Record<string, unknown>>) ?? [];

      for (const repo of repos) {
        const repoName = repo.name as string;
        const defaultBranch = repo.default_branch as string;
        const isArchived = repo.archived as boolean;

        if (isArchived) continue;

        const protResp = await this.client.getBranchProtection(
          this.credentials.org,
          repoName,
          defaultBranch,
        );
        const protHash = await sha256(JSON.stringify(protResp.data));
        tracker.record('github', 'GET /repos/{owner}/{repo}/branches/{branch}/protection', protResp, protHash);

        if (protResp.httpStatus === 404) {
          const item = await buildEvidenceItem(
            {
              scanType: scanKey,
              title: `No Branch Protection: ${repoName}/${defaultBranch}`,
              description: `Repository ${repoName} has no branch protection rules on ${defaultBranch}.`,
              controls: ['CC8.1'],
              status: 'fail',
              severity: 'critical',
              resource: `https://github.com/${this.credentials.org}/${repoName}`,
              rawData: { repoName, defaultBranch, protected: false },
              remediation: `Enable branch protection on ${defaultBranch} requiring pull request reviews, status checks, and restricting force pushes.`,
              auditorQuestions: [
                'Can code be pushed directly to the main branch?',
                'Is there a code review process?',
                'How is change management enforced?',
              ],
            },
            tracker,
            this.integrationId,
            startedAt,
            previousHash,
          );
          previousHash = item.sourceTrace.evidenceHash;
          evidence.push(item);
          continue;
        }

        const protection = protResp.data;
        const requiredReviews = protection.required_pull_request_reviews as Record<string, unknown> | undefined;
        const requiredStatusChecks = protection.required_status_checks as Record<string, unknown> | undefined;
        const enforceAdmins = protection.enforce_admins as Record<string, boolean> | undefined;
        const allowForcePushes = protection.allow_force_pushes as Record<string, boolean> | undefined;
        const allowDeletions = protection.allow_deletions as Record<string, boolean> | undefined;

        const issues: string[] = [];
        if (!requiredReviews) {
          issues.push('pull request reviews not required');
        } else {
          const approvalCount = requiredReviews.required_approving_review_count as number;
          if (approvalCount < 1) issues.push('zero approving reviews required');
          if (!requiredReviews.dismiss_stale_reviews) issues.push('stale reviews not dismissed on new pushes');
          if (!requiredReviews.require_code_owner_reviews) issues.push('code owner reviews not required');
        }
        if (!requiredStatusChecks) issues.push('status checks not required');
        if (!enforceAdmins?.enabled) issues.push('admins can bypass protection rules');
        if (allowForcePushes?.enabled) issues.push('force pushes are allowed');
        if (allowDeletions?.enabled) issues.push('branch deletion is allowed');

        const status: EvidenceStatus = issues.length === 0 ? 'pass' : 'fail';
        const severity: EvidenceSeverity =
          !requiredReviews ? 'critical' : issues.length > 0 ? 'high' : 'info';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `Branch Protection: ${repoName}/${defaultBranch}`,
            description:
              issues.length === 0
                ? `Repository ${repoName} has comprehensive branch protection on ${defaultBranch}.`
                : `Repository ${repoName} branch protection issues: ${issues.join(', ')}.`,
            controls: ['CC8.1'],
            status,
            severity,
            resource: `https://github.com/${this.credentials.org}/${repoName}/settings/branches`,
            rawData: protection,
            remediation:
              issues.length === 0
                ? 'No action needed.'
                : `Fix: ${issues.join('; ')}. Require PR reviews (2+ approvals), enable status checks, enforce for admins, block force pushes.`,
            auditorQuestions: [
              'How many approvals are required for a merge?',
              'Are code owners automatically requested for review?',
              'What CI checks must pass before merging?',
            ],
          },
          tracker,
          this.integrationId,
          startedAt,
          previousHash,
        );
        previousHash = item.sourceTrace.evidenceHash;
        evidence.push(item);
      }

      return {
        scanKey,
        success: true,
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    } catch (err) {
      return {
        scanKey,
        success: false,
        error: err instanceof Error ? err.message : String(err),
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    }
  }

  // -----------------------------------------------------------------------
  // 3. Access Permissions — team/user access, outside collaborators
  // -----------------------------------------------------------------------
  async scanAccessPermissions(): Promise<ScanResult> {
    const scanKey = 'access-permissions';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      // Org members
      const membersResp = await this.client.listOrgMembers(this.credentials.org);
      const memHash = await sha256(JSON.stringify(membersResp.data));
      tracker.record('github', 'GET /orgs/{org}/members', membersResp, memHash);

      const members = (membersResp.data.members as Array<Record<string, unknown>>) ?? [];
      const adminMembers = members.filter((m) => m.role === 'admin');

      const adminItem = await buildEvidenceItem(
        {
          scanType: scanKey,
          title: 'Organization Admin Users',
          description: `${adminMembers.length} of ${members.length} organization members have admin role.`,
          controls: ['CC6.3'],
          status: adminMembers.length <= 3 ? 'pass' : 'warning',
          severity: adminMembers.length > 5 ? 'high' : adminMembers.length > 3 ? 'medium' : 'info',
          resource: `https://github.com/orgs/${this.credentials.org}/people`,
          rawData: {
            totalMembers: members.length,
            adminCount: adminMembers.length,
            admins: adminMembers.map((m) => m.login),
          },
          remediation:
            adminMembers.length <= 3
              ? 'No action needed.'
              : 'Reduce the number of organization admins. Follow the principle of least privilege.',
          auditorQuestions: [
            'Who are the organization administrators?',
            'Is there a process for reviewing admin access?',
            'How is admin access granted and revoked?',
          ],
        },
        tracker,
        this.integrationId,
        startedAt,
        previousHash,
      );
      previousHash = adminItem.sourceTrace.evidenceHash;
      evidence.push(adminItem);

      // Teams
      const teamsResp = await this.client.listOrgTeams(this.credentials.org);
      const teamsHash = await sha256(JSON.stringify(teamsResp.data));
      tracker.record('github', 'GET /orgs/{org}/teams', teamsResp, teamsHash);

      const teams = (teamsResp.data.teams as Array<Record<string, unknown>>) ?? [];
      const teamItem = await buildEvidenceItem(
        {
          scanType: scanKey,
          title: 'Organization Team Structure',
          description: `Organization has ${teams.length} team(s) for access management.`,
          controls: ['CC6.3'],
          status: teams.length > 0 ? 'pass' : 'warning',
          severity: teams.length === 0 ? 'medium' : 'info',
          resource: `https://github.com/orgs/${this.credentials.org}/teams`,
          rawData: { teamCount: teams.length, teams: teams.map((t) => ({ name: t.name, permission: t.permission })) },
          remediation:
            teams.length > 0
              ? 'No action needed.'
              : 'Create teams to manage repository access. Avoid granting access to individual users.',
          auditorQuestions: [
            'How are teams structured (by function, project)?',
            'Is there a team membership review process?',
            'Who can create and manage teams?',
          ],
        },
        tracker,
        this.integrationId,
        startedAt,
        previousHash,
      );
      previousHash = teamItem.sourceTrace.evidenceHash;
      evidence.push(teamItem);

      // Outside collaborators
      const collabResp = await this.client.listOutsideCollaborators(this.credentials.org);
      const collabHash = await sha256(JSON.stringify(collabResp.data));
      tracker.record('github', 'GET /orgs/{org}/outside_collaborators', collabResp, collabHash);

      const collaborators = (collabResp.data.collaborators as Array<Record<string, unknown>>) ?? [];
      const collabItem = await buildEvidenceItem(
        {
          scanType: scanKey,
          title: 'Outside Collaborators',
          description: `Organization has ${collaborators.length} outside collaborator(s).`,
          controls: ['CC6.3'],
          status: collaborators.length === 0 ? 'pass' : 'warning',
          severity: collaborators.length > 5 ? 'high' : collaborators.length > 0 ? 'medium' : 'info',
          resource: `https://github.com/orgs/${this.credentials.org}/outside-collaborators`,
          rawData: {
            count: collaborators.length,
            collaborators: collaborators.map((c) => c.login),
          },
          remediation:
            collaborators.length === 0
              ? 'No action needed.'
              : 'Review outside collaborators regularly. Convert long-term collaborators to org members or remove inactive ones.',
          auditorQuestions: [
            'Why do outside collaborators have access?',
            'Is there a periodic review of outside collaborators?',
            'What repositories do outside collaborators access?',
          ],
        },
        tracker,
        this.integrationId,
        startedAt,
        previousHash,
      );
      previousHash = collabItem.sourceTrace.evidenceHash;
      evidence.push(collabItem);

      return {
        scanKey,
        success: true,
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    } catch (err) {
      return {
        scanKey,
        success: false,
        error: err instanceof Error ? err.message : String(err),
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    }
  }

  // -----------------------------------------------------------------------
  // 4. Audit Log — availability and retention
  // -----------------------------------------------------------------------
  async scanAuditLog(): Promise<ScanResult> {
    const scanKey = 'audit-log';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const auditResp = await this.client.getAuditLog(this.credentials.org);
      const auditHash = await sha256(JSON.stringify(auditResp.data));
      tracker.record('github', 'GET /orgs/{org}/audit-log', auditResp, auditHash);

      const entries = (auditResp.data.entries as Array<Record<string, unknown>>) ?? [];
      const isAvailable = auditResp.httpStatus === 200 && entries.length > 0;

      // Check how far back entries go
      let oldestEntryAge = 0;
      if (entries.length > 0) {
        const oldestTimestamp = entries[entries.length - 1]?.created_at as string;
        if (oldestTimestamp) {
          oldestEntryAge = Math.floor(
            (Date.now() - new Date(oldestTimestamp).getTime()) / (1000 * 60 * 60 * 24),
          );
        }
      }

      const item = await buildEvidenceItem(
        {
          scanType: scanKey,
          title: 'GitHub Audit Log',
          description: isAvailable
            ? `Audit log is available with ${entries.length} recent entries. Oldest sampled entry is ${oldestEntryAge} days old.`
            : 'Audit log is not available or empty. This may require a GitHub Enterprise plan.',
          controls: ['CC7.2', 'CC4.1'],
          status: isAvailable ? 'pass' : 'fail',
          severity: isAvailable ? 'info' : 'high',
          resource: `https://github.com/orgs/${this.credentials.org}/settings/audit-log`,
          rawData: { entriesCount: entries.length, oldestEntryAgeDays: oldestEntryAge, sampleActions: entries.slice(0, 5).map((e) => e.action) },
          remediation: isAvailable
            ? 'Ensure audit log streaming is configured for long-term retention (S3, Splunk, or Azure Blob).'
            : 'Upgrade to GitHub Enterprise to access the audit log API. Configure log streaming for retention.',
          auditorQuestions: [
            'How long are audit logs retained?',
            'Is audit log streaming configured?',
            'Where are audit logs forwarded for analysis?',
            'Is there alerting on security-relevant audit events?',
          ],
        },
        tracker,
        this.integrationId,
        startedAt,
        previousHash,
      );
      previousHash = item.sourceTrace.evidenceHash;
      evidence.push(item);

      return {
        scanKey,
        success: true,
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    } catch (err) {
      return {
        scanKey,
        success: false,
        error: err instanceof Error ? err.message : String(err),
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    }
  }

  // -----------------------------------------------------------------------
  // 5. Secrets — secret scanning, Dependabot
  // -----------------------------------------------------------------------
  async scanSecrets(): Promise<ScanResult> {
    const scanKey = 'secrets-scanning';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const reposResp = await this.client.listOrgRepos(this.credentials.org);
      const reposHash = await sha256(JSON.stringify(reposResp.data));
      tracker.record('github', 'GET /orgs/{org}/repos', reposResp, reposHash);

      const repos = (reposResp.data.repositories as Array<Record<string, unknown>>) ?? [];

      for (const repo of repos) {
        const repoName = repo.name as string;
        const isArchived = repo.archived as boolean;
        if (isArchived) continue;

        // Security settings
        const secResp = await this.client.getSecuritySettings(this.credentials.org, repoName);
        const secHash = await sha256(JSON.stringify(secResp.data));
        tracker.record('github', 'GET /repos/{owner}/{repo}/security', secResp, secHash);

        const securitySettings = secResp.data;
        const secretScanningEnabled = securitySettings.secret_scanning_enabled as boolean;
        const secretPushProtection = securitySettings.secret_scanning_push_protection_enabled as boolean;
        const dependabotEnabled = securitySettings.dependabot_alerts_enabled as boolean;
        const dependabotUpdates = securitySettings.dependabot_security_updates_enabled as boolean;

        // Secret scanning
        const issues: string[] = [];
        if (!secretScanningEnabled) issues.push('secret scanning not enabled');
        if (!secretPushProtection) issues.push('push protection not enabled');
        if (!dependabotEnabled) issues.push('Dependabot alerts not enabled');
        if (!dependabotUpdates) issues.push('Dependabot security updates not enabled');

        const settingsItem = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `Security Features: ${repoName}`,
            description:
              issues.length === 0
                ? `Repository ${repoName} has all security features enabled (secret scanning, push protection, Dependabot).`
                : `Repository ${repoName} missing security features: ${issues.join(', ')}.`,
            controls: ['CC7.1'],
            status: issues.length === 0 ? 'pass' : 'fail',
            severity: !secretScanningEnabled ? 'critical' : issues.length > 0 ? 'high' : 'info',
            resource: `https://github.com/${this.credentials.org}/${repoName}/settings/security_analysis`,
            rawData: { repoName, ...securitySettings },
            remediation:
              issues.length === 0
                ? 'No action needed.'
                : `Enable: ${issues.join('; ')}. Go to repo Settings > Code security and analysis.`,
            auditorQuestions: [
              'Is secret scanning enabled for all repositories?',
              'How are secret scanning alerts handled?',
              'Is there a process for rotating exposed secrets?',
            ],
          },
          tracker,
          this.integrationId,
          startedAt,
          previousHash,
        );
        previousHash = settingsItem.sourceTrace.evidenceHash;
        evidence.push(settingsItem);

        // Check for active secret scanning alerts
        if (secretScanningEnabled) {
          const alertsResp = await this.client.listSecretScanningAlerts(this.credentials.org, repoName);
          const alertsHash = await sha256(JSON.stringify(alertsResp.data));
          tracker.record('github', 'GET /repos/{owner}/{repo}/secret-scanning/alerts', alertsResp, alertsHash);

          const alerts = (alertsResp.data.alerts as Array<Record<string, unknown>>) ?? [];
          const openAlerts = alerts.filter((a) => a.state === 'open');

          if (openAlerts.length > 0) {
            const alertItem = await buildEvidenceItem(
              {
                scanType: scanKey,
                title: `Open Secret Alerts: ${repoName}`,
                description: `Repository ${repoName} has ${openAlerts.length} open secret scanning alert(s) requiring remediation.`,
                controls: ['CC7.1'],
                status: 'fail',
                severity: 'critical',
                resource: `https://github.com/${this.credentials.org}/${repoName}/security/secret-scanning`,
                rawData: {
                  repoName,
                  openAlertCount: openAlerts.length,
                  alertTypes: openAlerts.map((a) => a.secret_type),
                },
                remediation: 'Immediately rotate all exposed secrets. Investigate whether they were used maliciously. Update secret storage to use a vault.',
                auditorQuestions: [
                  'What types of secrets were exposed?',
                  'Were the exposed secrets rotated?',
                  'What was the exposure window?',
                ],
              },
              tracker,
              this.integrationId,
              startedAt,
              previousHash,
            );
            previousHash = alertItem.sourceTrace.evidenceHash;
            evidence.push(alertItem);
          }
        }

        // Dependabot alerts
        if (dependabotEnabled) {
          const depResp = await this.client.listDependabotAlerts(this.credentials.org, repoName);
          const depHash = await sha256(JSON.stringify(depResp.data));
          tracker.record('github', 'GET /repos/{owner}/{repo}/dependabot/alerts', depResp, depHash);

          const depAlerts = (depResp.data.alerts as Array<Record<string, unknown>>) ?? [];
          const openCritical = depAlerts.filter(
            (a) => a.state === 'open' && ((a.security_advisory as Record<string, string>)?.severity === 'critical'),
          );

          if (openCritical.length > 0) {
            const depItem = await buildEvidenceItem(
              {
                scanType: scanKey,
                title: `Critical Dependabot Alerts: ${repoName}`,
                description: `Repository ${repoName} has ${openCritical.length} critical Dependabot alert(s).`,
                controls: ['CC7.1'],
                status: 'fail',
                severity: 'critical',
                resource: `https://github.com/${this.credentials.org}/${repoName}/security/dependabot`,
                rawData: {
                  repoName,
                  criticalAlertCount: openCritical.length,
                  totalOpenAlerts: depAlerts.filter((a) => a.state === 'open').length,
                },
                remediation: 'Update dependencies with critical vulnerabilities immediately. Enable Dependabot auto-merge for patch updates.',
                auditorQuestions: [
                  'What is the SLA for patching critical vulnerabilities?',
                  'Is there a vulnerability management process?',
                  'Are dependency updates tested before deployment?',
                ],
              },
              tracker,
              this.integrationId,
              startedAt,
              previousHash,
            );
            previousHash = depItem.sourceTrace.evidenceHash;
            evidence.push(depItem);
          }
        }
      }

      return {
        scanKey,
        success: true,
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    } catch (err) {
      return {
        scanKey,
        success: false,
        error: err instanceof Error ? err.message : String(err),
        evidence,
        durationMs: Date.now() - start,
        startedAt,
        completedAt: new Date().toISOString(),
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Mock GitHub Client — realistic sample data
// ---------------------------------------------------------------------------

export class MockGitHubClient implements GitHubClient {
  private nextRequestId = 1;

  private response(data: Record<string, unknown>, httpStatus = 200): GitHubApiResponse {
    return {
      data,
      requestId: `gh-req-${String(this.nextRequestId++).padStart(6, '0')}`,
      httpStatus,
    };
  }

  async getOrg(_org: string): Promise<GitHubApiResponse> {
    return this.response({
      login: 'acme-corp',
      id: 12345678,
      name: 'Acme Corporation',
      two_factor_requirement_enabled: true,
      default_repository_permission: 'read',
      members_can_create_repositories: false,
      members_can_create_public_repositories: false,
      members_can_create_private_repositories: false,
      members_can_create_internal_repositories: true,
      plan: { name: 'enterprise', seats: 50, filled_seats: 42 },
    });
  }

  async getOrgMembershipSettings(_org: string): Promise<GitHubApiResponse> {
    return this.response({
      members_can_fork_private_repositories: false,
      web_commit_signoff_required: true,
      members_allowed_repository_creation_type: 'internal',
      dependabot_alerts_enabled_for_new_repositories: true,
      dependabot_security_updates_enabled_for_new_repositories: true,
      dependency_graph_enabled_for_new_repositories: true,
      secret_scanning_enabled_for_new_repositories: true,
      secret_scanning_push_protection_enabled_for_new_repositories: true,
    });
  }

  async listOrgRepos(_org: string): Promise<GitHubApiResponse> {
    return this.response({
      repositories: [
        {
          name: 'backend-api',
          full_name: 'acme-corp/backend-api',
          private: true,
          default_branch: 'main',
          archived: false,
          language: 'TypeScript',
        },
        {
          name: 'frontend-app',
          full_name: 'acme-corp/frontend-app',
          private: true,
          default_branch: 'main',
          archived: false,
          language: 'TypeScript',
        },
        {
          name: 'infrastructure',
          full_name: 'acme-corp/infrastructure',
          private: true,
          default_branch: 'main',
          archived: false,
          language: 'HCL',
        },
      ],
    });
  }

  async getBranchProtection(_owner: string, repo: string, _branch: string): Promise<GitHubApiResponse> {
    if (repo === 'infrastructure') {
      return this.response({}, 404); // No branch protection
    }
    return this.response({
      required_pull_request_reviews: {
        dismiss_stale_reviews: repo === 'backend-api',
        require_code_owner_reviews: repo === 'backend-api',
        required_approving_review_count: repo === 'backend-api' ? 2 : 1,
        require_last_push_approval: repo === 'backend-api',
      },
      required_status_checks: {
        strict: true,
        contexts: repo === 'backend-api' ? ['ci/test', 'ci/lint', 'security/snyk'] : ['ci/test'],
      },
      enforce_admins: { enabled: repo === 'backend-api' },
      allow_force_pushes: { enabled: false },
      allow_deletions: { enabled: false },
      required_linear_history: { enabled: true },
      required_conversation_resolution: { enabled: repo === 'backend-api' },
    });
  }

  async getRepo(_owner: string, _repo: string): Promise<GitHubApiResponse> {
    return this.response({
      name: 'backend-api',
      visibility: 'private',
      default_branch: 'main',
    });
  }

  async listOrgMembers(_org: string): Promise<GitHubApiResponse> {
    return this.response({
      members: [
        { login: 'cto-alice', id: 1001, role: 'admin', two_factor_enabled: true },
        { login: 'lead-bob', id: 1002, role: 'admin', two_factor_enabled: true },
        { login: 'dev-charlie', id: 1003, role: 'member', two_factor_enabled: true },
        { login: 'dev-diana', id: 1004, role: 'member', two_factor_enabled: true },
        { login: 'dev-evan', id: 1005, role: 'member', two_factor_enabled: true },
        { login: 'ops-frank', id: 1006, role: 'member', two_factor_enabled: true },
        { login: 'security-grace', id: 1007, role: 'admin', two_factor_enabled: true },
      ],
    });
  }

  async listOrgTeams(_org: string): Promise<GitHubApiResponse> {
    return this.response({
      teams: [
        { name: 'engineering', slug: 'engineering', permission: 'push', members_count: 4 },
        { name: 'platform', slug: 'platform', permission: 'push', members_count: 2 },
        { name: 'security', slug: 'security', permission: 'admin', members_count: 1 },
      ],
    });
  }

  async listOutsideCollaborators(_org: string): Promise<GitHubApiResponse> {
    return this.response({
      collaborators: [
        { login: 'contractor-henry', id: 2001 },
        { login: 'auditor-iris', id: 2002 },
      ],
    });
  }

  async getTeamMembers(_org: string, _teamSlug: string): Promise<GitHubApiResponse> {
    return this.response({
      members: [
        { login: 'dev-charlie', id: 1003, role: 'member' },
        { login: 'dev-diana', id: 1004, role: 'member' },
      ],
    });
  }

  async getAuditLog(_org: string): Promise<GitHubApiResponse> {
    const now = Date.now();
    return this.response({
      entries: [
        { action: 'repo.create', actor: 'cto-alice', created_at: new Date(now - 86400000).toISOString(), repo: 'acme-corp/new-service' },
        { action: 'team.add_member', actor: 'lead-bob', created_at: new Date(now - 172800000).toISOString(), team: 'engineering', user: 'dev-evan' },
        { action: 'org.update_member_repository_permission', actor: 'cto-alice', created_at: new Date(now - 259200000).toISOString() },
        { action: 'protected_branch.create', actor: 'lead-bob', created_at: new Date(now - 345600000).toISOString(), repo: 'acme-corp/new-service' },
        { action: 'org.invite_member', actor: 'security-grace', created_at: new Date(now - 2592000000).toISOString(), user: 'contractor-henry' },
        { action: 'repo.access', actor: 'auditor-iris', created_at: new Date(now - 7776000000).toISOString(), repo: 'acme-corp/backend-api' },
      ],
    });
  }

  async listSecretScanningAlerts(_owner: string, repo: string): Promise<GitHubApiResponse> {
    if (repo === 'infrastructure') {
      return this.response({
        alerts: [
          {
            number: 1,
            state: 'open',
            secret_type: 'aws_access_key_id',
            secret_type_display_name: 'AWS Access Key ID',
            created_at: new Date(Date.now() - 86400000).toISOString(),
          },
        ],
      });
    }
    return this.response({ alerts: [] });
  }

  async listDependabotAlerts(_owner: string, repo: string): Promise<GitHubApiResponse> {
    if (repo === 'frontend-app') {
      return this.response({
        alerts: [
          {
            number: 42,
            state: 'open',
            dependency: { package: { name: 'lodash', ecosystem: 'npm' }, manifest_path: 'package-lock.json' },
            security_advisory: { severity: 'critical', summary: 'Prototype Pollution in lodash', ghsa_id: 'GHSA-jf85-cpcp-j695' },
            created_at: new Date(Date.now() - 604800000).toISOString(),
          },
          {
            number: 43,
            state: 'open',
            dependency: { package: { name: 'express', ecosystem: 'npm' }, manifest_path: 'package-lock.json' },
            security_advisory: { severity: 'high', summary: 'Open Redirect in express', ghsa_id: 'GHSA-rv95-896h-c2yt' },
            created_at: new Date(Date.now() - 259200000).toISOString(),
          },
        ],
      });
    }
    return this.response({ alerts: [] });
  }

  async getSecuritySettings(_owner: string, repo: string): Promise<GitHubApiResponse> {
    if (repo === 'infrastructure') {
      return this.response({
        secret_scanning_enabled: true,
        secret_scanning_push_protection_enabled: false,
        dependabot_alerts_enabled: true,
        dependabot_security_updates_enabled: false,
      });
    }
    return this.response({
      secret_scanning_enabled: true,
      secret_scanning_push_protection_enabled: true,
      dependabot_alerts_enabled: true,
      dependabot_security_updates_enabled: true,
    });
  }
}
