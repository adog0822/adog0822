// =============================================================================
// LoxeAI — AWS Security Scanner
// Collects SOC 2 compliance evidence via read-only AWS API calls
// =============================================================================

import {
  type ApiCallRecord,
  type AwsCredentials,
  type EvidenceItem,
  type EvidenceSeverity,
  type EvidenceStatus,
  type Soc2ControlId,
  type SourceEvidenceTrace,
  type ScanResult,
} from '../../types/index';

// ---------------------------------------------------------------------------
// Crypto helpers
// ---------------------------------------------------------------------------

/**
 * Compute a SHA-256 hex digest of a string.
 * Uses the Web Crypto API when available, otherwise falls back to Node.js crypto.
 */
async function sha256(data: string): Promise<string> {
  if (typeof globalThis.crypto !== 'undefined' && globalThis.crypto.subtle) {
    const buf = new TextEncoder().encode(data);
    const hash = await globalThis.crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  // Node.js fallback
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createHash } = await import('crypto');
  return createHash('sha256').update(data).digest('hex');
}

function generateId(prefix: string): string {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).substring(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

// ---------------------------------------------------------------------------
// AWS Client Interface — abstracts the AWS SDK
// ---------------------------------------------------------------------------

/** Generic AWS API response envelope */
export interface AwsApiResponse {
  data: Record<string, unknown>;
  requestId: string;
  httpStatus: number;
}

/**
 * Abstraction over AWS SDK calls.
 * Each method corresponds to a single AWS API operation.
 * Implementations may hit the real SDK or return mock data.
 */
export interface AwsClient {
  // STS
  assumeRole(roleArn: string, externalId: string, sessionName: string): Promise<AwsApiResponse>;

  // IAM
  listUsers(): Promise<AwsApiResponse>;
  listMfaDevices(userName: string): Promise<AwsApiResponse>;
  getLoginProfile(userName: string): Promise<AwsApiResponse>;
  listAccessKeys(userName: string): Promise<AwsApiResponse>;
  getAccountPasswordPolicy(): Promise<AwsApiResponse>;
  listPolicies(onlyAttached: boolean): Promise<AwsApiResponse>;
  getPolicyVersion(policyArn: string, versionId: string): Promise<AwsApiResponse>;

  // CloudTrail
  describeTrails(): Promise<AwsApiResponse>;
  getTrailStatus(trailArn: string): Promise<AwsApiResponse>;

  // S3
  listBuckets(): Promise<AwsApiResponse>;
  getBucketEncryption(bucket: string): Promise<AwsApiResponse>;
  getPublicAccessBlock(bucket: string): Promise<AwsApiResponse>;
  getBucketVersioning(bucket: string): Promise<AwsApiResponse>;
  getBucketLogging(bucket: string): Promise<AwsApiResponse>;

  // VPC / EC2
  describeSecurityGroups(): Promise<AwsApiResponse>;
  describeNetworkAcls(): Promise<AwsApiResponse>;
  describeFlowLogs(): Promise<AwsApiResponse>;
  describeVpcs(): Promise<AwsApiResponse>;

  // RDS
  describeDbInstances(): Promise<AwsApiResponse>;

  // KMS
  listKeys(): Promise<AwsApiResponse>;
  describeKey(keyId: string): Promise<AwsApiResponse>;
  getKeyRotationStatus(keyId: string): Promise<AwsApiResponse>;
  listKeyPolicies(keyId: string): Promise<AwsApiResponse>;

  // GuardDuty
  listDetectors(): Promise<AwsApiResponse>;
  getDetector(detectorId: string): Promise<AwsApiResponse>;

  // AWS Config
  describeConfigurationRecorders(): Promise<AwsApiResponse>;
  describeConfigurationRecorderStatus(): Promise<AwsApiResponse>;
  describeDeliveryChannels(): Promise<AwsApiResponse>;

  // AWS Backup
  listBackupPlans(): Promise<AwsApiResponse>;
  getBackupPlan(backupPlanId: string): Promise<AwsApiResponse>;
  listBackupVaults(): Promise<AwsApiResponse>;
}

// ---------------------------------------------------------------------------
// API Call Recorder
// ---------------------------------------------------------------------------

class ApiCallTracker {
  private calls: ApiCallRecord[] = [];

  record(
    service: string,
    operation: string,
    response: AwsApiResponse,
    region: string,
    responseSha256: string,
  ): void {
    this.calls.push({
      service,
      operation,
      timestamp: new Date().toISOString(),
      requestId: response.requestId,
      responseSha256,
      httpStatus: response.httpStatus,
      region,
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

  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24h TTL

  return {
    id: generateId('ev'),
    source: 'aws',
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
// AWS Scanner — 10 scan functions
// ---------------------------------------------------------------------------

export class AwsScanner {
  private client: AwsClient;
  private credentials: AwsCredentials;
  private integrationId: string;

  constructor(client: AwsClient, credentials: AwsCredentials, integrationId: string) {
    this.client = client;
    this.credentials = credentials;
    this.integrationId = integrationId;
  }

  /** Run all scans and return aggregated results */
  async runAllScans(): Promise<ScanResult[]> {
    const scanFns: Array<() => Promise<ScanResult>> = [
      () => this.scanIamUsers(),
      () => this.scanIamPolicies(),
      () => this.scanCloudTrail(),
      () => this.scanS3Buckets(),
      () => this.scanVpcConfig(),
      () => this.scanRdsInstances(),
      () => this.scanKmsKeys(),
      () => this.scanGuardDuty(),
      () => this.scanConfig(),
      () => this.scanBackups(),
    ];
    const results: ScanResult[] = [];
    for (const fn of scanFns) {
      try {
        results.push(await fn());
      } catch (err) {
        // Individual scan failures don't abort the whole run
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
  // 1. IAM Users — MFA, password policies, access key age
  // -----------------------------------------------------------------------
  async scanIamUsers(): Promise<ScanResult> {
    const scanKey = 'iam-users';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      // List all IAM users
      const usersResp = await this.client.listUsers();
      const usersHash = await sha256(JSON.stringify(usersResp.data));
      tracker.record('iam', 'ListUsers', usersResp, this.credentials.region, usersHash);

      const users = (usersResp.data.Users as Array<Record<string, unknown>>) ?? [];

      // Check password policy
      const passwordPolicyResp = await this.client.getAccountPasswordPolicy();
      const ppHash = await sha256(JSON.stringify(passwordPolicyResp.data));
      tracker.record('iam', 'GetAccountPasswordPolicy', passwordPolicyResp, this.credentials.region, ppHash);

      const policy = passwordPolicyResp.data.PasswordPolicy as Record<string, unknown> | undefined;
      const policyItem = await buildEvidenceItem(
        {
          scanType: scanKey,
          title: 'IAM Password Policy',
          description: policy
            ? `Password policy: min length ${policy.MinimumPasswordLength}, require symbols=${policy.RequireSymbols}, require numbers=${policy.RequireNumbers}, max age=${policy.MaxPasswordAge} days`
            : 'No account password policy is configured.',
          controls: ['CC6.1', 'CC6.2'],
          status: policy && (policy.MinimumPasswordLength as number) >= 14 ? 'pass' : 'fail',
          severity: policy ? 'medium' : 'high',
          resource: `arn:aws:iam::${this.credentials.roleArn.split(':')[4]}:account-password-policy`,
          rawData: passwordPolicyResp.data,
          remediation: 'Configure an IAM password policy requiring at least 14 characters, symbols, numbers, and uppercase letters. Set MaxPasswordAge to 90 days or less.',
          auditorQuestions: [
            'What is the minimum password length enforced?',
            'Is password reuse prevention enabled?',
            'How often are users required to rotate passwords?',
          ],
        },
        tracker,
        this.integrationId,
        startedAt,
        previousHash,
      );
      previousHash = policyItem.sourceTrace.evidenceHash;
      evidence.push(policyItem);

      // Check each user for MFA and access key age
      for (const user of users) {
        const userName = user.UserName as string;
        const userArn = user.Arn as string;

        // MFA devices
        const mfaResp = await this.client.listMfaDevices(userName);
        const mfaHash = await sha256(JSON.stringify(mfaResp.data));
        tracker.record('iam', 'ListMFADevices', mfaResp, this.credentials.region, mfaHash);

        const mfaDevices = (mfaResp.data.MFADevices as Array<unknown>) ?? [];
        const hasMfa = mfaDevices.length > 0;

        const mfaItem = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `MFA Status for ${userName}`,
            description: hasMfa
              ? `User ${userName} has ${mfaDevices.length} MFA device(s) configured.`
              : `User ${userName} does NOT have MFA enabled.`,
            controls: ['CC6.1', 'CC6.2'],
            status: hasMfa ? 'pass' : 'fail',
            severity: hasMfa ? 'info' : 'critical',
            resource: userArn,
            rawData: { userName, mfaDevices: mfaResp.data.MFADevices },
            remediation: hasMfa
              ? 'No action needed.'
              : `Enable MFA for user ${userName}. Use a hardware TOTP device or virtual MFA app.`,
            auditorQuestions: [
              `Is ${userName} a human user or a service account?`,
              'What type of MFA device is configured?',
              'Is MFA enforced via IAM policy?',
            ],
          },
          tracker,
          this.integrationId,
          startedAt,
          previousHash,
        );
        previousHash = mfaItem.sourceTrace.evidenceHash;
        evidence.push(mfaItem);

        // Access keys
        const keysResp = await this.client.listAccessKeys(userName);
        const keysHash = await sha256(JSON.stringify(keysResp.data));
        tracker.record('iam', 'ListAccessKeys', keysResp, this.credentials.region, keysHash);

        const accessKeys = (keysResp.data.AccessKeyMetadata as Array<Record<string, unknown>>) ?? [];
        for (const key of accessKeys) {
          const createDate = new Date(key.CreateDate as string);
          const ageInDays = Math.floor((Date.now() - createDate.getTime()) / (1000 * 60 * 60 * 24));
          const isOld = ageInDays > 90;
          const isActive = key.Status === 'Active';

          const keyItem = await buildEvidenceItem(
            {
              scanType: scanKey,
              title: `Access Key Age for ${userName}`,
              description: `Access key ${key.AccessKeyId} is ${ageInDays} days old (status: ${key.Status}).`,
              controls: ['CC6.1', 'CC6.3'],
              status: isOld && isActive ? 'fail' : 'pass',
              severity: isOld && isActive ? 'high' : 'info',
              resource: userArn,
              rawData: { userName, accessKeyId: key.AccessKeyId, ageInDays, status: key.Status, createDate: key.CreateDate },
              remediation: isOld && isActive
                ? `Rotate access key ${key.AccessKeyId} for user ${userName}. Keys should be rotated every 90 days.`
                : 'No action needed.',
              auditorQuestions: [
                'What is the organization policy for access key rotation?',
                'Is this key used by an automated process?',
                'Are there monitoring alerts for access key usage?',
              ],
            },
            tracker,
            this.integrationId,
            startedAt,
            previousHash,
          );
          previousHash = keyItem.sourceTrace.evidenceHash;
          evidence.push(keyItem);
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

  // -----------------------------------------------------------------------
  // 2. IAM Policies — overly permissive, admin access
  // -----------------------------------------------------------------------
  async scanIamPolicies(): Promise<ScanResult> {
    const scanKey = 'iam-policies';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const policiesResp = await this.client.listPolicies(true);
      const pHash = await sha256(JSON.stringify(policiesResp.data));
      tracker.record('iam', 'ListPolicies', policiesResp, this.credentials.region, pHash);

      const policies = (policiesResp.data.Policies as Array<Record<string, unknown>>) ?? [];

      for (const pol of policies) {
        const policyArn = pol.Arn as string;
        const policyName = pol.PolicyName as string;
        const versionId = pol.DefaultVersionId as string;

        const versionResp = await this.client.getPolicyVersion(policyArn, versionId);
        const vHash = await sha256(JSON.stringify(versionResp.data));
        tracker.record('iam', 'GetPolicyVersion', versionResp, this.credentials.region, vHash);

        const document = versionResp.data.PolicyVersion as Record<string, unknown> | undefined;
        const docStr = JSON.stringify(document ?? {});
        const hasWildcardAction = docStr.includes('"Action":"*"') || docStr.includes('"Action": "*"');
        const hasWildcardResource = docStr.includes('"Resource":"*"') || docStr.includes('"Resource": "*"');
        const isOverlyPermissive = hasWildcardAction && hasWildcardResource;

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `IAM Policy: ${policyName}`,
            description: isOverlyPermissive
              ? `Policy ${policyName} grants wildcard Action and Resource ("*:*"), providing full administrator access.`
              : `Policy ${policyName} follows least-privilege principles.`,
            controls: ['CC6.1', 'CC5.2'],
            status: isOverlyPermissive ? 'fail' : 'pass',
            severity: isOverlyPermissive ? 'critical' : 'info',
            resource: policyArn,
            rawData: { policyName, policyArn, document },
            remediation: isOverlyPermissive
              ? `Replace ${policyName} with scoped policies following least-privilege. Avoid Action:"*" and Resource:"*" in production.`
              : 'No action needed.',
            auditorQuestions: [
              'Which users/roles is this policy attached to?',
              'Is there a periodic access review process?',
              'Are there compensating controls for administrative access?',
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
  // 3. CloudTrail — enabled, multi-region, log validation
  // -----------------------------------------------------------------------
  async scanCloudTrail(): Promise<ScanResult> {
    const scanKey = 'cloudtrail';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const trailsResp = await this.client.describeTrails();
      const tHash = await sha256(JSON.stringify(trailsResp.data));
      tracker.record('cloudtrail', 'DescribeTrails', trailsResp, this.credentials.region, tHash);

      const trails = (trailsResp.data.trailList as Array<Record<string, unknown>>) ?? [];

      if (trails.length === 0) {
        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: 'No CloudTrail Trails Configured',
            description: 'No CloudTrail trails were found. API activity is not being logged.',
            controls: ['CC7.2', 'CC4.1'],
            status: 'fail',
            severity: 'critical',
            resource: `arn:aws:cloudtrail:${this.credentials.region}:account`,
            rawData: { trails: [] },
            remediation: 'Create a multi-region CloudTrail trail with log file validation and S3 encryption enabled.',
            auditorQuestions: [
              'How is API activity currently monitored?',
              'Is there an alternative audit logging mechanism?',
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

      for (const trail of trails) {
        const trailArn = trail.TrailARN as string;
        const trailName = trail.Name as string;

        const statusResp = await this.client.getTrailStatus(trailArn);
        const sHash = await sha256(JSON.stringify(statusResp.data));
        tracker.record('cloudtrail', 'GetTrailStatus', statusResp, this.credentials.region, sHash);

        const isMultiRegion = trail.IsMultiRegionTrail as boolean;
        const hasLogValidation = trail.LogFileValidationEnabled as boolean;
        const isLogging = statusResp.data.IsLogging as boolean;
        const hasEncryption = !!trail.KmsKeyId;

        const issues: string[] = [];
        if (!isMultiRegion) issues.push('not multi-region');
        if (!hasLogValidation) issues.push('log file validation disabled');
        if (!isLogging) issues.push('logging is currently stopped');
        if (!hasEncryption) issues.push('not encrypted with KMS');

        const status: EvidenceStatus = issues.length === 0 ? 'pass' : 'fail';
        const severity: EvidenceSeverity =
          !isLogging ? 'critical' : issues.length > 0 ? 'high' : 'info';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `CloudTrail: ${trailName}`,
            description:
              issues.length === 0
                ? `Trail ${trailName} is properly configured with multi-region logging, file validation, and KMS encryption.`
                : `Trail ${trailName} has issues: ${issues.join(', ')}.`,
            controls: ['CC7.2', 'CC4.1'],
            status,
            severity,
            resource: trailArn,
            rawData: { trail, status: statusResp.data },
            remediation:
              issues.length === 0
                ? 'No action needed.'
                : `Fix the following: ${issues.join('; ')}. Enable multi-region, log validation, and KMS encryption.`,
            auditorQuestions: [
              'How long are CloudTrail logs retained?',
              'Who has access to the CloudTrail S3 bucket?',
              'Are CloudTrail logs forwarded to a SIEM?',
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
  // 4. S3 Buckets — encryption, public access, versioning, logging
  // -----------------------------------------------------------------------
  async scanS3Buckets(): Promise<ScanResult> {
    const scanKey = 's3-buckets';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const bucketsResp = await this.client.listBuckets();
      const bHash = await sha256(JSON.stringify(bucketsResp.data));
      tracker.record('s3', 'ListBuckets', bucketsResp, this.credentials.region, bHash);

      const buckets = (bucketsResp.data.Buckets as Array<Record<string, unknown>>) ?? [];

      for (const bucket of buckets) {
        const bucketName = bucket.Name as string;
        const issues: string[] = [];

        // Encryption
        const encResp = await this.client.getBucketEncryption(bucketName);
        const encHash = await sha256(JSON.stringify(encResp.data));
        tracker.record('s3', 'GetBucketEncryption', encResp, this.credentials.region, encHash);
        const hasEncryption = !!encResp.data.ServerSideEncryptionConfiguration;
        if (!hasEncryption) issues.push('server-side encryption not enabled');

        // Public access block
        const pubResp = await this.client.getPublicAccessBlock(bucketName);
        const pubHash = await sha256(JSON.stringify(pubResp.data));
        tracker.record('s3', 'GetPublicAccessBlock', pubResp, this.credentials.region, pubHash);
        const pubConfig = pubResp.data.PublicAccessBlockConfiguration as Record<string, boolean> | undefined;
        const allBlocked =
          pubConfig?.BlockPublicAcls &&
          pubConfig?.IgnorePublicAcls &&
          pubConfig?.BlockPublicPolicy &&
          pubConfig?.RestrictPublicBuckets;
        if (!allBlocked) issues.push('public access not fully blocked');

        // Versioning
        const verResp = await this.client.getBucketVersioning(bucketName);
        const verHash = await sha256(JSON.stringify(verResp.data));
        tracker.record('s3', 'GetBucketVersioning', verResp, this.credentials.region, verHash);
        const versioningEnabled = verResp.data.Status === 'Enabled';
        if (!versioningEnabled) issues.push('versioning not enabled');

        // Logging
        const logResp = await this.client.getBucketLogging(bucketName);
        const logHash = await sha256(JSON.stringify(logResp.data));
        tracker.record('s3', 'GetBucketLogging', logResp, this.credentials.region, logHash);
        const hasLogging = !!logResp.data.LoggingEnabled;
        if (!hasLogging) issues.push('access logging not enabled');

        const status: EvidenceStatus = issues.length === 0 ? 'pass' : 'fail';
        const severity: EvidenceSeverity =
          !allBlocked ? 'critical' : issues.length > 0 ? 'high' : 'info';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `S3 Bucket: ${bucketName}`,
            description:
              issues.length === 0
                ? `Bucket ${bucketName} is properly configured with encryption, public access blocks, versioning, and logging.`
                : `Bucket ${bucketName} has issues: ${issues.join(', ')}.`,
            controls: ['CC6.7', 'CC6.1'],
            status,
            severity,
            resource: `arn:aws:s3:::${bucketName}`,
            rawData: {
              bucketName,
              encryption: encResp.data,
              publicAccessBlock: pubResp.data,
              versioning: verResp.data,
              logging: logResp.data,
            },
            remediation:
              issues.length === 0
                ? 'No action needed.'
                : `Fix: ${issues.join('; ')}. Enable SSE-S3 or SSE-KMS encryption, block all public access, enable versioning, and configure access logging.`,
            auditorQuestions: [
              'What data classification does this bucket hold?',
              'Is there a lifecycle policy for object expiration?',
              'Are S3 access logs monitored for anomalies?',
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
  // 5. VPC Config — security groups, NACLs, flow logs
  // -----------------------------------------------------------------------
  async scanVpcConfig(): Promise<ScanResult> {
    const scanKey = 'vpc-config';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      // VPCs
      const vpcsResp = await this.client.describeVpcs();
      const vpcsHash = await sha256(JSON.stringify(vpcsResp.data));
      tracker.record('ec2', 'DescribeVpcs', vpcsResp, this.credentials.region, vpcsHash);

      // Security Groups
      const sgResp = await this.client.describeSecurityGroups();
      const sgHash = await sha256(JSON.stringify(sgResp.data));
      tracker.record('ec2', 'DescribeSecurityGroups', sgResp, this.credentials.region, sgHash);

      const securityGroups = (sgResp.data.SecurityGroups as Array<Record<string, unknown>>) ?? [];

      for (const sg of securityGroups) {
        const sgId = sg.GroupId as string;
        const sgName = sg.GroupName as string;
        const ingressRules = (sg.IpPermissions as Array<Record<string, unknown>>) ?? [];

        const openToWorld = ingressRules.some((rule) => {
          const ipRanges = (rule.IpRanges as Array<Record<string, string>>) ?? [];
          return ipRanges.some((range) => range.CidrIp === '0.0.0.0/0');
        });

        const openSshOrRdp = ingressRules.some((rule) => {
          const fromPort = rule.FromPort as number;
          const ipRanges = (rule.IpRanges as Array<Record<string, string>>) ?? [];
          const isOpenToWorld = ipRanges.some((range) => range.CidrIp === '0.0.0.0/0');
          return isOpenToWorld && (fromPort === 22 || fromPort === 3389);
        });

        const status: EvidenceStatus = openSshOrRdp ? 'fail' : openToWorld ? 'warning' : 'pass';
        const severity: EvidenceSeverity = openSshOrRdp ? 'critical' : openToWorld ? 'high' : 'info';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `Security Group: ${sgName} (${sgId})`,
            description: openSshOrRdp
              ? `Security group ${sgName} allows SSH/RDP access from 0.0.0.0/0.`
              : openToWorld
                ? `Security group ${sgName} has rules open to 0.0.0.0/0.`
                : `Security group ${sgName} has no overly permissive inbound rules.`,
            controls: ['CC6.6', 'CC6.1'],
            status,
            severity,
            resource: sgId,
            rawData: sg,
            remediation: openSshOrRdp
              ? `Restrict SSH (22) and RDP (3389) in ${sgName} to specific IP ranges or use AWS Systems Manager Session Manager.`
              : openToWorld
                ? `Review rules in ${sgName} that allow 0.0.0.0/0. Restrict to known IP ranges.`
                : 'No action needed.',
            auditorQuestions: [
              'What workloads use this security group?',
              'Is there a periodic review of security group rules?',
              'Are there compensating controls (WAF, bastion hosts)?',
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

      // Flow Logs
      const flowResp = await this.client.describeFlowLogs();
      const flowHash = await sha256(JSON.stringify(flowResp.data));
      tracker.record('ec2', 'DescribeFlowLogs', flowResp, this.credentials.region, flowHash);

      const flowLogs = (flowResp.data.FlowLogs as Array<Record<string, unknown>>) ?? [];
      const vpcs = (vpcsResp.data.Vpcs as Array<Record<string, string>>) ?? [];
      const vpcIds = vpcs.map((v) => v.VpcId);
      const flowLogVpcIds = new Set(flowLogs.map((fl) => fl.ResourceId as string));

      for (const vpcId of vpcIds) {
        const hasFlowLog = flowLogVpcIds.has(vpcId);
        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `VPC Flow Logs: ${vpcId}`,
            description: hasFlowLog
              ? `VPC ${vpcId} has flow logs enabled.`
              : `VPC ${vpcId} does NOT have flow logs enabled.`,
            controls: ['CC6.6', 'CC6.1'],
            status: hasFlowLog ? 'pass' : 'fail',
            severity: hasFlowLog ? 'info' : 'high',
            resource: vpcId,
            rawData: { vpcId, hasFlowLog, flowLogs: flowLogs.filter((fl) => fl.ResourceId === vpcId) },
            remediation: hasFlowLog
              ? 'No action needed.'
              : `Enable VPC Flow Logs for ${vpcId} and deliver to CloudWatch Logs or S3.`,
            auditorQuestions: [
              'Where are flow logs delivered?',
              'How long are flow logs retained?',
              'Are flow logs analyzed for suspicious traffic?',
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
  // 6. RDS Instances — encryption, backup, public access
  // -----------------------------------------------------------------------
  async scanRdsInstances(): Promise<ScanResult> {
    const scanKey = 'rds-instances';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const rdsResp = await this.client.describeDbInstances();
      const rdsHash = await sha256(JSON.stringify(rdsResp.data));
      tracker.record('rds', 'DescribeDBInstances', rdsResp, this.credentials.region, rdsHash);

      const instances = (rdsResp.data.DBInstances as Array<Record<string, unknown>>) ?? [];

      for (const db of instances) {
        const dbId = db.DBInstanceIdentifier as string;
        const dbArn = db.DBInstanceArn as string;
        const issues: string[] = [];

        const encrypted = db.StorageEncrypted as boolean;
        if (!encrypted) issues.push('storage not encrypted');

        const publiclyAccessible = db.PubliclyAccessible as boolean;
        if (publiclyAccessible) issues.push('publicly accessible');

        const backupRetention = db.BackupRetentionPeriod as number;
        if (backupRetention < 7) issues.push(`backup retention only ${backupRetention} days (minimum 7 recommended)`);

        const multiAz = db.MultiAZ as boolean;
        if (!multiAz) issues.push('not configured for Multi-AZ');

        const deletionProtection = db.DeletionProtection as boolean;
        if (!deletionProtection) issues.push('deletion protection not enabled');

        const status: EvidenceStatus = issues.length === 0 ? 'pass' : 'fail';
        const severity: EvidenceSeverity =
          publiclyAccessible || !encrypted ? 'critical' : issues.length > 0 ? 'high' : 'info';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `RDS Instance: ${dbId}`,
            description:
              issues.length === 0
                ? `RDS instance ${dbId} is properly configured with encryption, private access, adequate backups, and Multi-AZ.`
                : `RDS instance ${dbId} has issues: ${issues.join(', ')}.`,
            controls: ['CC6.7', 'CC7.5'],
            status,
            severity,
            resource: dbArn,
            rawData: db,
            remediation:
              issues.length === 0
                ? 'No action needed.'
                : `Fix: ${issues.join('; ')}. Enable encryption at rest, disable public access, set backup retention >= 7 days, enable Multi-AZ and deletion protection.`,
            auditorQuestions: [
              'What type of data is stored in this database?',
              'Is encryption in transit (TLS) enforced?',
              'How are database credentials managed?',
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
  // 7. KMS Keys — rotation, usage policies
  // -----------------------------------------------------------------------
  async scanKmsKeys(): Promise<ScanResult> {
    const scanKey = 'kms-keys';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const keysResp = await this.client.listKeys();
      const kHash = await sha256(JSON.stringify(keysResp.data));
      tracker.record('kms', 'ListKeys', keysResp, this.credentials.region, kHash);

      const keys = (keysResp.data.Keys as Array<Record<string, string>>) ?? [];

      for (const key of keys) {
        const keyId = key.KeyId;
        const keyArn = key.KeyArn;

        // Describe key
        const descResp = await this.client.describeKey(keyId);
        const descHash = await sha256(JSON.stringify(descResp.data));
        tracker.record('kms', 'DescribeKey', descResp, this.credentials.region, descHash);

        const meta = descResp.data.KeyMetadata as Record<string, unknown>;
        const keyManager = meta.KeyManager as string;
        const keyState = meta.KeyState as string;

        // Skip AWS-managed keys
        if (keyManager === 'AWS') continue;

        // Rotation status
        const rotResp = await this.client.getKeyRotationStatus(keyId);
        const rotHash = await sha256(JSON.stringify(rotResp.data));
        tracker.record('kms', 'GetKeyRotationStatus', rotResp, this.credentials.region, rotHash);

        const rotationEnabled = rotResp.data.KeyRotationEnabled as boolean;
        const issues: string[] = [];
        if (!rotationEnabled) issues.push('automatic key rotation not enabled');
        if (keyState !== 'Enabled') issues.push(`key state is ${keyState}`);

        const status: EvidenceStatus = issues.length === 0 ? 'pass' : 'fail';
        const severity: EvidenceSeverity = !rotationEnabled ? 'high' : 'info';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `KMS Key: ${keyId}`,
            description:
              issues.length === 0
                ? `KMS key ${keyId} has automatic rotation enabled and is in Enabled state.`
                : `KMS key ${keyId} has issues: ${issues.join(', ')}.`,
            controls: ['CC6.7'],
            status,
            severity,
            resource: keyArn,
            rawData: { keyMetadata: meta, rotationEnabled },
            remediation:
              issues.length === 0
                ? 'No action needed.'
                : `Enable automatic key rotation for ${keyId}. Review key policy for least-privilege access.`,
            auditorQuestions: [
              'What services use this KMS key?',
              'Who has access to manage this key?',
              'Is there a key management policy documented?',
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
  // 8. GuardDuty — detection service enabled
  // -----------------------------------------------------------------------
  async scanGuardDuty(): Promise<ScanResult> {
    const scanKey = 'guardduty';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const detectorsResp = await this.client.listDetectors();
      const dHash = await sha256(JSON.stringify(detectorsResp.data));
      tracker.record('guardduty', 'ListDetectors', detectorsResp, this.credentials.region, dHash);

      const detectorIds = (detectorsResp.data.DetectorIds as string[]) ?? [];

      if (detectorIds.length === 0) {
        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: 'GuardDuty Not Enabled',
            description: 'Amazon GuardDuty is not enabled in this region. Threat detection is not active.',
            controls: ['CC7.1'],
            status: 'fail',
            severity: 'critical',
            resource: `arn:aws:guardduty:${this.credentials.region}:account`,
            rawData: { detectorIds: [] },
            remediation: 'Enable Amazon GuardDuty in all regions. Configure findings export to S3 and CloudWatch Events.',
            auditorQuestions: [
              'Is there an alternative threat detection mechanism?',
              'Is GuardDuty enabled in other regions?',
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

      for (const detectorId of detectorIds) {
        const detResp = await this.client.getDetector(detectorId);
        const detHash = await sha256(JSON.stringify(detResp.data));
        tracker.record('guardduty', 'GetDetector', detResp, this.credentials.region, detHash);

        const detStatus = detResp.data.Status as string;
        const findingPublishingFrequency = detResp.data.FindingPublishingFrequency as string;
        const isEnabled = detStatus === 'ENABLED';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `GuardDuty Detector: ${detectorId}`,
            description: isEnabled
              ? `GuardDuty detector ${detectorId} is enabled with ${findingPublishingFrequency} finding frequency.`
              : `GuardDuty detector ${detectorId} is ${detStatus}.`,
            controls: ['CC7.1'],
            status: isEnabled ? 'pass' : 'fail',
            severity: isEnabled ? 'info' : 'critical',
            resource: `arn:aws:guardduty:${this.credentials.region}:detector/${detectorId}`,
            rawData: detResp.data,
            remediation: isEnabled
              ? 'No action needed.'
              : `Re-enable GuardDuty detector ${detectorId}.`,
            auditorQuestions: [
              'How are GuardDuty findings triaged?',
              'Is there an automated response to high-severity findings?',
              'Are findings integrated with your incident response process?',
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
  // 9. AWS Config — recording, delivery channels
  // -----------------------------------------------------------------------
  async scanConfig(): Promise<ScanResult> {
    const scanKey = 'aws-config';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const recordersResp = await this.client.describeConfigurationRecorders();
      const rHash = await sha256(JSON.stringify(recordersResp.data));
      tracker.record('config', 'DescribeConfigurationRecorders', recordersResp, this.credentials.region, rHash);

      const statusResp = await this.client.describeConfigurationRecorderStatus();
      const sHash = await sha256(JSON.stringify(statusResp.data));
      tracker.record('config', 'DescribeConfigurationRecorderStatus', statusResp, this.credentials.region, sHash);

      const channelsResp = await this.client.describeDeliveryChannels();
      const cHash = await sha256(JSON.stringify(channelsResp.data));
      tracker.record('config', 'DescribeDeliveryChannels', channelsResp, this.credentials.region, cHash);

      const recorders = (recordersResp.data.ConfigurationRecorders as Array<Record<string, unknown>>) ?? [];
      const statuses = (statusResp.data.ConfigurationRecordersStatus as Array<Record<string, unknown>>) ?? [];
      const channels = (channelsResp.data.DeliveryChannels as Array<Record<string, unknown>>) ?? [];

      if (recorders.length === 0) {
        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: 'AWS Config Not Enabled',
            description: 'No AWS Config recorder found. Configuration changes are not being tracked.',
            controls: ['CC4.1', 'CC7.2'],
            status: 'fail',
            severity: 'critical',
            resource: `arn:aws:config:${this.credentials.region}:account`,
            rawData: { recorders: [], statuses: [], channels: [] },
            remediation: 'Enable AWS Config with a recorder that captures all resource types. Configure a delivery channel to S3.',
            auditorQuestions: [
              'How are configuration changes currently tracked?',
              'Is there an alternative configuration management database?',
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

      for (const recorder of recorders) {
        const recorderName = recorder.name as string;
        const recordingGroup = recorder.recordingGroup as Record<string, unknown> | undefined;
        const allSupported = recordingGroup?.allSupported as boolean;
        const recorderStatus = statuses.find((s) => s.name === recorderName);
        const isRecording = recorderStatus?.recording as boolean;

        const issues: string[] = [];
        if (!isRecording) issues.push('recorder is not currently recording');
        if (!allSupported) issues.push('not recording all supported resource types');
        if (channels.length === 0) issues.push('no delivery channel configured');

        const status: EvidenceStatus = issues.length === 0 ? 'pass' : 'fail';
        const severity: EvidenceSeverity = !isRecording ? 'critical' : issues.length > 0 ? 'high' : 'info';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `AWS Config Recorder: ${recorderName}`,
            description:
              issues.length === 0
                ? `AWS Config recorder ${recorderName} is active, recording all resource types with a delivery channel configured.`
                : `AWS Config recorder ${recorderName} has issues: ${issues.join(', ')}.`,
            controls: ['CC4.1', 'CC7.2'],
            status,
            severity,
            resource: `arn:aws:config:${this.credentials.region}:recorder/${recorderName}`,
            rawData: { recorder, status: recorderStatus, channels },
            remediation:
              issues.length === 0
                ? 'No action needed.'
                : `Fix: ${issues.join('; ')}. Start the recorder, enable all resource types, and configure a delivery channel.`,
            auditorQuestions: [
              'How long are Config snapshots retained?',
              'Are Config rules set up to evaluate compliance?',
              'Is conformance pack used for SOC 2 controls?',
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
  // 10. Backups — backup plans, retention policies
  // -----------------------------------------------------------------------
  async scanBackups(): Promise<ScanResult> {
    const scanKey = 'backups';
    const startedAt = new Date().toISOString();
    const start = Date.now();
    const tracker = new ApiCallTracker();
    const evidence: EvidenceItem[] = [];
    let previousHash = '';

    try {
      const plansResp = await this.client.listBackupPlans();
      const pHash = await sha256(JSON.stringify(plansResp.data));
      tracker.record('backup', 'ListBackupPlans', plansResp, this.credentials.region, pHash);

      const plans = (plansResp.data.BackupPlansList as Array<Record<string, unknown>>) ?? [];

      if (plans.length === 0) {
        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: 'No AWS Backup Plans Found',
            description: 'No AWS Backup plans are configured. Data recovery may not be possible.',
            controls: ['CC7.5'],
            status: 'fail',
            severity: 'critical',
            resource: `arn:aws:backup:${this.credentials.region}:account`,
            rawData: { plans: [] },
            remediation: 'Create AWS Backup plans with appropriate schedules and retention policies for critical resources.',
            auditorQuestions: [
              'How is data backup currently managed?',
              'Is there a documented backup and recovery strategy?',
              'Has a recovery test been performed recently?',
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

      for (const plan of plans) {
        const planId = plan.BackupPlanId as string;
        const planName = plan.BackupPlanName as string;
        const planArn = plan.BackupPlanArn as string;

        const planResp = await this.client.getBackupPlan(planId);
        const planHash = await sha256(JSON.stringify(planResp.data));
        tracker.record('backup', 'GetBackupPlan', planResp, this.credentials.region, planHash);

        const backupPlan = planResp.data.BackupPlan as Record<string, unknown>;
        const rules = (backupPlan?.Rules as Array<Record<string, unknown>>) ?? [];

        const issues: string[] = [];
        if (rules.length === 0) {
          issues.push('no backup rules defined');
        }

        for (const rule of rules) {
          const lifecycle = rule.Lifecycle as Record<string, number> | undefined;
          const retentionDays = lifecycle?.DeleteAfterDays ?? 0;
          if (retentionDays < 30) {
            issues.push(`rule "${rule.RuleName}" retention is only ${retentionDays} days (minimum 30 recommended)`);
          }
        }

        const status: EvidenceStatus = issues.length === 0 ? 'pass' : 'warning';
        const severity: EvidenceSeverity = rules.length === 0 ? 'high' : issues.length > 0 ? 'medium' : 'info';

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `Backup Plan: ${planName}`,
            description:
              issues.length === 0
                ? `Backup plan ${planName} has ${rules.length} rule(s) with adequate retention.`
                : `Backup plan ${planName} has issues: ${issues.join(', ')}.`,
            controls: ['CC7.5'],
            status,
            severity,
            resource: planArn,
            rawData: { planId, planName, backupPlan },
            remediation:
              issues.length === 0
                ? 'No action needed.'
                : `Review and update backup rules: ${issues.join('; ')}. Set retention to at least 30 days.`,
            auditorQuestions: [
              'Which resources are covered by this backup plan?',
              'How often are backup restores tested?',
              'Is cross-region backup configured for disaster recovery?',
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

      // Backup vaults
      const vaultsResp = await this.client.listBackupVaults();
      const vHash = await sha256(JSON.stringify(vaultsResp.data));
      tracker.record('backup', 'ListBackupVaults', vaultsResp, this.credentials.region, vHash);

      const vaults = (vaultsResp.data.BackupVaultList as Array<Record<string, unknown>>) ?? [];
      for (const vault of vaults) {
        const vaultName = vault.BackupVaultName as string;
        const vaultArn = vault.BackupVaultArn as string;
        const encrypted = !!vault.EncryptionKeyArn;

        const item = await buildEvidenceItem(
          {
            scanType: scanKey,
            title: `Backup Vault: ${vaultName}`,
            description: encrypted
              ? `Backup vault ${vaultName} is encrypted with KMS.`
              : `Backup vault ${vaultName} is NOT encrypted with a customer-managed KMS key.`,
            controls: ['CC7.5'],
            status: encrypted ? 'pass' : 'warning',
            severity: encrypted ? 'info' : 'medium',
            resource: vaultArn,
            rawData: vault,
            remediation: encrypted
              ? 'No action needed.'
              : `Configure a customer-managed KMS key for backup vault ${vaultName}.`,
            auditorQuestions: [
              'Who has access to this backup vault?',
              'Is vault lock enabled to prevent deletion?',
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
}

// ---------------------------------------------------------------------------
// Mock AWS Client — realistic sample data for testing
// ---------------------------------------------------------------------------

export class MockAwsClient implements AwsClient {
  private nextRequestId = 1;

  private response(data: Record<string, unknown>): AwsApiResponse {
    return {
      data,
      requestId: `mock-req-${String(this.nextRequestId++).padStart(6, '0')}`,
      httpStatus: 200,
    };
  }

  async assumeRole(_roleArn: string, _externalId: string, _sessionName: string): Promise<AwsApiResponse> {
    return this.response({
      Credentials: {
        AccessKeyId: 'ASIAIOSFODNN7EXAMPLE',
        SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        SessionToken: 'FwoGZXIvYXdzEBYaDH...EXAMPLETOKEN',
        Expiration: new Date(Date.now() + 3600000).toISOString(),
      },
    });
  }

  // --- IAM ---
  async listUsers(): Promise<AwsApiResponse> {
    return this.response({
      Users: [
        {
          UserName: 'admin-user',
          UserId: 'AIDAIOSFODNN7EXAMPLE1',
          Arn: 'arn:aws:iam::123456789012:user/admin-user',
          CreateDate: '2023-01-15T10:30:00Z',
          PasswordLastUsed: '2024-11-01T08:00:00Z',
        },
        {
          UserName: 'dev-user',
          UserId: 'AIDAIOSFODNN7EXAMPLE2',
          Arn: 'arn:aws:iam::123456789012:user/dev-user',
          CreateDate: '2023-06-20T14:00:00Z',
          PasswordLastUsed: '2024-10-28T16:30:00Z',
        },
        {
          UserName: 'ci-bot',
          UserId: 'AIDAIOSFODNN7EXAMPLE3',
          Arn: 'arn:aws:iam::123456789012:user/ci-bot',
          CreateDate: '2023-03-10T09:00:00Z',
        },
      ],
    });
  }

  async listMfaDevices(userName: string): Promise<AwsApiResponse> {
    const mfaMap: Record<string, Array<Record<string, string>>> = {
      'admin-user': [
        { SerialNumber: 'arn:aws:iam::123456789012:mfa/admin-user', UserName: 'admin-user', EnableDate: '2023-01-16T10:00:00Z' },
      ],
      'dev-user': [],
      'ci-bot': [],
    };
    return this.response({ MFADevices: mfaMap[userName] ?? [] });
  }

  async getLoginProfile(userName: string): Promise<AwsApiResponse> {
    if (userName === 'ci-bot') {
      return { data: {}, requestId: `mock-req-${String(this.nextRequestId++).padStart(6, '0')}`, httpStatus: 404 };
    }
    return this.response({
      LoginProfile: { UserName: userName, CreateDate: '2023-01-15T10:30:00Z', PasswordResetRequired: false },
    });
  }

  async listAccessKeys(userName: string): Promise<AwsApiResponse> {
    const keysMap: Record<string, Array<Record<string, string>>> = {
      'admin-user': [
        { AccessKeyId: 'AKIAIOSFODNN7EXAMPLE', Status: 'Active', CreateDate: '2023-01-15T10:30:00Z' },
      ],
      'dev-user': [
        { AccessKeyId: 'AKIAI44QH8DHBEXAMPLE', Status: 'Active', CreateDate: '2024-09-01T14:00:00Z' },
      ],
      'ci-bot': [
        { AccessKeyId: 'AKIAI44QH8DHBEXAMPL2', Status: 'Active', CreateDate: '2023-03-10T09:00:00Z' },
        { AccessKeyId: 'AKIAI44QH8DHBEXAMPL3', Status: 'Inactive', CreateDate: '2022-12-01T09:00:00Z' },
      ],
    };
    return this.response({ AccessKeyMetadata: keysMap[userName] ?? [] });
  }

  async getAccountPasswordPolicy(): Promise<AwsApiResponse> {
    return this.response({
      PasswordPolicy: {
        MinimumPasswordLength: 12,
        RequireSymbols: true,
        RequireNumbers: true,
        RequireUppercaseCharacters: true,
        RequireLowercaseCharacters: true,
        AllowUsersToChangePassword: true,
        MaxPasswordAge: 90,
        PasswordReusePrevention: 12,
        HardExpiry: false,
      },
    });
  }

  async listPolicies(_onlyAttached: boolean): Promise<AwsApiResponse> {
    return this.response({
      Policies: [
        {
          PolicyName: 'AdminFullAccess',
          PolicyId: 'ANPAIOSFODNN7EXAMPLE1',
          Arn: 'arn:aws:iam::123456789012:policy/AdminFullAccess',
          DefaultVersionId: 'v1',
          AttachmentCount: 2,
        },
        {
          PolicyName: 'DeveloperAccess',
          PolicyId: 'ANPAIOSFODNN7EXAMPLE2',
          Arn: 'arn:aws:iam::123456789012:policy/DeveloperAccess',
          DefaultVersionId: 'v3',
          AttachmentCount: 5,
        },
      ],
    });
  }

  async getPolicyVersion(policyArn: string, _versionId: string): Promise<AwsApiResponse> {
    const isAdmin = policyArn.includes('AdminFullAccess');
    return this.response({
      PolicyVersion: {
        Document: isAdmin
          ? { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }
          : {
              Version: '2012-10-17',
              Statement: [
                { Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::dev-bucket/*' },
                { Effect: 'Allow', Action: ['ec2:Describe*'], Resource: '*' },
              ],
            },
        VersionId: 'v1',
        IsDefaultVersion: true,
      },
    });
  }

  // --- CloudTrail ---
  async describeTrails(): Promise<AwsApiResponse> {
    return this.response({
      trailList: [
        {
          Name: 'management-trail',
          TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail',
          IsMultiRegionTrail: true,
          LogFileValidationEnabled: true,
          S3BucketName: 'company-cloudtrail-logs',
          KmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
          HomeRegion: 'us-east-1',
        },
      ],
    });
  }

  async getTrailStatus(_trailArn: string): Promise<AwsApiResponse> {
    return this.response({
      IsLogging: true,
      LatestDeliveryTime: new Date(Date.now() - 300000).toISOString(),
      LatestNotificationTime: new Date(Date.now() - 300000).toISOString(),
      StartLoggingTime: '2023-01-01T00:00:00Z',
    });
  }

  // --- S3 ---
  async listBuckets(): Promise<AwsApiResponse> {
    return this.response({
      Buckets: [
        { Name: 'company-data-prod', CreationDate: '2023-02-01T00:00:00Z' },
        { Name: 'company-logs', CreationDate: '2023-02-01T00:00:00Z' },
        { Name: 'marketing-assets', CreationDate: '2024-03-15T00:00:00Z' },
      ],
    });
  }

  async getBucketEncryption(bucket: string): Promise<AwsApiResponse> {
    if (bucket === 'marketing-assets') {
      return this.response({}); // No encryption
    }
    return this.response({
      ServerSideEncryptionConfiguration: {
        Rules: [
          {
            ApplyServerSideEncryptionByDefault: {
              SSEAlgorithm: bucket === 'company-data-prod' ? 'aws:kms' : 'AES256',
              KMSMasterKeyID: bucket === 'company-data-prod' ? 'arn:aws:kms:us-east-1:123456789012:key/example' : undefined,
            },
            BucketKeyEnabled: true,
          },
        ],
      },
    });
  }

  async getPublicAccessBlock(bucket: string): Promise<AwsApiResponse> {
    if (bucket === 'marketing-assets') {
      return this.response({
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: false,
          IgnorePublicAcls: false,
          BlockPublicPolicy: false,
          RestrictPublicBuckets: false,
        },
      });
    }
    return this.response({
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true,
      },
    });
  }

  async getBucketVersioning(bucket: string): Promise<AwsApiResponse> {
    return this.response({
      Status: bucket === 'marketing-assets' ? 'Suspended' : 'Enabled',
      MFADelete: 'Disabled',
    });
  }

  async getBucketLogging(bucket: string): Promise<AwsApiResponse> {
    if (bucket === 'company-logs' || bucket === 'marketing-assets') {
      return this.response({});
    }
    return this.response({
      LoggingEnabled: {
        TargetBucket: 'company-logs',
        TargetPrefix: `${bucket}/`,
      },
    });
  }

  // --- VPC / EC2 ---
  async describeVpcs(): Promise<AwsApiResponse> {
    return this.response({
      Vpcs: [
        { VpcId: 'vpc-0abc123def456', CidrBlock: '10.0.0.0/16', IsDefault: false, State: 'available' },
        { VpcId: 'vpc-0default789', CidrBlock: '172.31.0.0/16', IsDefault: true, State: 'available' },
      ],
    });
  }

  async describeSecurityGroups(): Promise<AwsApiResponse> {
    return this.response({
      SecurityGroups: [
        {
          GroupId: 'sg-0abc123',
          GroupName: 'web-servers',
          Description: 'Web server security group',
          VpcId: 'vpc-0abc123def456',
          IpPermissions: [
            {
              IpProtocol: 'tcp',
              FromPort: 443,
              ToPort: 443,
              IpRanges: [{ CidrIp: '0.0.0.0/0', Description: 'HTTPS from anywhere' }],
            },
            {
              IpProtocol: 'tcp',
              FromPort: 80,
              ToPort: 80,
              IpRanges: [{ CidrIp: '0.0.0.0/0', Description: 'HTTP from anywhere' }],
            },
          ],
        },
        {
          GroupId: 'sg-0def456',
          GroupName: 'bastion-ssh',
          Description: 'Bastion host SSH access',
          VpcId: 'vpc-0abc123def456',
          IpPermissions: [
            {
              IpProtocol: 'tcp',
              FromPort: 22,
              ToPort: 22,
              IpRanges: [{ CidrIp: '0.0.0.0/0', Description: 'SSH from anywhere' }],
            },
          ],
        },
        {
          GroupId: 'sg-0ghi789',
          GroupName: 'database',
          Description: 'Database security group',
          VpcId: 'vpc-0abc123def456',
          IpPermissions: [
            {
              IpProtocol: 'tcp',
              FromPort: 5432,
              ToPort: 5432,
              IpRanges: [{ CidrIp: '10.0.0.0/16', Description: 'PostgreSQL from VPC' }],
            },
          ],
        },
      ],
    });
  }

  async describeNetworkAcls(): Promise<AwsApiResponse> {
    return this.response({
      NetworkAcls: [
        {
          NetworkAclId: 'acl-0abc123',
          VpcId: 'vpc-0abc123def456',
          IsDefault: true,
          Entries: [
            { RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: false, CidrBlock: '0.0.0.0/0' },
            { RuleNumber: 100, Protocol: '-1', RuleAction: 'allow', Egress: true, CidrBlock: '0.0.0.0/0' },
          ],
        },
      ],
    });
  }

  async describeFlowLogs(): Promise<AwsApiResponse> {
    return this.response({
      FlowLogs: [
        {
          FlowLogId: 'fl-0abc123',
          ResourceId: 'vpc-0abc123def456',
          LogGroupName: '/vpc/flowlogs/vpc-0abc123def456',
          TrafficType: 'ALL',
          FlowLogStatus: 'ACTIVE',
        },
      ],
    });
  }

  // --- RDS ---
  async describeDbInstances(): Promise<AwsApiResponse> {
    return this.response({
      DBInstances: [
        {
          DBInstanceIdentifier: 'prod-postgres',
          DBInstanceArn: 'arn:aws:rds:us-east-1:123456789012:db:prod-postgres',
          Engine: 'postgres',
          EngineVersion: '15.4',
          DBInstanceClass: 'db.r6g.xlarge',
          StorageEncrypted: true,
          KmsKeyId: 'arn:aws:kms:us-east-1:123456789012:key/rds-key',
          PubliclyAccessible: false,
          BackupRetentionPeriod: 14,
          MultiAZ: true,
          DeletionProtection: true,
          AutoMinorVersionUpgrade: true,
        },
        {
          DBInstanceIdentifier: 'dev-mysql',
          DBInstanceArn: 'arn:aws:rds:us-east-1:123456789012:db:dev-mysql',
          Engine: 'mysql',
          EngineVersion: '8.0.33',
          DBInstanceClass: 'db.t3.medium',
          StorageEncrypted: false,
          PubliclyAccessible: true,
          BackupRetentionPeriod: 1,
          MultiAZ: false,
          DeletionProtection: false,
          AutoMinorVersionUpgrade: true,
        },
      ],
    });
  }

  // --- KMS ---
  async listKeys(): Promise<AwsApiResponse> {
    return this.response({
      Keys: [
        { KeyId: '12345678-1234-1234-1234-123456789012', KeyArn: 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012' },
        { KeyId: 'abcdefgh-abcd-abcd-abcd-abcdefghijkl', KeyArn: 'arn:aws:kms:us-east-1:123456789012:key/abcdefgh-abcd-abcd-abcd-abcdefghijkl' },
        { KeyId: 'aws-managed-s3', KeyArn: 'arn:aws:kms:us-east-1:123456789012:key/aws-managed-s3' },
      ],
    });
  }

  async describeKey(keyId: string): Promise<AwsApiResponse> {
    if (keyId === 'aws-managed-s3') {
      return this.response({
        KeyMetadata: {
          KeyId: keyId,
          KeyManager: 'AWS',
          KeyState: 'Enabled',
          Description: 'Default master key that protects my S3 objects',
          Origin: 'AWS_KMS',
        },
      });
    }
    return this.response({
      KeyMetadata: {
        KeyId: keyId,
        KeyManager: 'CUSTOMER',
        KeyState: keyId.startsWith('1234') ? 'Enabled' : 'Enabled',
        Description: keyId.startsWith('1234') ? 'CloudTrail encryption key' : 'Application data key',
        Origin: 'AWS_KMS',
        CreationDate: '2023-01-15T00:00:00Z',
      },
    });
  }

  async getKeyRotationStatus(keyId: string): Promise<AwsApiResponse> {
    return this.response({
      KeyRotationEnabled: keyId.startsWith('1234'),
    });
  }

  async listKeyPolicies(_keyId: string): Promise<AwsApiResponse> {
    return this.response({ PolicyNames: ['default'] });
  }

  // --- GuardDuty ---
  async listDetectors(): Promise<AwsApiResponse> {
    return this.response({ DetectorIds: ['abcdef1234567890abcdef1234567890'] });
  }

  async getDetector(_detectorId: string): Promise<AwsApiResponse> {
    return this.response({
      Status: 'ENABLED',
      FindingPublishingFrequency: 'FIFTEEN_MINUTES',
      ServiceRole: 'arn:aws:iam::123456789012:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty',
      CreatedAt: '2023-01-15T00:00:00Z',
      UpdatedAt: new Date().toISOString(),
      DataSources: {
        CloudTrail: { Status: 'ENABLED' },
        DNSLogs: { Status: 'ENABLED' },
        FlowLogs: { Status: 'ENABLED' },
        S3Logs: { Status: 'ENABLED' },
      },
    });
  }

  // --- AWS Config ---
  async describeConfigurationRecorders(): Promise<AwsApiResponse> {
    return this.response({
      ConfigurationRecorders: [
        {
          name: 'default',
          roleARN: 'arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig',
          recordingGroup: {
            allSupported: true,
            includeGlobalResourceTypes: true,
          },
        },
      ],
    });
  }

  async describeConfigurationRecorderStatus(): Promise<AwsApiResponse> {
    return this.response({
      ConfigurationRecordersStatus: [
        {
          name: 'default',
          recording: true,
          lastStatus: 'SUCCESS',
          lastStartTime: '2023-01-15T00:00:00Z',
          lastStatusChangeTime: new Date(Date.now() - 60000).toISOString(),
        },
      ],
    });
  }

  async describeDeliveryChannels(): Promise<AwsApiResponse> {
    return this.response({
      DeliveryChannels: [
        {
          name: 'default',
          s3BucketName: 'company-config-logs',
          snsTopicARN: 'arn:aws:sns:us-east-1:123456789012:config-notifications',
          configSnapshotDeliveryProperties: { deliveryFrequency: 'Six_Hours' },
        },
      ],
    });
  }

  // --- AWS Backup ---
  async listBackupPlans(): Promise<AwsApiResponse> {
    return this.response({
      BackupPlansList: [
        {
          BackupPlanId: 'plan-0abc123',
          BackupPlanName: 'daily-production-backup',
          BackupPlanArn: 'arn:aws:backup:us-east-1:123456789012:backup-plan:plan-0abc123',
          CreationDate: '2023-06-01T00:00:00Z',
          LastExecutionDate: new Date(Date.now() - 86400000).toISOString(),
        },
        {
          BackupPlanId: 'plan-0def456',
          BackupPlanName: 'weekly-full-backup',
          BackupPlanArn: 'arn:aws:backup:us-east-1:123456789012:backup-plan:plan-0def456',
          CreationDate: '2023-06-01T00:00:00Z',
          LastExecutionDate: new Date(Date.now() - 604800000).toISOString(),
        },
      ],
    });
  }

  async getBackupPlan(backupPlanId: string): Promise<AwsApiResponse> {
    const plans: Record<string, Record<string, unknown>> = {
      'plan-0abc123': {
        BackupPlanName: 'daily-production-backup',
        Rules: [
          {
            RuleName: 'DailyBackup',
            TargetBackupVaultName: 'production-vault',
            ScheduleExpression: 'cron(0 2 * * ? *)',
            StartWindowMinutes: 60,
            CompletionWindowMinutes: 180,
            Lifecycle: { MoveToColdStorageAfterDays: 30, DeleteAfterDays: 365 },
          },
        ],
      },
      'plan-0def456': {
        BackupPlanName: 'weekly-full-backup',
        Rules: [
          {
            RuleName: 'WeeklyFull',
            TargetBackupVaultName: 'production-vault',
            ScheduleExpression: 'cron(0 1 ? * SUN *)',
            StartWindowMinutes: 120,
            CompletionWindowMinutes: 360,
            Lifecycle: { DeleteAfterDays: 14 },
          },
        ],
      },
    };
    return this.response({ BackupPlan: plans[backupPlanId] ?? {} });
  }

  async listBackupVaults(): Promise<AwsApiResponse> {
    return this.response({
      BackupVaultList: [
        {
          BackupVaultName: 'production-vault',
          BackupVaultArn: 'arn:aws:backup:us-east-1:123456789012:backup-vault:production-vault',
          EncryptionKeyArn: 'arn:aws:kms:us-east-1:123456789012:key/backup-key',
          CreationDate: '2023-06-01T00:00:00Z',
          NumberOfRecoveryPoints: 42,
        },
        {
          BackupVaultName: 'Default',
          BackupVaultArn: 'arn:aws:backup:us-east-1:123456789012:backup-vault:Default',
          CreationDate: '2023-01-01T00:00:00Z',
          NumberOfRecoveryPoints: 3,
        },
      ],
    });
  }
}
