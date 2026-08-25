// =============================================================================
// LoxeAI — Evidence Collector
// Orchestrates scanning across all connected integrations
// =============================================================================

import {
  type AwsCredentials,
  type CollectionProgress,
  type EvidenceItem,
  type GitHubCredentials,
  type IntegrationConfig,
  type ScanResult,
} from '../types/index';

import { AwsScanner } from './aws/scanner';
import { GitHubScanner } from './github/scanner';
import type { AwsClient } from './aws/scanner';
import type { GitHubClient } from './github/scanner';

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
// Client Factory — allows injecting mock or real clients
// ---------------------------------------------------------------------------

export interface ClientFactory {
  createAwsClient(credentials: AwsCredentials): AwsClient;
  createGitHubClient(credentials: GitHubCredentials): GitHubClient;
}

// ---------------------------------------------------------------------------
// Collection Progress Tracker
// ---------------------------------------------------------------------------

const activeCollections = new Map<string, CollectionProgress>();

/**
 * Get the current progress of an evidence collection run.
 */
export function getCollectionProgress(collectionId: string): CollectionProgress | undefined {
  return activeCollections.get(collectionId);
}

// ---------------------------------------------------------------------------
// Hash Chain Builder
// ---------------------------------------------------------------------------

/**
 * Build a cryptographic hash chain across all evidence items.
 * Each item's sourceTrace.previousHash points to the prior item's evidenceHash,
 * creating an ordered tamper-evident chain.
 */
async function buildHashChain(evidence: EvidenceItem[]): Promise<EvidenceItem[]> {
  if (evidence.length === 0) return evidence;

  const chained: EvidenceItem[] = [];
  let previousHash = '';

  for (const item of evidence) {
    const rawStr = JSON.stringify(item.rawData);
    const evidenceHash = await sha256(rawStr + item.collectedAt + previousHash);

    chained.push({
      ...item,
      sourceTrace: {
        ...item.sourceTrace,
        evidenceHash,
        previousHash,
      },
    });

    previousHash = evidenceHash;
  }

  return chained;
}

// ---------------------------------------------------------------------------
// Scan key mapping
// ---------------------------------------------------------------------------

const AWS_SCAN_KEYS = [
  'iam-users',
  'iam-policies',
  'cloudtrail',
  's3-buckets',
  'vpc-config',
  'rds-instances',
  'kms-keys',
  'guardduty',
  'aws-config',
  'backups',
] as const;

const GITHUB_SCAN_KEYS = [
  'org-settings',
  'repo-protection',
  'access-permissions',
  'audit-log',
  'secrets-scanning',
] as const;

function getScanKeysForIntegration(integrationKey: string): readonly string[] {
  switch (integrationKey) {
    case 'aws':
      return AWS_SCAN_KEYS;
    case 'github':
      return GITHUB_SCAN_KEYS;
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// Single-Integration Collector
// ---------------------------------------------------------------------------

/**
 * Collect evidence from a single integration.
 */
export async function collectForIntegration(
  integration: IntegrationConfig,
  clientFactory: ClientFactory,
): Promise<ScanResult[]> {
  const { integrationKey, credentials, id: integrationId, enabledScans } = integration;

  switch (integrationKey) {
    case 'aws': {
      if (credentials.type !== 'aws') {
        throw new Error(`Invalid credential type "${credentials.type}" for AWS integration`);
      }
      const client = clientFactory.createAwsClient(credentials);
      const scanner = new AwsScanner(client, credentials, integrationId);

      if (enabledScans.length > 0) {
        // Run only enabled scans
        const results: ScanResult[] = [];
        const scanMethodMap: Record<string, () => Promise<ScanResult>> = {
          'iam-users': () => scanner.scanIamUsers(),
          'iam-policies': () => scanner.scanIamPolicies(),
          'cloudtrail': () => scanner.scanCloudTrail(),
          's3-buckets': () => scanner.scanS3Buckets(),
          'vpc-config': () => scanner.scanVpcConfig(),
          'rds-instances': () => scanner.scanRdsInstances(),
          'kms-keys': () => scanner.scanKmsKeys(),
          'guardduty': () => scanner.scanGuardDuty(),
          'aws-config': () => scanner.scanConfig(),
          'backups': () => scanner.scanBackups(),
        };
        for (const scanKey of enabledScans) {
          const method = scanMethodMap[scanKey];
          if (method) {
            try {
              results.push(await method());
            } catch (err) {
              results.push({
                scanKey,
                success: false,
                error: err instanceof Error ? err.message : String(err),
                evidence: [],
                durationMs: 0,
                startedAt: new Date().toISOString(),
                completedAt: new Date().toISOString(),
              });
            }
          }
        }
        return results;
      }

      return scanner.runAllScans();
    }

    case 'github': {
      if (credentials.type !== 'github') {
        throw new Error(`Invalid credential type "${credentials.type}" for GitHub integration`);
      }
      const client = clientFactory.createGitHubClient(credentials);
      const scanner = new GitHubScanner(client, credentials, integrationId);

      if (enabledScans.length > 0) {
        const results: ScanResult[] = [];
        const scanMethodMap: Record<string, () => Promise<ScanResult>> = {
          'org-settings': () => scanner.scanOrgSettings(),
          'repo-protection': () => scanner.scanRepoProtection(),
          'access-permissions': () => scanner.scanAccessPermissions(),
          'audit-log': () => scanner.scanAuditLog(),
          'secrets-scanning': () => scanner.scanSecrets(),
        };
        for (const scanKey of enabledScans) {
          const method = scanMethodMap[scanKey];
          if (method) {
            try {
              results.push(await method());
            } catch (err) {
              results.push({
                scanKey,
                success: false,
                error: err instanceof Error ? err.message : String(err),
                evidence: [],
                durationMs: 0,
                startedAt: new Date().toISOString(),
                completedAt: new Date().toISOString(),
              });
            }
          }
        }
        return results;
      }

      return scanner.runAllScans();
    }

    default:
      throw new Error(`Unsupported integration type: ${integrationKey}`);
  }
}

// ---------------------------------------------------------------------------
// Multi-Integration Evidence Collection
// ---------------------------------------------------------------------------

/**
 * Collect evidence across all connected integrations for a workspace.
 *
 * @param workspaceId - The workspace to collect evidence for
 * @param integrations - Integration configurations to scan
 * @param clientFactory - Factory to create API clients
 * @returns CollectionProgress with all evidence and hash chain
 */
export async function collectEvidence(
  workspaceId: string,
  integrations: IntegrationConfig[],
  clientFactory: ClientFactory,
): Promise<CollectionProgress> {
  const collectionId = generateId('col');

  // Compute total scan count
  const connectedIntegrations = integrations.filter((i) => i.status === 'connected');
  let totalScans = 0;
  for (const integration of connectedIntegrations) {
    const allKeys = getScanKeysForIntegration(integration.integrationKey);
    const scansToRun =
      integration.enabledScans.length > 0
        ? integration.enabledScans.filter((s) => allKeys.includes(s))
        : allKeys;
    totalScans += scansToRun.length;
  }

  // Initialize progress
  const progress: CollectionProgress = {
    collectionId,
    workspaceId,
    totalScans,
    completedScans: 0,
    failedScans: 0,
    activeScans: [],
    scanStatuses: {},
    startedAt: new Date().toISOString(),
    evidence: [],
  };

  // Initialize all scan statuses
  for (const integration of connectedIntegrations) {
    const allKeys = getScanKeysForIntegration(integration.integrationKey);
    const scansToRun =
      integration.enabledScans.length > 0
        ? integration.enabledScans.filter((s) => allKeys.includes(s))
        : [...allKeys];
    for (const key of scansToRun) {
      progress.scanStatuses[`${integration.integrationKey}:${key}`] = 'pending';
    }
  }

  activeCollections.set(collectionId, progress);

  // Run scans for each integration sequentially
  const allEvidence: EvidenceItem[] = [];

  for (const integration of connectedIntegrations) {
    const allKeys = getScanKeysForIntegration(integration.integrationKey);
    const scansToRun =
      integration.enabledScans.length > 0
        ? integration.enabledScans.filter((s) => allKeys.includes(s))
        : [...allKeys];

    // Mark scans as running
    for (const key of scansToRun) {
      const compositeKey = `${integration.integrationKey}:${key}`;
      progress.scanStatuses[compositeKey] = 'running';
      progress.activeScans.push(key);
    }
    activeCollections.set(collectionId, { ...progress });

    try {
      const results = await collectForIntegration(integration, clientFactory);

      for (const result of results) {
        const compositeKey = `${integration.integrationKey}:${result.scanKey}`;
        if (result.success) {
          progress.scanStatuses[compositeKey] = 'completed';
          progress.completedScans++;
        } else {
          progress.scanStatuses[compositeKey] = 'failed';
          progress.failedScans++;
          progress.completedScans++;
        }
        progress.activeScans = progress.activeScans.filter((s) => s !== result.scanKey);
        allEvidence.push(...result.evidence);
      }
    } catch (err) {
      // Mark all scans for this integration as failed
      for (const key of scansToRun) {
        const compositeKey = `${integration.integrationKey}:${key}`;
        progress.scanStatuses[compositeKey] = 'failed';
        progress.failedScans++;
        progress.completedScans++;
      }
      progress.activeScans = progress.activeScans.filter(
        (s) => !scansToRun.includes(s),
      );
    }

    activeCollections.set(collectionId, { ...progress });
  }

  // Build the hash chain across all evidence
  const chainedEvidence = await buildHashChain(allEvidence);

  // Finalize progress
  progress.evidence = chainedEvidence;
  progress.activeScans = [];
  progress.completedAt = new Date().toISOString();

  activeCollections.set(collectionId, progress);

  return progress;
}
