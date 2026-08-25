/**
 * LoxeAI AWS Setup Flow
 *
 * Handles the specific AWS integration setup for cross-account access:
 *   1. Generate a unique external ID
 *   2. Generate a CloudFormation YAML template (read-only IAM role)
 *   3. Validate a provided role ARN
 *   4. Create the AwsSetupConfig object
 *
 * The CloudFormation template creates an IAM role with:
 *   - Trust policy using the external ID for secure cross-account assumption
 *   - SecurityAudit managed policy (broad read-only security visibility)
 *   - ViewOnlyAccess managed policy (general read-only access)
 *   - Custom inline policy for SOC 2-specific read-only actions
 */

import type { AwsSetupConfig } from "../types/index";

// ─── Constants ────────────────────────────────────────────────────────

/** The LoxeAI AWS account ID that will assume the cross-account role. */
const LOXEAI_AWS_ACCOUNT_ID = "123456789012";

/** Default role name created in the customer's AWS account. */
const DEFAULT_ROLE_NAME = "LoxeAI-SOC2-ReadOnly";

/** CloudFormation template download path (relative to app domain). */
const TEMPLATE_PATH = "/integrations/aws/cloudformation-template.yaml";

// ─── External ID Generation ──────────────────────────────────────────

/**
 * Generate a unique external ID for cross-account role assumption.
 *
 * The external ID prevents the "confused deputy" problem by ensuring
 * only LoxeAI can assume the role on behalf of this specific workspace.
 *
 * Format: loxeai_{workspaceId}_{timestamp_hex}
 */
export function generateExternalId(workspaceId: string): string {
  const timestamp = Date.now().toString(16);
  // Create a deterministic hash-like suffix from the workspace ID
  let hash = 0;
  for (let i = 0; i < workspaceId.length; i++) {
    const char = workspaceId.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  const hashHex = Math.abs(hash).toString(16).padStart(8, "0");
  return `loxeai_${workspaceId}_${timestamp}_${hashHex}`;
}

// ─── CloudFormation Template ──────────────────────────────────────────

/**
 * Generate the CloudFormation YAML template for creating the read-only
 * IAM role in the customer's AWS account.
 *
 * The template creates:
 * - An IAM Role with a trust policy scoped to the LoxeAI account + external ID
 * - SecurityAudit AWS managed policy
 * - ViewOnlyAccess AWS managed policy
 * - A custom inline policy for SOC 2-specific read-only actions
 */
export function generateCloudFormationTemplate(
  externalId: string,
  roleName: string = DEFAULT_ROLE_NAME
): string {
  return `AWSTemplateFormatVersion: "2010-09-09"
Description: >
  LoxeAI SOC 2 Compliance — Read-Only Cross-Account Role.
  This template creates an IAM role that grants LoxeAI read-only access
  to collect evidence for SOC 2 compliance automation.

Parameters:
  ExternalId:
    Type: String
    Default: "${externalId}"
    Description: >
      Unique external ID to prevent confused deputy attacks.
      Do not change this value.
    AllowedPattern: "^loxeai_.+"
    ConstraintDescription: Must be the external ID provided by LoxeAI.

  RoleName:
    Type: String
    Default: "${roleName}"
    Description: Name of the IAM role to create.
    AllowedPattern: "^[a-zA-Z0-9+=,.@\\\\-_]{1,64}$"
    ConstraintDescription: Must be a valid IAM role name.

Resources:
  LoxeAIReadOnlyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      Description: >
        Read-only role for LoxeAI SOC 2 compliance evidence collection.
        Grants SecurityAudit, ViewOnlyAccess, and custom read-only permissions.
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: "arn:aws:iam::${LOXEAI_AWS_ACCOUNT_ID}:root"
            Action: "sts:AssumeRole"
            Condition:
              StringEquals:
                "sts:ExternalId": !Ref ExternalId
      ManagedPolicyArns:
        - "arn:aws:iam::aws:policy/SecurityAudit"
        - "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
      Policies:
        - PolicyName: LoxeAI-SOC2-CustomReadOnly
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: SOC2EvidenceCollection
                Effect: Allow
                Action:
                  # CloudTrail — audit logging evidence
                  - "cloudtrail:GetTrailStatus"
                  - "cloudtrail:DescribeTrails"
                  - "cloudtrail:GetEventSelectors"
                  - "cloudtrail:LookupEvents"

                  # CloudWatch — monitoring and alerting evidence
                  - "cloudwatch:DescribeAlarms"
                  - "cloudwatch:GetMetricData"
                  - "logs:DescribeLogGroups"
                  - "logs:DescribeMetricFilters"

                  # Config — configuration compliance evidence
                  - "config:DescribeConfigRules"
                  - "config:DescribeComplianceByConfigRule"
                  - "config:GetComplianceDetailsByConfigRule"
                  - "config:DescribeConfigurationRecorders"
                  - "config:DescribeConfigurationRecorderStatus"

                  # GuardDuty — threat detection evidence
                  - "guardduty:ListDetectors"
                  - "guardduty:GetDetector"
                  - "guardduty:ListFindings"
                  - "guardduty:GetFindings"

                  # IAM — access control evidence
                  - "iam:GetAccountPasswordPolicy"
                  - "iam:GetAccountSummary"
                  - "iam:GenerateCredentialReport"
                  - "iam:GetCredentialReport"
                  - "iam:ListMFADevices"
                  - "iam:ListVirtualMFADevices"
                  - "iam:GetLoginProfile"

                  # KMS — encryption evidence
                  - "kms:ListKeys"
                  - "kms:DescribeKey"
                  - "kms:GetKeyRotationStatus"
                  - "kms:ListAliases"

                  # S3 — data protection evidence
                  - "s3:GetBucketEncryption"
                  - "s3:GetBucketVersioning"
                  - "s3:GetBucketLogging"
                  - "s3:GetBucketPublicAccessBlock"
                  - "s3:GetAccountPublicAccessBlock"
                  - "s3:GetBucketPolicy"
                  - "s3:GetBucketAcl"

                  # RDS — database security evidence
                  - "rds:DescribeDBInstances"
                  - "rds:DescribeDBClusters"
                  - "rds:DescribeDBSnapshots"
                  - "rds:DescribeDBSubnetGroups"

                  # VPC — network security evidence
                  - "ec2:DescribeSecurityGroups"
                  - "ec2:DescribeNetworkAcls"
                  - "ec2:DescribeFlowLogs"
                  - "ec2:DescribeVpcs"
                  - "ec2:DescribeSubnets"

                  # ECS/EKS — container security
                  - "ecs:DescribeClusters"
                  - "ecs:ListClusters"
                  - "eks:DescribeCluster"
                  - "eks:ListClusters"

                  # Lambda — serverless config
                  - "lambda:ListFunctions"
                  - "lambda:GetFunction"
                  - "lambda:GetFunctionConfiguration"

                  # SNS — notification channels
                  - "sns:ListTopics"
                  - "sns:ListSubscriptions"

                  # SSM — patch management evidence
                  - "ssm:DescribeInstanceInformation"
                  - "ssm:ListComplianceItems"

                  # Backup — data recovery evidence
                  - "backup:ListBackupPlans"
                  - "backup:ListBackupVaults"
                  - "backup:DescribeBackupVault"

                  # WAF — web application firewall evidence
                  - "wafv2:ListWebACLs"
                  - "wafv2:GetWebACL"

                  # ACM — certificate management
                  - "acm:ListCertificates"
                  - "acm:DescribeCertificate"

                  # SecretsManager — secrets rotation evidence
                  - "secretsmanager:ListSecrets"
                  - "secretsmanager:DescribeSecret"
                Resource: "*"
      Tags:
        - Key: Purpose
          Value: LoxeAI-SOC2-Compliance
        - Key: ManagedBy
          Value: LoxeAI
        - Key: CreatedVia
          Value: CloudFormation

Outputs:
  RoleArn:
    Description: >
      The ARN of the created role. Copy this value and paste it
      back into LoxeAI to complete the AWS integration setup.
    Value: !GetAtt LoxeAIReadOnlyRole.Arn
    Export:
      Name: !Sub "\${AWS::StackName}-RoleArn"

  ExternalId:
    Description: The external ID used for this integration.
    Value: !Ref ExternalId
`;
}

// ─── Role ARN Validation ──────────────────────────────────────────────

/**
 * Validate an AWS IAM role ARN format.
 *
 * Expected format: arn:aws:iam::<account-id>:role/<role-name>
 * Also supports: arn:aws:iam::<account-id>:role/<path>/<role-name>
 *
 * Returns null if valid, or an error message string if invalid.
 */
export function validateRoleArn(roleArn: string): string | null {
  if (!roleArn || roleArn.trim().length === 0) {
    return "Role ARN is required.";
  }

  const trimmed = roleArn.trim();

  // Basic ARN format check
  const arnPattern = /^arn:aws:iam::\d{12}:role\/.+$/;
  if (!arnPattern.test(trimmed)) {
    return "Invalid ARN format. Expected: arn:aws:iam::<12-digit-account-id>:role/<role-name>";
  }

  // Extract and validate the account ID
  const accountIdMatch = trimmed.match(/arn:aws:iam::(\d{12}):role\//);
  if (!accountIdMatch) {
    return "Could not parse AWS account ID from ARN. Ensure it contains a 12-digit account ID.";
  }

  // Extract and validate the role name
  const roleNameMatch = trimmed.match(/role\/(.+)$/);
  if (!roleNameMatch || roleNameMatch[1].length === 0) {
    return "Role name is missing from the ARN.";
  }

  // Role name should not exceed 64 characters (each path segment)
  const rolePath = roleNameMatch[1];
  const segments = rolePath.split("/");
  const roleName = segments[segments.length - 1];
  if (roleName.length > 64) {
    return "Role name exceeds the 64-character maximum.";
  }

  return null;
}

// ─── AWS Setup Config Factory ─────────────────────────────────────────

/**
 * Generate the complete AWS setup configuration for a workspace.
 *
 * This creates everything needed for the AWS integration setup flow:
 * 1. A unique external ID
 * 2. The CloudFormation template
 * 3. The setup config object
 *
 * The user flow is:
 * 1. User selects AWS in onboarding
 * 2. LoxeAI generates external ID + CF template
 * 3. User clicks "Launch Stack" (links to CloudFormation console)
 * 4. CloudFormation creates the read-only role
 * 5. User copies the role ARN from CF outputs
 * 6. User pastes role ARN back into LoxeAI
 * 7. LoxeAI validates the ARN and starts the cloud scan
 */
export function generateAwsSetup(
  workspaceId: string,
  roleName: string = DEFAULT_ROLE_NAME
): AwsSetupConfig {
  const externalId = generateExternalId(workspaceId);
  const templateYaml = generateCloudFormationTemplate(externalId, roleName);

  return {
    externalId,
    roleName,
    templateUrl: TEMPLATE_PATH,
    templateYaml,
    readOnlyPolicies: [
      "arn:aws:iam::aws:policy/SecurityAudit",
      "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
      "LoxeAI-SOC2-CustomReadOnly (inline)",
    ],
  };
}
