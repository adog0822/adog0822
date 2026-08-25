/**
 * LoxeAI GRC — Default IBAC Control Templates
 *
 * 18 pre-built control templates covering the core SOC 2 operational
 * risk surface.  Every template ships with configurable parameters
 * that workspace admins can tune without touching code.
 *
 * evaluationLogic values map to keys the evaluation engine resolves
 * at runtime — they are declarative rule identifiers, not executable code.
 */

import type { IbacControlTemplate } from "@/types";

export const DEFAULT_IBAC_CONTROLS: IbacControlTemplate[] = [
  // ── Policy Modifications ────────────────────────────────────────────

  {
    id: "ctrl-policy-modify",
    name: "Policy Modification Control",
    description:
      "Requires approval when modifying policies rated at or above the configured risk threshold.",
    category: "policy",
    defaultParameters: {
      riskThreshold: "high",
      requireApprovalAboveThreshold: true,
      allowedRoles: ["owner", "admin"],
    },
    evaluationLogic: "action_eq_modify_and_resource_eq_policy",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },

  {
    id: "ctrl-policy-delete",
    name: "Policy Deletion Control",
    description:
      "Blocks direct deletion of policies; always routes through admin approval.",
    category: "policy",
    defaultParameters: {
      requireAdminApproval: true,
      blockNonAdmins: true,
    },
    evaluationLogic: "action_eq_delete_and_resource_eq_policy",
    riskThreshold: "critical",
    requiresApproval: true,
    enabled: true,
  },

  // ── Evidence ────────────────────────────────────────────────────────

  {
    id: "ctrl-evidence-delete",
    name: "Evidence Deletion Control",
    description:
      "Evidence records may never be deleted without explicit admin approval.",
    category: "evidence",
    defaultParameters: {
      requireAdminApproval: true,
      allowSoftDelete: true,
    },
    evaluationLogic: "action_eq_delete_and_resource_eq_evidence",
    riskThreshold: "critical",
    requiresApproval: true,
    enabled: true,
  },

  {
    id: "ctrl-evidence-export",
    name: "Evidence Export Control",
    description:
      "Logs all evidence export operations and blocks bulk PII exports.",
    category: "evidence",
    defaultParameters: {
      logAllExports: true,
      blockBulkPiiExport: true,
      maxBulkExportCount: 100,
    },
    evaluationLogic: "action_eq_export_and_resource_eq_evidence",
    riskThreshold: "high",
    requiresApproval: false,
    enabled: true,
  },

  // ── Integration Credentials ─────────────────────────────────────────

  {
    id: "ctrl-integration-credential-change",
    name: "Integration Credential Change Control",
    description:
      "Requires step-up authentication when modifying integration credentials.",
    category: "integration",
    defaultParameters: {
      requireStepUpAuth: true,
      notifyAdmins: true,
      allowedAuthMethods: ["mfa", "hardware_key"],
    },
    evaluationLogic: "action_eq_modify_and_resource_eq_integration",
    riskThreshold: "critical",
    requiresApproval: false,
    enabled: true,
  },

  {
    id: "ctrl-integration-create",
    name: "Integration Creation Control",
    description:
      "Controls who may connect new cloud/SaaS integrations.",
    category: "integration",
    defaultParameters: {
      allowedRoles: ["owner", "admin"],
      requireApproval: false,
    },
    evaluationLogic: "action_eq_create_and_resource_eq_integration",
    riskThreshold: "medium",
    requiresApproval: false,
    enabled: true,
  },

  {
    id: "ctrl-integration-delete",
    name: "Integration Removal Control",
    description:
      "Requires approval before disconnecting an active integration.",
    category: "integration",
    defaultParameters: {
      requireAdminApproval: true,
      graceWindowHours: 24,
    },
    evaluationLogic: "action_eq_delete_and_resource_eq_integration",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },

  // ── User Role Changes ──────────────────────────────────────────────

  {
    id: "ctrl-user-role-escalation",
    name: "User Role Escalation Control",
    description:
      "Escalates any attempt to promote a user to admin or owner.",
    category: "user",
    defaultParameters: {
      protectedRoles: ["admin", "owner"],
      requireOwnerApproval: true,
    },
    evaluationLogic: "action_eq_modify_and_resource_eq_user_role_escalation",
    riskThreshold: "critical",
    requiresApproval: true,
    enabled: true,
  },

  {
    id: "ctrl-user-delete",
    name: "User Deletion Control",
    description:
      "Prevents accidental user account removal; requires admin approval.",
    category: "user",
    defaultParameters: {
      requireAdminApproval: true,
      retainDataDays: 90,
    },
    evaluationLogic: "action_eq_delete_and_resource_eq_user",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },

  // ── Export Operations ──────────────────────────────────────────────

  {
    id: "ctrl-report-export",
    name: "Report Export Control",
    description:
      "Logs all report exports; blocks bulk exports containing PII.",
    category: "export",
    defaultParameters: {
      logAllExports: true,
      blockBulkPiiExport: true,
      maxExportRows: 10000,
    },
    evaluationLogic: "action_eq_export_and_resource_eq_report",
    riskThreshold: "medium",
    requiresApproval: false,
    enabled: true,
  },

  {
    id: "ctrl-share-report",
    name: "Report Sharing Control",
    description:
      "Controls external sharing of compliance reports.",
    category: "export",
    defaultParameters: {
      allowExternalShare: false,
      requireApprovalForExternal: true,
      allowedDomains: [],
    },
    evaluationLogic: "action_eq_share_and_resource_eq_report",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },

  // ── Multi-Entity / Cross-Boundary ──────────────────────────────────

  {
    id: "ctrl-workspace-cross-boundary",
    name: "Cross-Workspace Boundary Control",
    description:
      "Blocks or escalates actions that span multiple workspace entities.",
    category: "workspace",
    defaultParameters: {
      blockCrossBoundary: true,
      allowedCrossBoundaryActions: ["read"],
      requireApprovalForCrossBoundary: true,
    },
    evaluationLogic: "cross_boundary_workspace_check",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },

  {
    id: "ctrl-workspace-settings-modify",
    name: "Workspace Settings Modification Control",
    description:
      "Requires owner approval before changing workspace-level settings.",
    category: "workspace",
    defaultParameters: {
      requireOwnerApproval: true,
      protectedSettings: ["ibacParameters", "integrations"],
    },
    evaluationLogic: "action_eq_modify_and_resource_eq_workspace",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },

  // ── Vendor Risk ────────────────────────────────────────────────────

  {
    id: "ctrl-vendor-risk-modify",
    name: "Vendor Risk Modification Control",
    description:
      "Requires approval when modifying vendor risk assessments.",
    category: "vendor",
    defaultParameters: {
      requireApproval: true,
      notifyComplianceTeam: true,
      allowedRoles: ["owner", "admin"],
    },
    evaluationLogic: "action_eq_modify_and_resource_eq_vendor",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },

  {
    id: "ctrl-vendor-delete",
    name: "Vendor Deletion Control",
    description:
      "Prevents vendor record deletion without compliance team sign-off.",
    category: "vendor",
    defaultParameters: {
      requireAdminApproval: true,
      requireComplianceSignoff: true,
    },
    evaluationLogic: "action_eq_delete_and_resource_eq_vendor",
    riskThreshold: "critical",
    requiresApproval: true,
    enabled: true,
  },

  // ── Firewall / Security Templates ──────────────────────────────────

  {
    id: "ctrl-firewall-template-modify",
    name: "Firewall Template Modification Control",
    description:
      "Requires approval for any change to firewall policy templates.",
    category: "security",
    defaultParameters: {
      requireApproval: true,
      notifySecurityTeam: true,
      allowedRoles: ["owner", "admin"],
    },
    evaluationLogic: "action_eq_modify_and_resource_eq_firewall_template",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },

  {
    id: "ctrl-firewall-template-delete",
    name: "Firewall Template Deletion Control",
    description:
      "Blocks deletion of firewall templates; always requires owner approval.",
    category: "security",
    defaultParameters: {
      requireOwnerApproval: true,
      blockNonOwners: true,
    },
    evaluationLogic: "action_eq_delete_and_resource_eq_firewall_template",
    riskThreshold: "critical",
    requiresApproval: true,
    enabled: true,
  },

  // ── Access Review ──────────────────────────────────────────────────

  {
    id: "ctrl-access-review-modify",
    name: "Access Review Modification Control",
    description:
      "Requires approval to modify completed or in-progress access reviews.",
    category: "access_control",
    defaultParameters: {
      requireApproval: true,
      protectCompletedReviews: true,
      allowedRoles: ["owner", "admin", "auditor"],
    },
    evaluationLogic: "action_eq_modify_and_resource_eq_access_review",
    riskThreshold: "high",
    requiresApproval: true,
    enabled: true,
  },
];

/**
 * Retrieve a shallow copy of all default control templates.
 * Workspace customisation layers on top of these via parameter overrides.
 */
export function getDefaultControls(): IbacControlTemplate[] {
  return DEFAULT_IBAC_CONTROLS.map((c) => ({ ...c }));
}

/**
 * Look up a single default control by its template ID.
 */
export function getDefaultControlById(
  id: string,
): IbacControlTemplate | undefined {
  const ctrl = DEFAULT_IBAC_CONTROLS.find((c) => c.id === id);
  return ctrl ? { ...ctrl } : undefined;
}
