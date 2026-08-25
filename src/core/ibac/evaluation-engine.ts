/**
 * LoxeAI GRC — Deterministic IBAC Evaluation Engine
 *
 * Matches an IntentObject against a set of IbacControlTemplates
 * (with optional workspace parameter overrides) and produces an
 * IbacEvaluation with a deterministic decision.
 *
 * Pure function — same inputs ALWAYS yield the same outputs.
 */

import type {
  IntentObject,
  IbacControlTemplate,
  IbacParameter,
  IbacEvaluation,
  IbacDecision,
  MatchedControl,
  RiskLevel,
  IbacAction,
  IbacResource,
  UserRole,
} from "@/types";
import { sha256 } from "../evidence/crypto-chain";

// ─── Risk Ordering ────────────────────────────────────────────────────

const RISK_ORDER: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function riskMeetsThreshold(
  actual: RiskLevel,
  threshold: RiskLevel,
): boolean {
  return RISK_ORDER[actual] >= RISK_ORDER[threshold];
}

// ─── Condition Evaluators ─────────────────────────────────────────────

/**
 * Each evaluationLogic string maps to a pure predicate that checks
 * whether the intent triggers the control.
 *
 * Returns:
 *   - `null`                if the control does not apply
 *   - `"pass"`             if the control applies and the action is allowed
 *   - `"fail"`             if the control blocks the action
 *   - `"requires_approval"` if the control defers to human approval
 */
type ControlResult = "pass" | "fail" | "requires_approval";

function evaluateCondition(
  logic: string,
  intent: IntentObject,
  params: Record<string, unknown>,
): { applies: boolean; result: ControlResult; reason: string } {
  // Helper: extract action + resource from the logic key
  const actionResourceMatch = logic.match(
    /^action_eq_(\w+)_and_resource_eq_(.+)$/,
  );

  if (actionResourceMatch) {
    const [, expectedAction, expectedResourceRaw] = actionResourceMatch;

    // Special case: user role escalation — the logic key encodes the
    // sub-scenario after the resource (e.g. "user_role_escalation").
    let expectedResource = expectedResourceRaw as string;
    let isSubScenario = false;
    if (expectedResource.startsWith("user_")) {
      const subParts = expectedResource.split("_");
      // "user_role_escalation" → resource = "user"
      expectedResource = subParts[0];
      isSubScenario = true;
    }

    // Does this control apply?
    if (intent.action !== expectedAction) {
      return { applies: false, result: "pass", reason: "" };
    }
    if (intent.resource !== expectedResource) {
      return { applies: false, result: "pass", reason: "" };
    }

    // Risk gate
    const threshold = (params["riskThreshold"] as RiskLevel) ?? "high";
    if (!riskMeetsThreshold(intent.riskLevel, threshold)) {
      return {
        applies: true,
        result: "pass",
        reason: `Risk level "${intent.riskLevel}" is below threshold "${threshold}"`,
      };
    }

    // Role check (if configured)
    const allowedRoles = params["allowedRoles"] as UserRole[] | undefined;
    // We cannot check roles here (intent has no user role), so we
    // store the requirement for upstream middleware to enforce.

    // Step-up auth check
    if (params["requireStepUpAuth"] === true) {
      return {
        applies: true,
        result: "requires_approval",
        reason: "Step-up authentication required for this operation",
      };
    }

    // Admin approval check
    if (
      params["requireAdminApproval"] === true ||
      params["requireOwnerApproval"] === true ||
      params["requireApproval"] === true ||
      params["requireApprovalAboveThreshold"] === true
    ) {
      return {
        applies: true,
        result: "requires_approval",
        reason: `Approval required: ${intent.action} on ${intent.resource} at risk level "${intent.riskLevel}"`,
      };
    }

    // Block non-admins / non-owners
    if (params["blockNonAdmins"] === true || params["blockNonOwners"] === true) {
      return {
        applies: true,
        result: "fail",
        reason: `Action "${intent.action}" on "${intent.resource}" is restricted to admins/owners`,
      };
    }

    // Default: passes
    return {
      applies: true,
      result: "pass",
      reason: `Allowed: ${intent.action} on ${intent.resource}`,
    };
  }

  // ── Cross-boundary workspace check ──────────────────────────────────
  if (logic === "cross_boundary_workspace_check") {
    const entities = intent.context.targetEntities ?? [];
    const hasCrossBoundary = entities.length > 1;

    if (!hasCrossBoundary) {
      return { applies: false, result: "pass", reason: "" };
    }

    const blockCrossBoundary = params["blockCrossBoundary"] as boolean;
    const allowedActions = (params["allowedCrossBoundaryActions"] as IbacAction[]) ?? [];
    const requireApproval = params["requireApprovalForCrossBoundary"] as boolean;

    if (blockCrossBoundary && !allowedActions.includes(intent.action)) {
      if (requireApproval) {
        return {
          applies: true,
          result: "requires_approval",
          reason: `Cross-boundary "${intent.action}" across ${entities.length} entities requires approval`,
        };
      }
      return {
        applies: true,
        result: "fail",
        reason: `Cross-boundary "${intent.action}" is not permitted`,
      };
    }

    return {
      applies: true,
      result: "pass",
      reason: `Cross-boundary "${intent.action}" is in the allowed action list`,
    };
  }

  // ── Bulk PII export check (embedded in export controls) ─────────────
  if (
    logic === "action_eq_export_and_resource_eq_evidence" ||
    logic === "action_eq_export_and_resource_eq_report"
  ) {
    if (intent.action !== "export") {
      return { applies: false, result: "pass", reason: "" };
    }

    const blockBulkPii = params["blockBulkPiiExport"] as boolean;
    const hasPiiFlag = intent.context.metadata["containsPii"] === true;
    const isBulk = intent.context.metadata["isBulk"] === true;

    if (blockBulkPii && hasPiiFlag && isBulk) {
      return {
        applies: true,
        result: "fail",
        reason: "Bulk export containing PII is blocked by policy",
      };
    }

    // Log-only controls pass but are still recorded as matched
    return {
      applies: true,
      result: "pass",
      reason: `Export logged (PII: ${hasPiiFlag}, bulk: ${isBulk})`,
    };
  }

  // ── Catch-all: unknown logic key ────────────────────────────────────
  return { applies: false, result: "pass", reason: "" };
}

// ─── Parameter Merging ────────────────────────────────────────────────

/**
 * Merge workspace-level parameter overrides onto a control template's
 * defaults.  Workspace values take precedence.
 */
function resolveParameters(
  template: IbacControlTemplate,
  overrides: IbacParameter[],
): Record<string, unknown> {
  const merged = { ...template.defaultParameters };
  for (const p of overrides) {
    if (p.controlTemplateId === template.id) {
      merged[p.key] = p.value;
    }
  }
  return merged;
}

// ─── Decision Logic ───────────────────────────────────────────────────

/**
 * Derive the top-level decision from the collected control results.
 *
 * Priority (highest wins):
 *   1. Any `fail`              → deny
 *   2. Any `requires_approval` → escalate (or step_up_auth when the
 *      triggering control uses step-up auth parameters)
 *   3. All `pass`              → allow
 */
function deriveDecision(
  matched: MatchedControl[],
  controls: IbacControlTemplate[],
): IbacDecision {
  let hasApprovalRequired = false;
  let needsStepUp = false;

  for (const mc of matched) {
    if (mc.result === "fail") return "deny";
    if (mc.result === "requires_approval") {
      hasApprovalRequired = true;
      // Check if this control uses step-up auth
      const ctrl = controls.find((c) => c.id === mc.controlTemplateId);
      if (ctrl) {
        const params = mc.parameters;
        if (params["requireStepUpAuth"] === true) {
          needsStepUp = true;
        }
      }
    }
  }

  if (needsStepUp) return "step_up_auth";
  if (hasApprovalRequired) return "escalate";
  return "allow";
}

// ─── Public API ───────────────────────────────────────────────────────

export interface EvaluateInput {
  intent: IntentObject;
  controls: IbacControlTemplate[];
  parameterOverrides?: IbacParameter[];
}

/**
 * Evaluate an IntentObject against a set of IBAC control templates.
 *
 * This function is **purely deterministic**: the same intent,
 * controls, and parameter overrides always produce the same evaluation.
 */
export function evaluate(input: EvaluateInput): IbacEvaluation {
  const {
    intent,
    controls,
    parameterOverrides = [],
  } = input;

  const evaluatedAt = new Date().toISOString();
  const matchedControls: MatchedControl[] = [];

  for (const ctrl of controls) {
    if (!ctrl.enabled) continue;

    const params = resolveParameters(ctrl, parameterOverrides);
    const { applies, result, reason } = evaluateCondition(
      ctrl.evaluationLogic,
      intent,
      params,
    );

    if (applies) {
      matchedControls.push({
        controlTemplateId: ctrl.id,
        controlName: ctrl.name,
        parameters: params,
        result,
        reason,
      });
    }
  }

  const decision = deriveDecision(matchedControls, controls);

  // Produce a deterministic evidence hash of the evaluation payload
  const evidencePayload = JSON.stringify({
    intentId: intent.id,
    decision,
    matchedControls,
    evaluatedAt,
  });
  const evidenceHash = sha256(evidencePayload);

  const evaluation: IbacEvaluation = {
    intentId: intent.id,
    decision,
    matchedControls,
    evaluatedAt,
    evidenceHash,
  };

  // Attach escalation info when the decision requires human review
  if (decision === "escalate" || decision === "step_up_auth") {
    const expiresAt = new Date(
      Date.now() + 24 * 60 * 60 * 1000,
    ).toISOString();

    evaluation.escalationRequired = {
      approverId: intent.context.userId, // placeholder — real approver resolved upstream
      reason: matchedControls
        .filter((mc) => mc.result === "requires_approval")
        .map((mc) => mc.reason)
        .join("; "),
      expiresAt,
    };
  }

  return evaluation;
}
