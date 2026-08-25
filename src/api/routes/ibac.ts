/**
 * IBAC (Intent-Based Access Control) API Route Handlers
 *
 * IBAC evaluates agent actions by analyzing their stated intent
 * against a set of configurable controls. Unlike traditional RBAC,
 * IBAC decisions are based on *what* an agent wants to do and *why*,
 * not just *who* it is.
 *
 * Every evaluation is logged to an immutable audit trail that
 * becomes part of the evidence chain for SOC 2 compliance.
 */

import type {
  ApiResponse,
  AuthenticatedRequest,
  IBACControl,
  IBACDecisionLog,
  IBACEvaluation,
  IBACIntent,
  PaginatedResponse,
  PaginationParams,
  UUID,
} from '../../types';

// ---------------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------------

export interface EvaluateIntentRequest extends AuthenticatedRequest {
  body: {
    intent: IBACIntent;
  };
}

export interface EvaluateIntentResponse {
  evaluation: IBACEvaluation;
}

export interface ListControlsRequest extends AuthenticatedRequest {}

export interface ListControlsResponse {
  controls: IBACControl[];
}

export interface UpdateControlRequest extends AuthenticatedRequest {
  params: {
    id: UUID;
  };
  body: {
    name?: string;
    description?: string;
    intentPattern?: string;
    resourcePattern?: string;
    defaultVerdict?: IBACEvaluation['verdict'];
    riskLevel?: IBACEvaluation['riskLevel'];
    conditions?: IBACControl['conditions'];
    enabled?: boolean;
  };
}

export interface UpdateControlResponse {
  control: IBACControl;
}

export interface GetAuditLogRequest extends AuthenticatedRequest {
  query: PaginationParams & {
    verdict?: IBACEvaluation['verdict'];
    riskLevel?: IBACEvaluation['riskLevel'];
    startDate?: string;
    endDate?: string;
    requestorId?: UUID;
  };
}

export type GetAuditLogResponse = PaginatedResponse<IBACDecisionLog>;

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

/**
 * POST /api/ibac/evaluate
 *
 * Evaluates an intent through the IBAC system. The intent describes
 * what an agent or user wants to do, and IBAC returns a verdict:
 *
 * - **allow:** The action is permitted.
 * - **deny:** The action is blocked. A clear reason is provided.
 * - **escalate:** The action requires human approval before proceeding.
 * - **allow_with_logging:** The action is permitted but logged with
 *   extra scrutiny for audit purposes.
 *
 * Every evaluation is recorded in the immutable audit log regardless
 * of the verdict.
 */
export async function evaluateIntent(
  req: EvaluateIntentRequest
): Promise<ApiResponse<EvaluateIntentResponse>> {
  const { body, workspace } = req;
  const { intent } = body;

  if (!intent.action || !intent.resource) {
    return {
      success: false,
      error: {
        code: 'INVALID_INTENT',
        message: 'Intent must include both action and resource fields.',
      },
    };
  }

  const startTime = Date.now();

  // Load all active IBAC controls for this workspace
  const controls = await getActiveControls(workspace.id);

  // Find matching controls
  const matchedControls = controls.filter((control) =>
    matchesIntent(control, intent)
  );

  // Determine verdict based on matched controls
  const { verdict, riskLevel, reasoning, conditions } = resolveVerdict(
    matchedControls,
    intent
  );

  const evaluation: IBACEvaluation = {
    id: generateUUID(),
    intent,
    verdict,
    riskLevel,
    reasoning,
    matchedControls: matchedControls.map((c) => c.id),
    conditions,
    evaluatedAt: new Date().toISOString(),
    evaluationDurationMs: Date.now() - startTime,
  };

  // Log to immutable audit trail
  const decisionLog: IBACDecisionLog = {
    id: generateUUID(),
    evaluation,
    workspaceId: workspace.id,
    createdAt: new Date().toISOString(),
  };

  await persistDecisionLog(decisionLog);

  return {
    success: true,
    data: { evaluation },
  };
}

/**
 * GET /api/ibac/controls
 *
 * Lists all IBAC control templates for the workspace. Controls define
 * patterns for matching intents and their associated verdicts.
 *
 * Requires admin or owner role.
 */
export async function listControls(
  req: ListControlsRequest
): Promise<ApiResponse<ListControlsResponse>> {
  const { workspace, user } = req;

  if (!['admin', 'owner'].includes(user.role)) {
    return {
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Only admins and owners can view IBAC controls.',
      },
    };
  }

  const controls = await getAllControls(workspace.id);

  return {
    success: true,
    data: { controls },
  };
}

/**
 * PUT /api/ibac/controls/:id
 *
 * Updates an IBAC control's parameters. Supports partial updates.
 *
 * Changes take effect immediately for all subsequent evaluations.
 * The update is itself logged in the audit trail.
 *
 * Requires admin or owner role.
 */
export async function updateControl(
  req: UpdateControlRequest
): Promise<ApiResponse<UpdateControlResponse>> {
  const { workspace, user, body } = req;

  if (!['admin', 'owner'].includes(user.role)) {
    return {
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Only admins and owners can update IBAC controls.',
      },
    };
  }

  const control = await findControlById(req.params.id, workspace.id);
  if (!control) {
    return {
      success: false,
      error: {
        code: 'CONTROL_NOT_FOUND',
        message: 'IBAC control not found.',
      },
    };
  }

  // Apply partial update
  if (body.name !== undefined) control.name = body.name;
  if (body.description !== undefined) control.description = body.description;
  if (body.intentPattern !== undefined) control.intentPattern = body.intentPattern;
  if (body.resourcePattern !== undefined) control.resourcePattern = body.resourcePattern;
  if (body.defaultVerdict !== undefined) control.defaultVerdict = body.defaultVerdict;
  if (body.riskLevel !== undefined) control.riskLevel = body.riskLevel;
  if (body.conditions !== undefined) control.conditions = body.conditions;
  if (body.enabled !== undefined) control.enabled = body.enabled;
  control.updatedAt = new Date().toISOString();

  await persistControl(control);

  // Log the configuration change
  await persistDecisionLog({
    id: generateUUID(),
    evaluation: {
      id: generateUUID(),
      intent: {
        action: 'update_ibac_control',
        resource: `ibac_control:${control.id}`,
        requestorId: user.id,
        requestorType: 'user',
        context: { changes: body },
      },
      verdict: 'allow_with_logging',
      riskLevel: 'medium',
      reasoning: `IBAC control "${control.name}" updated by ${user.name}.`,
      matchedControls: [],
      evaluatedAt: new Date().toISOString(),
      evaluationDurationMs: 0,
    },
    workspaceId: workspace.id,
    createdAt: new Date().toISOString(),
  });

  return {
    success: true,
    data: { control },
  };
}

/**
 * GET /api/ibac/audit-log
 *
 * Returns the IBAC decision audit log. Every intent evaluation is
 * recorded here, creating an immutable trail of all agent decisions.
 *
 * Supports filtering by verdict, risk level, date range, and requestor.
 * This log is itself evidence for SOC 2 CC6.1 (Logical Access Controls).
 */
export async function getAuditLog(
  req: GetAuditLogRequest
): Promise<ApiResponse<GetAuditLogResponse>> {
  const { workspace, user } = req;
  const { page = 1, pageSize = 25, verdict, riskLevel, startDate, endDate, requestorId } =
    req.query;

  if (!['admin', 'owner', 'auditor'].includes(user.role)) {
    return {
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Insufficient permissions to view the IBAC audit log.',
      },
    };
  }

  const filters: Record<string, unknown> = { workspaceId: workspace.id };
  if (verdict) filters['evaluation.verdict'] = verdict;
  if (riskLevel) filters['evaluation.riskLevel'] = riskLevel;
  if (startDate) filters.startDate = startDate;
  if (endDate) filters.endDate = endDate;
  if (requestorId) filters['evaluation.intent.requestorId'] = requestorId;

  const result = await queryAuditLog(filters, page, pageSize);

  return {
    success: true,
    data: result,
  };
}

// ---------------------------------------------------------------------------
// IBAC Evaluation Engine
// ---------------------------------------------------------------------------

/**
 * Checks whether an IBAC control matches a given intent.
 * Uses pattern matching on the intent action and resource.
 * @internal
 */
function matchesIntent(control: IBACControl, intent: IBACIntent): boolean {
  const actionMatch = matchPattern(control.intentPattern, intent.action);
  const resourceMatch = matchPattern(control.resourcePattern, intent.resource);
  return actionMatch && resourceMatch;
}

/**
 * Converts a glob-style pattern to a regex and tests the value.
 * @internal
 */
function matchPattern(pattern: string, value: string): boolean {
  const regexStr = '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
  try {
    return new RegExp(regexStr, 'i').test(value);
  } catch {
    return false;
  }
}

/**
 * Resolves the final verdict from all matched controls.
 * Deny takes precedence, then escalate, then allow_with_logging, then allow.
 * @internal
 */
function resolveVerdict(
  matchedControls: IBACControl[],
  intent: IBACIntent
): {
  verdict: IBACEvaluation['verdict'];
  riskLevel: IBACEvaluation['riskLevel'];
  reasoning: string;
  conditions?: string[];
} {
  if (matchedControls.length === 0) {
    // Default: allow with logging when no controls match (fail-open with audit)
    return {
      verdict: 'allow_with_logging',
      riskLevel: 'low',
      reasoning: 'No IBAC controls matched this intent. Allowed with logging per default policy.',
    };
  }

  // Check for condition overrides first
  for (const control of matchedControls) {
    for (const condition of control.conditions) {
      const fieldValue = getNestedField(intent.context, condition.field);
      if (evaluateCondition(fieldValue, condition.operator, condition.value)) {
        return {
          verdict: condition.verdictOverride,
          riskLevel: control.riskLevel,
          reasoning: `Condition override on control "${control.name}": ${condition.field} ${condition.operator} ${condition.value}.`,
        };
      }
    }
  }

  // Priority-based verdict resolution
  const verdictPriority: IBACEvaluation['verdict'][] = [
    'deny',
    'escalate',
    'allow_with_logging',
    'allow',
  ];

  let highestPriorityVerdict: IBACEvaluation['verdict'] = 'allow';
  let highestRiskLevel: IBACEvaluation['riskLevel'] = 'low';
  const reasonParts: string[] = [];

  for (const control of matchedControls) {
    const verdictIndex = verdictPriority.indexOf(control.defaultVerdict);
    const currentIndex = verdictPriority.indexOf(highestPriorityVerdict);
    if (verdictIndex < currentIndex) {
      highestPriorityVerdict = control.defaultVerdict;
    }

    const riskOrder: IBACEvaluation['riskLevel'][] = ['critical', 'high', 'medium', 'low'];
    if (riskOrder.indexOf(control.riskLevel) < riskOrder.indexOf(highestRiskLevel)) {
      highestRiskLevel = control.riskLevel;
    }

    reasonParts.push(`Matched control "${control.name}" (${control.defaultVerdict}).`);
  }

  return {
    verdict: highestPriorityVerdict,
    riskLevel: highestRiskLevel,
    reasoning: reasonParts.join(' '),
  };
}

/** @internal */
function getNestedField(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((current, key) => {
    if (current && typeof current === 'object' && key in (current as Record<string, unknown>)) {
      return (current as Record<string, unknown>)[key];
    }
    return undefined;
  }, obj);
}

/** @internal */
function evaluateCondition(fieldValue: unknown, operator: string, conditionValue: unknown): boolean {
  switch (operator) {
    case 'eq':
      return fieldValue === conditionValue;
    case 'neq':
      return fieldValue !== conditionValue;
    case 'contains':
      return typeof fieldValue === 'string' && typeof conditionValue === 'string'
        ? fieldValue.includes(conditionValue)
        : false;
    case 'gt':
      return typeof fieldValue === 'number' && typeof conditionValue === 'number'
        ? fieldValue > conditionValue
        : false;
    case 'lt':
      return typeof fieldValue === 'number' && typeof conditionValue === 'number'
        ? fieldValue < conditionValue
        : false;
    case 'in':
      return Array.isArray(conditionValue) ? conditionValue.includes(fieldValue) : false;
    case 'not_in':
      return Array.isArray(conditionValue) ? !conditionValue.includes(fieldValue) : false;
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/** @internal */
async function getActiveControls(workspaceId: UUID): Promise<IBACControl[]> {
  const all = await getAllControls(workspaceId);
  return all.filter((c) => c.enabled);
}

/** @internal */
async function getAllControls(workspaceId: UUID): Promise<IBACControl[]> {
  void workspaceId;
  return [];
}

/** @internal */
async function findControlById(id: UUID, workspaceId: UUID): Promise<IBACControl | null> {
  void id;
  void workspaceId;
  return null;
}

/** @internal */
async function persistControl(control: IBACControl): Promise<void> {
  void control;
}

/** @internal */
async function persistDecisionLog(log: IBACDecisionLog): Promise<void> {
  void log;
}

/** @internal */
async function queryAuditLog(
  filters: Record<string, unknown>,
  page: number,
  pageSize: number
): Promise<PaginatedResponse<IBACDecisionLog>> {
  void filters;
  return { data: [], total: 0, page, pageSize, hasMore: false };
}

/** @internal */
function generateUUID(): UUID {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
