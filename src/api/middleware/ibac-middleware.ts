/**
 * IBAC (Intent-Based Access Control) Middleware
 *
 * Express-style middleware that intercepts requests involving agent
 * actions, evaluates the agent's intent through the IBAC system,
 * and either allows the request to proceed or blocks it.
 *
 * Every decision — allow or deny — is logged to the evidence chain,
 * providing an immutable audit trail of all automated actions.
 *
 * The middleware attaches the IBAC evaluation result to the request
 * object so downstream handlers can access it.
 */

import type {
  IBACEvaluation,
  IBACIntent,
  IBACControl,
  IBACCondition,
  IBACDecisionLog,
  IBACVerdict,
  IBACRiskLevel,
  UUID,
} from '../../types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Extended request type with IBAC evaluation attached. */
export interface IBACRequest {
  /** Standard Express request properties */
  method: string;
  path: string;
  body: Record<string, unknown>;
  headers: Record<string, string | string[] | undefined>;
  /** Auth context — set by auth middleware */
  userId?: UUID;
  workspaceId?: UUID;
  userRole?: string;
  /** IBAC evaluation result — set by this middleware */
  ibacEvaluation?: IBACEvaluation;
}

export interface IBACResponse {
  status: (code: number) => IBACResponse;
  json: (body: unknown) => void;
}

export type IBACNextFunction = () => void;

export interface IBACMiddlewareOptions {
  /** Route patterns that should be evaluated through IBAC */
  protectedPatterns: string[];
  /** Whether to fail-open (allow) or fail-closed (deny) on errors */
  failMode: 'open' | 'closed';
  /** Custom intent parser, if the default is insufficient */
  intentParser?: (req: IBACRequest) => IBACIntent | null;
}

// ---------------------------------------------------------------------------
// Middleware Factory
// ---------------------------------------------------------------------------

/**
 * Creates the IBAC middleware function.
 *
 * Usage:
 * ```typescript
 * app.use(createIBACMiddleware({
 *   protectedPatterns: ['/api/evidence/scan', '/api/agent/*'],
 *   failMode: 'closed',
 * }));
 * ```
 */
export function createIBACMiddleware(options: IBACMiddlewareOptions) {
  const { protectedPatterns, failMode, intentParser } = options;

  return async function ibacMiddleware(
    req: IBACRequest,
    res: IBACResponse,
    next: IBACNextFunction
  ): Promise<void> {
    // Only evaluate requests that match protected patterns
    if (!shouldEvaluate(req.path, req.method, protectedPatterns)) {
      next();
      return;
    }

    // Parse the intent from the request
    const intent = intentParser
      ? intentParser(req)
      : parseIntentFromRequest(req);

    if (!intent) {
      // No intent detected — this is a regular user request, not an agent action
      next();
      return;
    }

    try {
      // Load active IBAC controls
      const controls = await loadActiveControls(req.workspaceId);

      // Evaluate the intent
      const evaluation = evaluateIntent(intent, controls);

      // Log the decision to the evidence chain
      await logDecision(evaluation, req.workspaceId);

      // Attach evaluation to the request for downstream handlers
      req.ibacEvaluation = evaluation;

      // Handle the verdict
      switch (evaluation.verdict) {
        case 'allow':
          next();
          return;

        case 'allow_with_logging':
          // Allow, but flag for enhanced audit logging
          await logEnhancedAudit(evaluation, req);
          next();
          return;

        case 'escalate':
          // Block and notify for human review
          await notifyEscalation(evaluation, req.workspaceId);
          res.status(403).json({
            success: false,
            error: {
              code: 'IBAC_ESCALATION',
              message: 'This action requires human approval before proceeding.',
              details: {
                evaluationId: evaluation.id,
                reasoning: evaluation.reasoning,
                riskLevel: evaluation.riskLevel,
                matchedControls: evaluation.matchedControls,
              },
            },
          });
          return;

        case 'deny':
          res.status(403).json({
            success: false,
            error: {
              code: 'IBAC_DENIED',
              message: 'This action has been denied by IBAC policy.',
              details: {
                evaluationId: evaluation.id,
                reasoning: evaluation.reasoning,
                riskLevel: evaluation.riskLevel,
                matchedControls: evaluation.matchedControls,
              },
            },
          });
          return;
      }
    } catch (error) {
      // Handle evaluation errors based on fail mode
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';

      await logEvaluationError(intent, errorMessage, req.workspaceId);

      if (failMode === 'closed') {
        res.status(500).json({
          success: false,
          error: {
            code: 'IBAC_ERROR',
            message: 'IBAC evaluation failed. Request blocked per fail-closed policy.',
            details: { error: errorMessage },
          },
        });
        return;
      }

      // Fail-open: allow but log the error
      next();
    }
  };
}

// ---------------------------------------------------------------------------
// Intent Parsing
// ---------------------------------------------------------------------------

/**
 * Determines if a request path/method should be evaluated by IBAC.
 * @internal
 */
function shouldEvaluate(
  path: string,
  method: string,
  patterns: string[]
): boolean {
  // Only evaluate state-changing methods by default
  const evaluateMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!evaluateMethods.includes(method.toUpperCase())) {
    return false;
  }

  return patterns.some((pattern) => {
    const regexStr = '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$';
    try {
      return new RegExp(regexStr).test(path);
    } catch {
      return false;
    }
  });
}

/**
 * Parses an IBAC intent from a request body.
 *
 * Looks for standard intent fields in the request body:
 * - `intent` object (explicit intent declaration)
 * - `agentId` or `agentAction` fields (agent-originated request)
 *
 * Returns null if the request does not contain an agent intent.
 * @internal
 */
function parseIntentFromRequest(req: IBACRequest): IBACIntent | null {
  const body = req.body;

  // Check for explicit intent declaration
  if (body.intent && typeof body.intent === 'object') {
    const intent = body.intent as Record<string, unknown>;
    if (intent.action && intent.resource) {
      return {
        action: String(intent.action),
        resource: String(intent.resource),
        requestorId: (intent.requestorId as UUID) ?? req.userId ?? '',
        requestorType: (intent.requestorType as 'agent' | 'user') ?? 'agent',
        context: (intent.context as Record<string, unknown>) ?? {},
      };
    }
  }

  // Check for agent action fields
  if (body.agentId || body.agentAction) {
    return {
      action: String(body.agentAction ?? body.action ?? req.method.toLowerCase()),
      resource: String(body.resource ?? req.path),
      requestorId: (body.agentId as UUID) ?? req.userId ?? '',
      requestorType: 'agent',
      context: {
        method: req.method,
        path: req.path,
        body: sanitizeBodyForLogging(body),
      },
    };
  }

  return null;
}

/**
 * Removes sensitive fields from request body before logging.
 * @internal
 */
function sanitizeBodyForLogging(body: Record<string, unknown>): Record<string, unknown> {
  const sensitiveFields = ['password', 'token', 'secret', 'apiKey', 'credentials'];
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(body)) {
    if (sensitiveFields.some((f) => key.toLowerCase().includes(f))) {
      sanitized[key] = '[REDACTED]';
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

// ---------------------------------------------------------------------------
// Evaluation Engine
// ---------------------------------------------------------------------------

/**
 * Evaluates an intent against a set of IBAC controls.
 * @internal
 */
function evaluateIntent(intent: IBACIntent, controls: IBACControl[]): IBACEvaluation {
  const startTime = Date.now();

  // Find matching controls
  const matched = controls.filter((control) => {
    const actionMatch = matchPattern(control.intentPattern, intent.action);
    const resourceMatch = matchPattern(control.resourcePattern, intent.resource);
    return actionMatch && resourceMatch;
  });

  // Resolve verdict
  const { verdict, riskLevel, reasoning, conditions } = resolveVerdict(matched, intent);

  return {
    id: generateUUID(),
    intent,
    verdict,
    riskLevel,
    reasoning,
    matchedControls: matched.map((c) => c.id),
    conditions,
    evaluatedAt: new Date().toISOString(),
    evaluationDurationMs: Date.now() - startTime,
  };
}

/**
 * Matches a glob-style pattern against a value.
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
 * Resolves the final verdict from matched controls.
 * Priority: deny > escalate > allow_with_logging > allow.
 * @internal
 */
function resolveVerdict(
  matchedControls: IBACControl[],
  intent: IBACIntent
): {
  verdict: IBACVerdict;
  riskLevel: IBACRiskLevel;
  reasoning: string;
  conditions?: string[];
} {
  if (matchedControls.length === 0) {
    return {
      verdict: 'allow_with_logging',
      riskLevel: 'low',
      reasoning: 'No IBAC controls matched. Allowed with logging per default policy.',
    };
  }

  // Check condition overrides
  for (const control of matchedControls) {
    for (const condition of control.conditions) {
      const fieldValue = getNestedField(intent.context, condition.field);
      if (evaluateCondition(fieldValue, condition)) {
        return {
          verdict: condition.verdictOverride,
          riskLevel: control.riskLevel,
          reasoning: `Condition override on "${control.name}": ${condition.field} ${condition.operator} matched.`,
        };
      }
    }
  }

  // Priority resolution
  const verdictPriority: IBACVerdict[] = ['deny', 'escalate', 'allow_with_logging', 'allow'];
  const riskPriority: IBACRiskLevel[] = ['critical', 'high', 'medium', 'low'];

  let finalVerdict: IBACVerdict = 'allow';
  let finalRisk: IBACRiskLevel = 'low';
  const reasons: string[] = [];

  for (const control of matchedControls) {
    if (verdictPriority.indexOf(control.defaultVerdict) < verdictPriority.indexOf(finalVerdict)) {
      finalVerdict = control.defaultVerdict;
    }
    if (riskPriority.indexOf(control.riskLevel) < riskPriority.indexOf(finalRisk)) {
      finalRisk = control.riskLevel;
    }
    reasons.push(`"${control.name}" (${control.defaultVerdict})`);
  }

  return {
    verdict: finalVerdict,
    riskLevel: finalRisk,
    reasoning: `Matched controls: ${reasons.join(', ')}.`,
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
function evaluateCondition(fieldValue: unknown, condition: IBACCondition): boolean {
  const { operator, value } = condition;
  switch (operator) {
    case 'eq':
      return fieldValue === value;
    case 'neq':
      return fieldValue !== value;
    case 'contains':
      return typeof fieldValue === 'string' && typeof value === 'string'
        ? fieldValue.includes(value)
        : false;
    case 'gt':
      return typeof fieldValue === 'number' && typeof value === 'number'
        ? fieldValue > value
        : false;
    case 'lt':
      return typeof fieldValue === 'number' && typeof value === 'number'
        ? fieldValue < value
        : false;
    case 'in':
      return Array.isArray(value) ? value.includes(fieldValue) : false;
    case 'not_in':
      return Array.isArray(value) ? !value.includes(fieldValue) : false;
    default:
      return false;
  }
}

// ---------------------------------------------------------------------------
// Persistence & Notifications (stubs)
// ---------------------------------------------------------------------------

/** @internal */
async function loadActiveControls(workspaceId: UUID | undefined): Promise<IBACControl[]> {
  void workspaceId;
  return [];
}

/** @internal */
async function logDecision(evaluation: IBACEvaluation, workspaceId: UUID | undefined): Promise<void> {
  const log: IBACDecisionLog = {
    id: generateUUID(),
    evaluation,
    workspaceId: workspaceId ?? '',
    createdAt: new Date().toISOString(),
  };
  // TODO: Persist to immutable audit log
  void log;
}

/** @internal */
async function logEnhancedAudit(evaluation: IBACEvaluation, req: IBACRequest): Promise<void> {
  // TODO: Write enhanced audit entry with full request context
  void evaluation;
  void req;
}

/** @internal */
async function logEvaluationError(
  intent: IBACIntent,
  error: string,
  workspaceId: UUID | undefined
): Promise<void> {
  // TODO: Log evaluation failure
  void intent;
  void error;
  void workspaceId;
}

/** @internal */
async function notifyEscalation(
  evaluation: IBACEvaluation,
  workspaceId: UUID | undefined
): Promise<void> {
  // TODO: Notify workspace admins of escalated action
  void evaluation;
  void workspaceId;
}

/** @internal */
function generateUUID(): UUID {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
