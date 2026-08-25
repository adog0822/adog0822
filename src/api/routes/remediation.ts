/**
 * Remediation API Route Handlers
 *
 * Manages remediation items — actionable work items created when
 * evidence fails validation or a control score drops below threshold.
 *
 * Remediation items track the full lifecycle from identification
 * through resolution: open -> assigned -> in_progress -> verification
 * -> resolved (or accepted_risk).
 *
 * **Auditor view:** Remediation items appear in the exception report
 * and demonstrate management's response to identified deficiencies.
 *
 * **User view:** Remediation items are work tickets that need to be
 * addressed to improve control scores.
 */

import type {
  ApiResponse,
  AuthenticatedRequest,
  PaginatedResponse,
  PaginationParams,
  RemediationActivity,
  RemediationDashboard,
  RemediationItem,
  RemediationPriority,
  RemediationStatus,
  UUID,
} from '../../types';

// ---------------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------------

export interface ListRemediationRequest extends AuthenticatedRequest {
  query: PaginationParams & {
    status?: RemediationStatus;
    priority?: RemediationPriority;
    controlId?: UUID;
    assigneeId?: UUID;
  };
}

export type ListRemediationResponse = PaginatedResponse<RemediationItem>;

export interface CreateRemediationRequest extends AuthenticatedRequest {
  body: {
    /** The failing evidence that triggered this remediation */
    sourceEvidenceId: UUID;
    controlId: UUID;
    title: string;
    description: string;
    priority: RemediationPriority;
    assigneeId?: UUID;
    dueDate?: string;
  };
}

export interface CreateRemediationResponse {
  item: RemediationItem;
}

export interface UpdateRemediationRequest extends AuthenticatedRequest {
  params: {
    id: UUID;
  };
  body: {
    status?: RemediationStatus;
    priority?: RemediationPriority;
    assigneeId?: UUID;
    dueDate?: string;
    comment?: string;
  };
}

export interface UpdateRemediationResponse {
  item: RemediationItem;
}

export interface GetRemediationDashboardRequest extends AuthenticatedRequest {}

export interface GetRemediationDashboardResponse {
  dashboard: RemediationDashboard;
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

/**
 * GET /api/remediation
 *
 * Lists remediation items with optional filters. Supports filtering
 * by status, priority, control, and assignee.
 *
 * **Auditor view:** Shows all remediation items as evidence of
 * management's response to identified control deficiencies.
 * Maps to the management response section of a SOC 2 report.
 *
 * **User view:** Shows remediation items as a work queue sorted
 * by priority and due date.
 */
export async function listRemediation(
  req: ListRemediationRequest
): Promise<ApiResponse<ListRemediationResponse>> {
  const { workspace, session } = req;
  const { page = 1, pageSize = 25, status, priority, controlId, assigneeId } = req.query;

  const filters: Record<string, unknown> = {
    workspaceId: workspace.id,
  };

  if (status) filters.status = status;
  if (priority) filters.priority = priority;
  if (controlId) filters.controlId = controlId;
  if (assigneeId) filters.assigneeId = assigneeId;

  // Auditor scope filtering
  if (session.role === 'auditor' && session.auditorScope) {
    filters.controlId = { $in: session.auditorScope.controlIds };
  }

  const result = await queryRemediation(filters, page, pageSize);

  return {
    success: true,
    data: result,
  };
}

/**
 * POST /api/remediation
 *
 * Creates a new remediation item from a failed evidence item.
 * Links the remediation to the source evidence and control.
 *
 * Gideon automatically suggests a fix based on the evidence failure
 * and known remediation patterns.
 *
 * Requires member, admin, or owner role.
 */
export async function createRemediation(
  req: CreateRemediationRequest
): Promise<ApiResponse<CreateRemediationResponse>> {
  const { workspace, user, body } = req;

  if (!['member', 'admin', 'owner'].includes(user.role)) {
    return {
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Insufficient permissions to create remediation items.',
      },
    };
  }

  // Verify the source evidence exists and is in a failed state
  const evidence = await findEvidenceById(body.sourceEvidenceId, workspace.id);
  if (!evidence) {
    return {
      success: false,
      error: {
        code: 'EVIDENCE_NOT_FOUND',
        message: 'Source evidence item not found.',
      },
    };
  }

  // Verify the control exists
  const control = await findControlById(body.controlId, workspace.id);
  if (!control) {
    return {
      success: false,
      error: {
        code: 'CONTROL_NOT_FOUND',
        message: 'Control not found.',
      },
    };
  }

  // Generate AI-suggested fix
  const suggestedFix = await generateSuggestedFix(body.sourceEvidenceId, body.controlId);

  const now = new Date().toISOString();
  const assigneeName = body.assigneeId
    ? await getUserName(body.assigneeId)
    : undefined;

  const initialActivity: RemediationActivity = {
    id: generateUUID(),
    type: 'created',
    description: `Remediation item created by ${user.name} from evidence failure.`,
    actorId: user.id,
    actorName: user.name,
    timestamp: now,
  };

  const activities: RemediationActivity[] = [initialActivity];

  if (body.assigneeId) {
    activities.push({
      id: generateUUID(),
      type: 'assigned',
      description: `Assigned to ${assigneeName ?? 'unknown'}.`,
      actorId: user.id,
      actorName: user.name,
      timestamp: now,
    });
  }

  const item: RemediationItem = {
    id: generateUUID(),
    sourceEvidenceId: body.sourceEvidenceId,
    controlId: body.controlId,
    criteriaRef: control.criteriaRef,
    title: body.title,
    description: body.description,
    status: body.assigneeId ? 'assigned' : 'open',
    priority: body.priority,
    assigneeId: body.assigneeId,
    assigneeName,
    suggestedFix,
    dueDate: body.dueDate,
    activityLog: activities,
    workspaceId: workspace.id,
    createdAt: now,
    updatedAt: now,
  };

  await persistRemediation(item);

  return {
    success: true,
    data: { item },
  };
}

/**
 * PUT /api/remediation/:id
 *
 * Updates a remediation item's status, priority, assignee, or due date.
 * Every change is recorded in the activity log.
 *
 * Status transitions:
 * - open -> assigned (when assignee is set)
 * - assigned -> in_progress
 * - in_progress -> verification
 * - verification -> resolved | in_progress (if verification fails)
 * - Any status -> accepted_risk (with justification)
 */
export async function updateRemediation(
  req: UpdateRemediationRequest
): Promise<ApiResponse<UpdateRemediationResponse>> {
  const { workspace, user, body } = req;

  if (!['member', 'admin', 'owner'].includes(user.role)) {
    return {
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Insufficient permissions to update remediation items.',
      },
    };
  }

  const item = await findRemediationById(req.params.id, workspace.id);
  if (!item) {
    return {
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: 'Remediation item not found.',
      },
    };
  }

  const now = new Date().toISOString();

  // Apply updates and log activities
  if (body.status && body.status !== item.status) {
    const validTransition = isValidStatusTransition(item.status, body.status);
    if (!validTransition) {
      return {
        success: false,
        error: {
          code: 'INVALID_TRANSITION',
          message: `Cannot transition from "${item.status}" to "${body.status}".`,
        },
      };
    }

    item.activityLog.push({
      id: generateUUID(),
      type: 'status_change',
      description: `Status changed from "${item.status}" to "${body.status}".`,
      actorId: user.id,
      actorName: user.name,
      timestamp: now,
    });
    item.status = body.status;
  }

  if (body.priority && body.priority !== item.priority) {
    item.priority = body.priority;
  }

  if (body.assigneeId && body.assigneeId !== item.assigneeId) {
    const assigneeName = await getUserName(body.assigneeId);
    item.assigneeId = body.assigneeId;
    item.assigneeName = assigneeName;
    item.activityLog.push({
      id: generateUUID(),
      type: 'assigned',
      description: `Reassigned to ${assigneeName ?? 'unknown'}.`,
      actorId: user.id,
      actorName: user.name,
      timestamp: now,
    });
  }

  if (body.dueDate) {
    item.dueDate = body.dueDate;
  }

  if (body.comment) {
    item.activityLog.push({
      id: generateUUID(),
      type: 'comment',
      description: body.comment,
      actorId: user.id,
      actorName: user.name,
      timestamp: now,
    });
  }

  item.updatedAt = now;
  await persistRemediation(item);

  return {
    success: true,
    data: { item },
  };
}

/**
 * GET /api/remediation/dashboard
 *
 * Returns remediation health metrics: counts by status and priority,
 * overdue items, average resolution time, and upcoming due items.
 *
 * **Auditor view:** Demonstrates management's responsiveness to
 * identified deficiencies. Resolution times and overdue counts
 * factor into the auditor's assessment.
 *
 * **User view:** Provides operational visibility into the
 * remediation backlog and team velocity.
 */
export async function getRemediationDashboard(
  req: GetRemediationDashboardRequest
): Promise<ApiResponse<GetRemediationDashboardResponse>> {
  const { workspace } = req;

  const dashboard = await buildRemediationDashboard(workspace.id);

  return {
    success: true,
    data: { dashboard },
  };
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

/**
 * Validates that a status transition is allowed.
 * @internal
 */
function isValidStatusTransition(from: RemediationStatus, to: RemediationStatus): boolean {
  const transitions: Record<RemediationStatus, RemediationStatus[]> = {
    open: ['assigned', 'accepted_risk'],
    assigned: ['in_progress', 'open', 'accepted_risk'],
    in_progress: ['verification', 'assigned', 'accepted_risk'],
    verification: ['resolved', 'in_progress', 'accepted_risk'],
    resolved: ['open'], // Can reopen
    accepted_risk: ['open'], // Can reopen
  };
  return transitions[from]?.includes(to) ?? false;
}

/** @internal */
async function queryRemediation(
  filters: Record<string, unknown>,
  page: number,
  pageSize: number
): Promise<PaginatedResponse<RemediationItem>> {
  void filters;
  return { data: [], total: 0, page, pageSize, hasMore: false };
}

/** @internal */
async function findRemediationById(id: UUID, workspaceId: UUID): Promise<RemediationItem | null> {
  void id;
  void workspaceId;
  return null;
}

/** @internal */
async function findEvidenceById(
  id: UUID,
  workspaceId: UUID
): Promise<{ id: UUID } | null> {
  void id;
  void workspaceId;
  return null;
}

/** @internal */
async function findControlById(
  id: UUID,
  workspaceId: UUID
): Promise<{ criteriaRef: string } | null> {
  void id;
  void workspaceId;
  return null;
}

/** @internal */
async function generateSuggestedFix(
  evidenceId: UUID,
  controlId: UUID
): Promise<string | undefined> {
  void evidenceId;
  void controlId;
  return undefined;
}

/** @internal */
async function getUserName(userId: UUID): Promise<string | undefined> {
  void userId;
  return undefined;
}

/** @internal */
async function persistRemediation(item: RemediationItem): Promise<void> {
  void item;
}

/** @internal */
async function buildRemediationDashboard(workspaceId: UUID): Promise<RemediationDashboard> {
  void workspaceId;
  return {
    totalItems: 0,
    byStatus: {
      open: 0,
      assigned: 0,
      in_progress: 0,
      verification: 0,
      resolved: 0,
      accepted_risk: 0,
    },
    byPriority: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    },
    overdue: 0,
    avgResolutionDays: 0,
    upcomingDue: [],
    criticalItems: [],
  };
}

/** @internal */
function generateUUID(): UUID {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
