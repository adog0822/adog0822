/**
 * Onboarding API Route Handlers
 *
 * Manages the guided onboarding flow for new LoxeAI workspaces.
 * Walks the user through company profile, integration setup, scope
 * selection, and initial evidence collection.
 */

import type {
  ApiResponse,
  AuthenticatedRequest,
  OnboardingSession,
  OnboardingAnswer,
  OnboardingQuestion,
  OnboardingSummary,
  AgentStatus,
  EvidenceSourceType,
  UUID,
} from '../../types';

// ---------------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------------

export interface StartOnboardingRequest extends AuthenticatedRequest {}

export interface StartOnboardingResponse {
  session: OnboardingSession;
  firstQuestion: OnboardingQuestion;
}

export interface SubmitAnswerRequest extends AuthenticatedRequest {
  body: {
    sessionId: UUID;
    questionId: string;
    answer: string | string[] | boolean;
  };
}

export interface SubmitAnswerResponse {
  /** Updated session with new progress */
  session: OnboardingSession;
  /** Next question, or null if stage complete */
  nextQuestion: OnboardingQuestion | null;
  /** If stage just completed, info about next stage */
  nextStage?: {
    stage: OnboardingSession['currentStage'];
    description: string;
  };
}

export interface GetProgressRequest extends AuthenticatedRequest {
  query: {
    sessionId: UUID;
  };
}

export interface GetProgressResponse {
  session: OnboardingSession;
  agentStatuses: AgentStatus[];
}

export interface TriggerAgentRequest extends AuthenticatedRequest {
  body: {
    sessionId: UUID;
    integrationType: EvidenceSourceType;
    integrationConfig: Record<string, unknown>;
  };
}

export interface TriggerAgentResponse {
  agentStatus: AgentStatus;
}

export interface GetSummaryRequest extends AuthenticatedRequest {
  query: {
    sessionId: UUID;
  };
}

export interface GetSummaryResponse {
  summary: OnboardingSummary;
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

/**
 * POST /api/onboarding/start
 *
 * Creates a new onboarding session for the authenticated workspace.
 * Returns the session and the first question in the onboarding flow.
 *
 * Only one active onboarding session is allowed per workspace. If one
 * already exists and is incomplete, it is resumed instead of creating
 * a new one.
 */
export async function startOnboarding(
  req: StartOnboardingRequest
): Promise<ApiResponse<StartOnboardingResponse>> {
  const { workspace } = req;

  // Check for existing incomplete session
  const existingSession = await findActiveOnboardingSession(workspace.id);
  if (existingSession) {
    const currentQuestion = await getQuestionForSession(existingSession);
    return {
      success: true,
      data: {
        session: existingSession,
        firstQuestion: currentQuestion,
      },
    };
  }

  const session: OnboardingSession = {
    id: generateUUID(),
    workspaceId: workspace.id,
    currentStage: 'welcome',
    completedStages: [],
    answers: {},
    agentStatuses: [],
    progress: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  await persistOnboardingSession(session);

  const firstQuestion = await getFirstQuestion();

  return {
    success: true,
    data: {
      session,
      firstQuestion,
    },
  };
}

/**
 * POST /api/onboarding/answer
 *
 * Submits an answer to the current onboarding question and advances the flow.
 * Validates the answer, stores it, calculates updated progress, and returns
 * the next question or stage transition.
 */
export async function submitAnswer(
  req: SubmitAnswerRequest
): Promise<ApiResponse<SubmitAnswerResponse>> {
  const { body, workspace } = req;

  const session = await getOnboardingSession(body.sessionId, workspace.id);
  if (!session) {
    return {
      success: false,
      error: {
        code: 'SESSION_NOT_FOUND',
        message: 'Onboarding session not found or does not belong to this workspace.',
      },
    };
  }

  // Validate and store the answer
  const question = await getQuestionById(body.questionId);
  if (!question) {
    return {
      success: false,
      error: {
        code: 'QUESTION_NOT_FOUND',
        message: `Question "${body.questionId}" not found.`,
      },
    };
  }

  const validationError = validateAnswer(question, body.answer);
  if (validationError) {
    return {
      success: false,
      error: {
        code: 'INVALID_ANSWER',
        message: validationError,
      },
    };
  }

  const answer: OnboardingAnswer = {
    questionId: body.questionId,
    value: body.answer,
    answeredAt: new Date().toISOString(),
  };

  session.answers[body.questionId] = answer;
  session.updatedAt = new Date().toISOString();

  // Determine next question or stage transition
  let nextQuestion: OnboardingQuestion | null = null;
  let nextStage: SubmitAnswerResponse['nextStage'] | undefined;

  if (question.nextQuestionId) {
    nextQuestion = await getQuestionById(question.nextQuestionId);
  } else {
    // End of current stage — advance to next
    const transition = advanceStage(session);
    if (transition) {
      session.currentStage = transition.stage;
      session.completedStages.push(question.stage);
      nextStage = transition;
      nextQuestion = await getFirstQuestionForStage(transition.stage);
    } else {
      // Onboarding complete
      session.currentStage = 'complete';
      session.completedStages.push(question.stage);
    }
  }

  session.progress = calculateProgress(session);
  await persistOnboardingSession(session);

  return {
    success: true,
    data: {
      session,
      nextQuestion,
      nextStage,
    },
  };
}

/**
 * GET /api/onboarding/progress
 *
 * Returns the current onboarding session progress including the status
 * of any background agents (integration connectors collecting initial evidence).
 */
export async function getProgress(
  req: GetProgressRequest
): Promise<ApiResponse<GetProgressResponse>> {
  const session = await getOnboardingSession(req.query.sessionId, req.workspace.id);
  if (!session) {
    return {
      success: false,
      error: {
        code: 'SESSION_NOT_FOUND',
        message: 'Onboarding session not found.',
      },
    };
  }

  return {
    success: true,
    data: {
      session,
      agentStatuses: session.agentStatuses,
    },
  };
}

/**
 * POST /api/onboarding/trigger-agent
 *
 * Triggers a background agent to connect to an integration and begin
 * initial evidence collection. The agent runs asynchronously; poll
 * GET /api/onboarding/progress for status updates.
 *
 * Each integration type (AWS, GitHub, Okta, etc.) has its own agent
 * that knows how to authenticate and collect relevant evidence.
 */
export async function triggerAgent(
  req: TriggerAgentRequest
): Promise<ApiResponse<TriggerAgentResponse>> {
  const { body, workspace } = req;

  const session = await getOnboardingSession(body.sessionId, workspace.id);
  if (!session) {
    return {
      success: false,
      error: {
        code: 'SESSION_NOT_FOUND',
        message: 'Onboarding session not found.',
      },
    };
  }

  // Verify we're at the right stage
  if (session.currentStage !== 'integrations' && session.currentStage !== 'agent-setup') {
    return {
      success: false,
      error: {
        code: 'INVALID_STAGE',
        message: 'Agents can only be triggered during the integrations or agent-setup stages.',
      },
    };
  }

  const agentStatus: AgentStatus = {
    agentId: generateUUID(),
    integrationId: generateUUID(),
    integrationType: body.integrationType,
    status: 'pending',
    progress: 0,
    message: `Initializing ${body.integrationType} integration agent...`,
    startedAt: new Date().toISOString(),
  };

  session.agentStatuses.push(agentStatus);
  await persistOnboardingSession(session);

  // Dispatch the agent to run in the background
  await dispatchIntegrationAgent(agentStatus, body.integrationConfig);

  return {
    success: true,
    data: { agentStatus },
  };
}

/**
 * GET /api/onboarding/summary
 *
 * Returns a comprehensive summary of the completed onboarding.
 * Includes company profile, selected integrations, scoped categories,
 * and initial readiness assessment.
 *
 * Only available once onboarding reaches the 'review' or 'complete' stage.
 */
export async function getOnboardingSummary(
  req: GetSummaryRequest
): Promise<ApiResponse<GetSummaryResponse>> {
  const session = await getOnboardingSession(req.query.sessionId, req.workspace.id);
  if (!session) {
    return {
      success: false,
      error: {
        code: 'SESSION_NOT_FOUND',
        message: 'Onboarding session not found.',
      },
    };
  }

  if (session.currentStage !== 'review' && session.currentStage !== 'complete') {
    return {
      success: false,
      error: {
        code: 'NOT_READY',
        message: 'Onboarding summary is available only after all stages are completed.',
      },
    };
  }

  const summary = await buildOnboardingSummary(session);

  return {
    success: true,
    data: { summary },
  };
}

// ---------------------------------------------------------------------------
// Internal Helpers (implementations would connect to persistence layer)
// ---------------------------------------------------------------------------

/** @internal */
async function findActiveOnboardingSession(workspaceId: UUID): Promise<OnboardingSession | null> {
  // TODO: Query persistence layer for active session
  void workspaceId;
  return null;
}

/** @internal */
async function getOnboardingSession(
  sessionId: UUID,
  workspaceId: UUID
): Promise<OnboardingSession | null> {
  // TODO: Query persistence layer
  void sessionId;
  void workspaceId;
  return null;
}

/** @internal */
async function persistOnboardingSession(session: OnboardingSession): Promise<void> {
  // TODO: Persist to database
  void session;
}

/** @internal */
async function getFirstQuestion(): Promise<OnboardingQuestion> {
  return {
    id: 'welcome-1',
    stage: 'welcome',
    text: 'Welcome to LoxeAI! What is your company name?',
    type: 'text',
    required: true,
    nextQuestionId: 'welcome-2',
  };
}

/** @internal */
async function getQuestionForSession(session: OnboardingSession): Promise<OnboardingQuestion> {
  // TODO: Determine current question based on session state
  void session;
  return getFirstQuestion();
}

/** @internal */
async function getQuestionById(questionId: string): Promise<OnboardingQuestion | null> {
  // TODO: Look up question by ID
  void questionId;
  return null;
}

/** @internal */
async function getFirstQuestionForStage(
  stage: OnboardingSession['currentStage']
): Promise<OnboardingQuestion | null> {
  // TODO: Return first question for the given stage
  void stage;
  return null;
}

/** @internal */
function validateAnswer(
  question: OnboardingQuestion,
  answer: string | string[] | boolean
): string | null {
  if (question.required && (answer === '' || answer === null || answer === undefined)) {
    return 'This question requires an answer.';
  }
  if (question.type === 'select' && question.options) {
    const validValues = question.options.map((o) => o.value);
    if (typeof answer === 'string' && !validValues.includes(answer)) {
      return `Invalid selection. Valid options: ${validValues.join(', ')}`;
    }
  }
  return null;
}

/** @internal */
function advanceStage(
  session: OnboardingSession
): { stage: OnboardingSession['currentStage']; description: string } | null {
  const stageOrder: OnboardingSession['currentStage'][] = [
    'welcome',
    'company-profile',
    'integrations',
    'scope-selection',
    'agent-setup',
    'initial-scan',
    'review',
    'complete',
  ];
  const currentIndex = stageOrder.indexOf(session.currentStage);
  if (currentIndex < 0 || currentIndex >= stageOrder.length - 1) return null;
  const nextStage = stageOrder[currentIndex + 1];
  const descriptions: Record<string, string> = {
    'company-profile': 'Tell us about your organization.',
    integrations: 'Connect your cloud and SaaS services.',
    'scope-selection': 'Select which Trust Services Categories to include.',
    'agent-setup': 'Configure evidence collection agents.',
    'initial-scan': 'Running initial evidence scan across your integrations.',
    review: 'Review your setup and readiness score.',
    complete: 'Onboarding complete!',
  };
  return { stage: nextStage, description: descriptions[nextStage] ?? '' };
}

/** @internal */
function calculateProgress(session: OnboardingSession): number {
  const totalStages = 7; // excluding 'complete'
  return Math.round((session.completedStages.length / totalStages) * 100);
}

/** @internal */
async function dispatchIntegrationAgent(
  agentStatus: AgentStatus,
  config: Record<string, unknown>
): Promise<void> {
  // TODO: Dispatch background agent via job queue
  void agentStatus;
  void config;
}

/** @internal */
async function buildOnboardingSummary(session: OnboardingSession): Promise<OnboardingSummary> {
  // TODO: Build summary from session data
  return {
    session,
    companyProfile: {},
    selectedIntegrations: [],
    scopedCategories: [],
    controlCount: 0,
    evidenceCollected: 0,
    readinessScore: 0,
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
