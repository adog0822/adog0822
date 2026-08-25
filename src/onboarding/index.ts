/**
 * LoxeAI Onboarding Module
 *
 * Barrel export for the complete onboarding questionnaire system.
 * Provides the question bank, engine, agent orchestrator, and AWS setup.
 */

// ─── Question Bank ────────────────────────────────────────────────────
export {
  QUESTION_BANK,
  ALL_QUESTIONS,
  SECTION_ORDER,
  SECTION_TITLES,
  getQuestionById,
  getQuestionsForSection,
} from "./questions";

// ─── Onboarding Engine ────────────────────────────────────────────────
export {
  createOnboardingSession,
  submitAnswer,
  getNextQuestion,
  getPreviousQuestion,
  skipQuestion,
  getProgress,
  getSectionSummary,
  getAllSectionSummaries,
} from "./engine";

export type {
  OnboardingProgress,
  SectionSummary,
  SubmitResult,
} from "./engine";

// ─── Agent Orchestrator ───────────────────────────────────────────────
export {
  triggerAgent,
  getAgentStatus,
  getAllAgentStatuses,
  cancelAgent,
  updateAgentProgress,
  startPendingAgent,
  getAgentSummary,
  resetAgentCounter,
} from "./agent-orchestrator";

// ─── AWS Setup ────────────────────────────────────────────────────────
export {
  generateAwsSetup,
  generateCloudFormationTemplate,
  generateExternalId,
  validateRoleArn,
} from "./aws-setup";
