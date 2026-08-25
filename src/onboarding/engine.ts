/**
 * LoxeAI Onboarding Engine
 *
 * State machine that drives the questionnaire flow.
 * Tracks progress, validates responses, handles conditional questions,
 * and triggers background agents when integration options are selected.
 */

import type {
  OnboardingSession,
  OnboardingSection,
  OnboardingResponse,
  OnboardingQuestion,
  BackgroundAgentStatus,
  WorkspaceId,
} from "../types/index";

import {
  SECTION_ORDER,
  SECTION_TITLES,
  QUESTION_BANK,
  ALL_QUESTIONS,
  getQuestionById,
  getQuestionsForSection,
} from "./questions";

import { triggerAgent } from "./agent-orchestrator";

// ─── Types ────────────────────────────────────────────────────────────

export interface OnboardingProgress {
  currentSection: OnboardingSection;
  currentSectionTitle: string;
  currentQuestionIndex: number;
  totalQuestionsInSection: number;
  completedSections: OnboardingSection[];
  totalSections: number;
  overallPercentage: number;
  isComplete: boolean;
}

export interface SectionSummary {
  section: OnboardingSection;
  title: string;
  totalQuestions: number;
  answeredQuestions: number;
  isComplete: boolean;
  responses: OnboardingResponse[];
}

export interface SubmitResult {
  success: boolean;
  error?: string;
  agentsTriggered: string[];
  nextQuestion: OnboardingQuestion | null;
  progress: OnboardingProgress;
}

// ─── Session Factory ──────────────────────────────────────────────────

/**
 * Create a fresh onboarding session for a workspace.
 */
export function createOnboardingSession(workspaceId: WorkspaceId): OnboardingSession {
  return {
    workspaceId,
    responses: [],
    currentSection: SECTION_ORDER[0],
    completedSections: [],
    backgroundAgents: [],
    startedAt: new Date().toISOString(),
  };
}

// ─── Conditional Logic ────────────────────────────────────────────────

/**
 * Determine whether a question should be shown based on dependsOn rules
 * and the current session responses.
 */
function isQuestionApplicable(
  question: OnboardingQuestion,
  responses: OnboardingResponse[]
): boolean {
  if (!question.dependsOn) return true;

  const dependency = responses.find((r) => r.questionId === question.dependsOn!.questionId);
  if (!dependency) return false;

  const requiredValues = Array.isArray(question.dependsOn.value)
    ? question.dependsOn.value
    : [question.dependsOn.value];

  if (Array.isArray(dependency.value)) {
    return requiredValues.some((v) => (dependency.value as string[]).includes(v));
  }

  return requiredValues.includes(String(dependency.value));
}

/**
 * Get the list of applicable questions for a section given current responses.
 */
function getApplicableQuestions(
  section: OnboardingSection,
  responses: OnboardingResponse[]
): OnboardingQuestion[] {
  return getQuestionsForSection(section).filter((q) => isQuestionApplicable(q, responses));
}

// ─── Validation ───────────────────────────────────────────────────────

/**
 * Validate a response value against its question definition.
 */
function validateResponse(
  question: OnboardingQuestion,
  value: string | string[] | number
): string | null {
  // Required check
  if (question.required) {
    if (value === "" || value === null || value === undefined) {
      return "This question is required.";
    }
    if (Array.isArray(value) && value.length === 0) {
      return "Please select at least one option.";
    }
  }

  // Type-specific validation
  switch (question.type) {
    case "single-select":
    case "dropdown": {
      if (typeof value !== "string") {
        return "Please select a single option.";
      }
      if (question.options && !question.options.some((o) => o.value === value)) {
        return "Invalid selection.";
      }
      break;
    }
    case "multi-select": {
      if (!Array.isArray(value)) {
        return "Please select one or more options.";
      }
      if (question.options) {
        const validValues = new Set(question.options.map((o) => o.value));
        const invalid = value.filter((v) => !validValues.has(v));
        if (invalid.length > 0) {
          return `Invalid selection(s): ${invalid.join(", ")}`;
        }
      }
      break;
    }
    case "text": {
      if (typeof value !== "string") {
        return "Please provide a text response.";
      }
      break;
    }
    case "number": {
      if (typeof value !== "number" || Number.isNaN(value)) {
        return "Please provide a valid number.";
      }
      break;
    }
  }

  return null;
}

// ─── Agent Triggering ─────────────────────────────────────────────────

/**
 * Check selected options for agent triggers and fire them.
 * Returns the list of integration keys that were triggered.
 */
function processAgentTriggers(
  question: OnboardingQuestion,
  value: string | string[] | number,
  session: OnboardingSession
): string[] {
  const triggered: string[] = [];

  if (!question.options) return triggered;

  const selectedValues = Array.isArray(value) ? value : [String(value)];

  for (const optionValue of selectedValues) {
    const option = question.options.find((o) => o.value === optionValue);
    const trigger = option?.triggersAgent ?? question.triggersAgent;

    if (trigger) {
      // Don't re-trigger an agent that's already running or completed
      const existing = session.backgroundAgents.find(
        (a) => a.integration === trigger.integrationKey && a.type === trigger.type
      );
      if (!existing) {
        const agentStatus = triggerAgent(trigger);
        session.backgroundAgents.push(agentStatus);
        triggered.push(trigger.integrationKey);
      }
    }
  }

  return triggered;
}

// ─── Core Engine Functions ────────────────────────────────────────────

/**
 * Submit an answer for a question and advance the session.
 */
export function submitAnswer(
  session: OnboardingSession,
  questionId: string,
  value: string | string[] | number
): SubmitResult {
  const question = getQuestionById(questionId);

  if (!question) {
    return {
      success: false,
      error: `Question "${questionId}" not found.`,
      agentsTriggered: [],
      nextQuestion: getNextQuestion(session),
      progress: getProgress(session),
    };
  }

  // Validate
  const validationError = validateResponse(question, value);
  if (validationError) {
    return {
      success: false,
      error: validationError,
      agentsTriggered: [],
      nextQuestion: question,
      progress: getProgress(session),
    };
  }

  // Upsert the response (overwrite if already answered)
  const existingIndex = session.responses.findIndex((r) => r.questionId === questionId);
  const response: OnboardingResponse = {
    questionId,
    value,
    answeredAt: new Date().toISOString(),
  };

  if (existingIndex >= 0) {
    session.responses[existingIndex] = response;
  } else {
    session.responses.push(response);
  }

  // Process agent triggers
  const agentsTriggered = processAgentTriggers(question, value, session);
  if (agentsTriggered.length > 0) {
    response.agentTriggered = true;
  }

  // Advance section if all applicable questions in the current section are answered
  updateCompletedSections(session);

  const nextQuestion = getNextQuestion(session);
  const progress = getProgress(session);

  // Mark complete if no more questions
  if (!nextQuestion && progress.isComplete && !session.completedAt) {
    session.completedAt = new Date().toISOString();
  }

  return {
    success: true,
    agentsTriggered,
    nextQuestion,
    progress,
  };
}

/**
 * Get the next unanswered question in the current flow.
 * Returns null if all questions are answered.
 */
export function getNextQuestion(session: OnboardingSession): OnboardingQuestion | null {
  const answeredIds = new Set(session.responses.map((r) => r.questionId));

  // Start from the current section and work forward
  const currentSectionIndex = SECTION_ORDER.indexOf(session.currentSection);

  for (let i = currentSectionIndex; i < SECTION_ORDER.length; i++) {
    const section = SECTION_ORDER[i];
    const questions = getApplicableQuestions(section, session.responses);

    for (const question of questions) {
      if (!answeredIds.has(question.id)) {
        // Update current section if we've moved forward
        if (section !== session.currentSection) {
          session.currentSection = section;
        }
        return question;
      }
    }
  }

  return null;
}

/**
 * Go back to the previous question.
 * Returns the previous question or null if at the start.
 */
export function getPreviousQuestion(session: OnboardingSession): OnboardingQuestion | null {
  const answeredIds = session.responses.map((r) => r.questionId);
  if (answeredIds.length === 0) return null;

  // Find the question the user most recently answered
  const lastAnsweredId = answeredIds[answeredIds.length - 1];
  const lastQuestion = getQuestionById(lastAnsweredId);

  if (lastQuestion) {
    // Remove that response so it becomes the "current" question again
    session.responses.pop();
    session.currentSection = lastQuestion.section;
    updateCompletedSections(session);
    return lastQuestion;
  }

  return null;
}

/**
 * Skip the current question (only for non-required questions).
 * Returns the next question after skipping.
 */
export function skipQuestion(session: OnboardingSession): {
  success: boolean;
  error?: string;
  nextQuestion: OnboardingQuestion | null;
} {
  const current = getNextQuestion(session);
  if (!current) {
    return { success: false, error: "No question to skip.", nextQuestion: null };
  }

  if (current.required) {
    return {
      success: false,
      error: "This question is required and cannot be skipped.",
      nextQuestion: current,
    };
  }

  // Record a skip as an empty response
  const emptyValue = current.type === "multi-select" ? [] : "";
  session.responses.push({
    questionId: current.id,
    value: emptyValue,
    answeredAt: new Date().toISOString(),
  });

  updateCompletedSections(session);
  return { success: true, nextQuestion: getNextQuestion(session) };
}

// ─── Progress Tracking ────────────────────────────────────────────────

/**
 * Recalculate which sections are completed based on current responses.
 */
function updateCompletedSections(session: OnboardingSession): void {
  const answeredIds = new Set(session.responses.map((r) => r.questionId));
  const completed: OnboardingSection[] = [];

  for (const section of SECTION_ORDER) {
    const applicable = getApplicableQuestions(section, session.responses);
    const requiredQuestions = applicable.filter((q) => q.required);
    const allRequiredAnswered = requiredQuestions.every((q) => answeredIds.has(q.id));

    if (allRequiredAnswered && requiredQuestions.length > 0) {
      completed.push(section);
    }
  }

  session.completedSections = completed;
}

/**
 * Calculate the overall onboarding progress.
 */
export function getProgress(session: OnboardingSession): OnboardingProgress {
  const answeredIds = new Set(session.responses.map((r) => r.questionId));

  // Count total applicable questions and how many are answered
  let totalApplicable = 0;
  let totalAnswered = 0;

  for (const section of SECTION_ORDER) {
    const applicable = getApplicableQuestions(section, session.responses);
    totalApplicable += applicable.length;
    totalAnswered += applicable.filter((q) => answeredIds.has(q.id)).length;
  }

  const currentSectionQuestions = getApplicableQuestions(session.currentSection, session.responses);
  const answeredInSection = currentSectionQuestions.filter((q) => answeredIds.has(q.id)).length;

  const overallPercentage = totalApplicable > 0
    ? Math.round((totalAnswered / totalApplicable) * 100)
    : 0;

  return {
    currentSection: session.currentSection,
    currentSectionTitle: SECTION_TITLES[session.currentSection],
    currentQuestionIndex: answeredInSection,
    totalQuestionsInSection: currentSectionQuestions.length,
    completedSections: session.completedSections,
    totalSections: SECTION_ORDER.length,
    overallPercentage,
    isComplete: overallPercentage === 100,
  };
}

/**
 * Get a summary for a specific section.
 */
export function getSectionSummary(
  session: OnboardingSession,
  section: OnboardingSection
): SectionSummary {
  const applicable = getApplicableQuestions(section, session.responses);
  const answeredIds = new Set(session.responses.map((r) => r.questionId));
  const sectionResponses = session.responses.filter((r) =>
    applicable.some((q) => q.id === r.questionId)
  );

  const answeredCount = applicable.filter((q) => answeredIds.has(q.id)).length;

  return {
    section,
    title: SECTION_TITLES[section],
    totalQuestions: applicable.length,
    answeredQuestions: answeredCount,
    isComplete: session.completedSections.includes(section),
    responses: sectionResponses,
  };
}

/**
 * Get summaries for all sections at once.
 */
export function getAllSectionSummaries(session: OnboardingSession): SectionSummary[] {
  return SECTION_ORDER.map((section) => getSectionSummary(session, section));
}
