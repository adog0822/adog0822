/**
 * Gideon API Route Handlers
 *
 * Gideon is LoxeAI's AI compliance co-pilot. These routes serve
 * the "Ask Gideon" feature and the text translation feature.
 *
 * **Ask Gideon:** Users highlight text or ask a free-form question.
 * Gideon returns three perspectives (Plain English, Engineer,
 * Auditor), maps to related SOC 2 controls, and suggests next actions.
 *
 * **Translate:** Takes selected text and returns the same three
 * perspectives, designed for inline use when reading compliance
 * documentation or evidence.
 */

import type {
  ApiResponse,
  AuthenticatedRequest,
  GideonQuestion,
  GideonResponse,
  GideonTranslation,
  GideonPageContext,
  UUID,
} from '../../types';

// ---------------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------------

export interface AskGideonRequest extends AuthenticatedRequest {
  body: GideonQuestion;
}

export interface AskGideonResponse {
  response: GideonResponse;
}

export interface TranslateRequest extends AuthenticatedRequest {
  body: {
    /** The text the user selected / highlighted */
    selectedText: string;
    /** Page context for relevance */
    pageContext: GideonPageContext;
  };
}

export interface TranslateResponse {
  translation: GideonTranslation;
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

/**
 * POST /api/gideon/ask
 *
 * Ask Gideon a compliance question. Accepts the user's question text
 * and the page context where the question originated.
 *
 * Returns:
 * - **Plain English:** A jargon-free explanation anyone can understand.
 * - **What Engineers Should Hear:** Technical implications, what to
 *   build or configure, and common pitfalls.
 * - **Why Auditors Care:** What an auditor looks for, what evidence
 *   they expect, and how this maps to Trust Services Criteria.
 * - **Related Controls:** SOC 2 controls relevant to the question.
 * - **Suggested Actions:** Concrete next steps the user can take.
 */
export async function askGideon(
  req: AskGideonRequest
): Promise<ApiResponse<AskGideonResponse>> {
  const { body, workspace } = req;

  if (!body.text || body.text.trim().length === 0) {
    return {
      success: false,
      error: {
        code: 'EMPTY_QUESTION',
        message: 'Please provide a question or select some text.',
      },
    };
  }

  if (body.text.length > 5000) {
    return {
      success: false,
      error: {
        code: 'TEXT_TOO_LONG',
        message: 'Question text must be 5,000 characters or fewer.',
      },
    };
  }

  const { askGideonService } = await import('../../copilot/gideon');

  const response = await askGideonService({
    text: body.text,
    pageContext: body.pageContext,
    controlId: body.controlId,
    workspaceId: workspace.id,
  });

  return {
    success: true,
    data: { response },
  };
}

/**
 * POST /api/gideon/translate
 *
 * Translates selected text into three perspectives. Designed for
 * inline use — when a user highlights text on any page, the frontend
 * calls this endpoint to get a contextual translation.
 *
 * This is a lighter-weight version of "Ask Gideon" focused specifically
 * on translating existing text rather than answering open-ended questions.
 *
 * Returns:
 * - **Plain English:** What this text actually means in simple terms.
 * - **What Engineers Should Hear:** The technical implication.
 * - **Why Auditors Care:** The compliance significance.
 * - **Related Controls:** SOC 2 controls related to this text.
 */
export async function translateText(
  req: TranslateRequest
): Promise<ApiResponse<TranslateResponse>> {
  const { body, workspace } = req;

  if (!body.selectedText || body.selectedText.trim().length === 0) {
    return {
      success: false,
      error: {
        code: 'EMPTY_TEXT',
        message: 'Please select some text to translate.',
      },
    };
  }

  if (body.selectedText.length > 3000) {
    return {
      success: false,
      error: {
        code: 'TEXT_TOO_LONG',
        message: 'Selected text must be 3,000 characters or fewer.',
      },
    };
  }

  const { translateService } = await import('../../copilot/gideon');

  const translation = await translateService({
    text: body.selectedText,
    pageContext: body.pageContext,
    workspaceId: workspace.id,
  });

  return {
    success: true,
    data: { translation },
  };
}
