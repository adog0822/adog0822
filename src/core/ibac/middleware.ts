/**
 * LoxeAI GRC — IBAC Middleware
 *
 * The middleware hook that sits in front of every agent action:
 *
 *   prompt → parseIntent → evaluate → allow / deny / escalate
 *
 * Every decision — regardless of outcome — is hashed into the
 * cryptographic evidence chain so that the full decision lineage
 * is immutable and auditable.
 */

import type {
  IntentObject,
  IbacEvaluation,
  IbacControlTemplate,
  IbacParameter,
  IbacDecision,
  WorkspaceId,
  UserId,
  EvidenceHash,
} from "@/types";
import { parseIntent } from "./intent-parser";
import { evaluate } from "./evaluation-engine";
import {
  sha256,
  hashDecisionRecord,
  appendToChain,
  generateEvidenceId,
  GENESIS_HASH,
} from "../evidence/crypto-chain";

// ─── Types ────────────────────────────────────────────────────────────

/**
 * Immutable evidence record produced by the middleware for every
 * intercepted action.
 */
export interface IbacEvidenceRecord {
  /** SHA-256 hash of the entire decision chain */
  decisionHash: string;
  /** Hash of the previous evidence record (chain link) */
  previousDecisionHash: string;
  /** Sequential position in the session's evidence chain */
  chainPosition: number;
  /** The parsed intent */
  intent: IntentObject;
  /** The evaluation result */
  evaluation: IbacEvaluation;
  /** Final decision applied */
  decision: IbacDecision;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** The originating raw prompt */
  rawPrompt: string;
}

/**
 * Result returned by the middleware to the caller.
 */
export interface MiddlewareResult {
  /** Whether the action may proceed */
  allowed: boolean;
  /** The IBAC decision */
  decision: IbacDecision;
  /** Human-readable reason (especially useful for deny / escalate) */
  reason: string;
  /** The immutable evidence record for this decision */
  evidenceRecord: IbacEvidenceRecord;
  /** The intent object produced by parsing */
  intent: IntentObject;
  /** The full evaluation */
  evaluation: IbacEvaluation;
}

/**
 * Configuration supplied to the middleware at construction time.
 */
export interface IbacMiddlewareConfig {
  controls: IbacControlTemplate[];
  parameterOverrides?: IbacParameter[];
}

// ─── Middleware Class ─────────────────────────────────────────────────

/**
 * Stateful middleware that maintains an in-memory evidence hash chain
 * across sequential agent actions within a session.
 *
 * Thread-safety note: this class is designed for single-threaded
 * Node.js event-loop execution.  If used across concurrent requests
 * you must synchronise access to `evidenceChain` externally.
 */
export class IbacMiddleware {
  private readonly controls: IbacControlTemplate[];
  private readonly parameterOverrides: IbacParameter[];

  /** The running evidence hash chain for this middleware session */
  private evidenceChain: EvidenceHash[] = [];
  /** The hash of the most recent decision record */
  private lastDecisionHash: string = GENESIS_HASH;
  /** Running count of processed actions */
  private chainPosition = 0;

  constructor(config: IbacMiddlewareConfig) {
    this.controls = config.controls;
    this.parameterOverrides = config.parameterOverrides ?? [];
  }

  // ── Primary entry point ─────────────────────────────────────────────

  /**
   * Intercept an agent action before execution.
   *
   * 1. Parse the natural-language prompt into an IntentObject
   * 2. Evaluate the intent against the configured control templates
   * 3. Hash the full decision chain (intent + evaluation + result)
   * 4. Append the hash to the evidence chain
   * 5. Return the decision with the immutable evidence record
   */
  intercept(
    prompt: string,
    workspaceId: WorkspaceId,
    userId: UserId,
    metadata?: Record<string, unknown>,
  ): MiddlewareResult {
    const timestamp = new Date().toISOString();

    // 1. Parse intent
    const intent = parseIntent({
      prompt,
      workspaceId,
      userId,
      metadata,
    });

    // 2. Evaluate
    const evaluation = evaluate({
      intent,
      controls: this.controls,
      parameterOverrides: this.parameterOverrides,
    });

    // 3. Determine outcome
    const decision = evaluation.decision;
    const allowed = decision === "allow";

    // 4. Build decision record and hash it
    const decisionRecord: Record<string, unknown> = {
      intentId: String(intent.id),
      action: intent.action,
      resource: intent.resource,
      riskLevel: intent.riskLevel,
      decision,
      matchedControls: evaluation.matchedControls.map((mc) => ({
        controlTemplateId: mc.controlTemplateId,
        result: mc.result,
        reason: mc.reason,
      })),
      evaluationHash: evaluation.evidenceHash,
      timestamp,
      chainPosition: this.chainPosition,
    };

    const decisionHash = hashDecisionRecord(
      decisionRecord,
      this.lastDecisionHash,
    );

    // 5. Append to the evidence hash chain
    const evidenceId = generateEvidenceId();
    this.evidenceChain = appendToChain(
      this.evidenceChain,
      evidenceId,
      decisionRecord,
    );

    // 6. Build the immutable evidence record
    const evidenceRecord: IbacEvidenceRecord = {
      decisionHash,
      previousDecisionHash: this.lastDecisionHash,
      chainPosition: this.chainPosition,
      intent,
      evaluation,
      decision,
      timestamp,
      rawPrompt: prompt,
    };

    // 7. Advance chain state
    this.lastDecisionHash = decisionHash;
    this.chainPosition++;

    // 8. Build reason string
    const reason = this.buildReasonString(evaluation, decision);

    return {
      allowed,
      decision,
      reason,
      evidenceRecord,
      intent,
      evaluation,
    };
  }

  // ── Helpers ─────────────────────────────────────────────────────────

  private buildReasonString(
    evaluation: IbacEvaluation,
    decision: IbacDecision,
  ): string {
    if (decision === "allow") {
      return "Action permitted — all controls passed.";
    }

    const reasons = evaluation.matchedControls
      .filter((mc) => mc.result === "fail" || mc.result === "requires_approval")
      .map((mc) => `[${mc.controlName}] ${mc.reason}`);

    if (decision === "deny") {
      return `Action denied: ${reasons.join("; ")}`;
    }
    if (decision === "step_up_auth") {
      return `Step-up authentication required: ${reasons.join("; ")}`;
    }
    // escalate
    return `Escalation required: ${reasons.join("; ")}`;
  }

  // ── Chain introspection ─────────────────────────────────────────────

  /**
   * Return a snapshot of the current evidence hash chain.
   */
  getEvidenceChain(): ReadonlyArray<EvidenceHash> {
    return [...this.evidenceChain];
  }

  /**
   * Return the hash of the most recent decision.
   */
  getLastDecisionHash(): string {
    return this.lastDecisionHash;
  }

  /**
   * Return the number of actions processed.
   */
  getChainLength(): number {
    return this.chainPosition;
  }

  /**
   * Replace the active control set (e.g. after an admin updates templates).
   */
  updateControls(controls: IbacControlTemplate[]): void {
    this.controls.length = 0;
    this.controls.push(...controls);
  }

  /**
   * Replace the active parameter overrides.
   */
  updateParameterOverrides(overrides: IbacParameter[]): void {
    this.parameterOverrides.length = 0;
    this.parameterOverrides.push(...overrides);
  }
}

// ─── Factory ──────────────────────────────────────────────────────────

/**
 * Create a new IBAC middleware instance.
 */
export function createIbacMiddleware(
  config: IbacMiddlewareConfig,
): IbacMiddleware {
  return new IbacMiddleware(config);
}
