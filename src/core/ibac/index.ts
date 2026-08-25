/**
 * IBAC (Intent-Based Access Control) — Core Security Infrastructure
 *
 * Intercepts all natural language prompts, agent plans, and API actions
 * before execution. Deterministic, parameter-driven, cryptographically logged.
 */
export { parseIntent, type ParsedIntent } from "./intent-parser.js";
export { evaluateIntent, type EvaluationResult } from "./evaluation-engine.js";
export { createIbacMiddleware, type IbacMiddlewareConfig } from "./middleware.js";
export { DEFAULT_IBAC_CONTROLS } from "./default-controls.js";
