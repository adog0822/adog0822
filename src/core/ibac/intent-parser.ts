/**
 * LoxeAI GRC — Agentic Intent Parser
 *
 * Translates natural-language agent prompts into structured IntentObjects
 * using deterministic keyword matching and pattern recognition.
 * No probabilistic models — same input always yields same output.
 */

import { createHash } from "crypto";
import type {
  IntentId,
  IntentObject,
  IntentContext,
  IbacAction,
  IbacResource,
  RiskLevel,
  WorkspaceId,
  UserId,
} from "@/types";

// ─── Keyword → Action Mapping ─────────────────────────────────────────

/**
 * Ordered list of keyword patterns for each IbacAction.
 * Patterns are tested against the lowercased prompt in declaration order;
 * the first match wins.  More-specific patterns come first to avoid
 * false positives (e.g. "read-only" should not match "read").
 */
const ACTION_PATTERNS: ReadonlyArray<{
  action: IbacAction;
  keywords: readonly string[];
}> = [
  { action: "delete",   keywords: ["delete", "remove", "destroy", "drop", "purge", "erase", "wipe"] },
  { action: "export",   keywords: ["export", "download", "extract", "dump", "backup"] },
  { action: "share",    keywords: ["share", "publish", "distribute", "send to", "grant access"] },
  { action: "approve",  keywords: ["approve", "sign off", "authorize", "accept", "ratify"] },
  { action: "escalate", keywords: ["escalate", "raise", "flag", "alert", "notify compliance"] },
  { action: "execute",  keywords: ["run", "execute", "trigger", "invoke", "launch", "deploy", "scan"] },
  { action: "modify",   keywords: ["update", "modify", "change", "edit", "revise", "patch", "adjust", "set", "configure", "rename", "exclude", "include", "reassign", "promote", "demote"] },
  { action: "create",   keywords: ["create", "add", "new", "generate", "provision", "register", "onboard", "setup", "set up", "connect"] },
  { action: "read",     keywords: ["read", "view", "show", "list", "get", "fetch", "display", "describe", "inspect", "review", "check", "audit", "look up", "lookup"] },
] as const;

// ─── Keyword → Resource Mapping ───────────────────────────────────────

const RESOURCE_PATTERNS: ReadonlyArray<{
  resource: IbacResource;
  keywords: readonly string[];
}> = [
  { resource: "firewall_template", keywords: ["firewall policy", "firewall template", "firewall rule", "firewall config", "network policy", "security group"] },
  { resource: "access_review",     keywords: ["access review", "access audit", "user access", "permission review", "entitlement review"] },
  { resource: "custom_field",      keywords: ["custom field", "custom attribute", "custom property", "metadata field"] },
  { resource: "policy",            keywords: ["policy", "policies", "compliance policy", "security policy"] },
  { resource: "evidence",          keywords: ["evidence", "proof", "artifact", "evidence record", "audit evidence"] },
  { resource: "control",           keywords: ["control", "controls", "soc 2 control", "security control", "compliance control"] },
  { resource: "integration",       keywords: ["integration", "connector", "connection", "credential", "api key", "oauth", "aws", "gcp", "azure", "github", "okta", "cloudflare", "jira", "rippling"] },
  { resource: "vendor",            keywords: ["vendor", "supplier", "third party", "third-party", "subprocessor", "sub-processor"] },
  { resource: "report",            keywords: ["report", "dashboard", "summary", "analytics", "audit report"] },
  { resource: "user",              keywords: ["user", "member", "team member", "admin", "role", "account"] },
  { resource: "workspace",         keywords: ["workspace", "organization", "org", "tenant", "entity", "environment"] },
] as const;

// ─── Risk Matrix ──────────────────────────────────────────────────────

/**
 * Risk level is derived from a severity score that combines the
 * action category with the resource sensitivity.
 *
 * Scores: action (0-4) + resource (0-4) → total (0-8)
 *   0-2 → low,  3-4 → medium,  5-6 → high,  7-8 → critical
 */
const ACTION_SEVERITY: Record<IbacAction, number> = {
  read: 0,
  create: 1,
  execute: 2,
  modify: 2,
  export: 2,
  share: 3,
  approve: 3,
  escalate: 3,
  delete: 4,
};

const RESOURCE_SENSITIVITY: Record<IbacResource, number> = {
  report: 0,
  custom_field: 1,
  control: 1,
  evidence: 2,
  vendor: 2,
  access_review: 3,
  policy: 3,
  user: 3,
  workspace: 3,
  integration: 4,
  firewall_template: 4,
};

function calculateRiskLevel(action: IbacAction, resource: IbacResource): RiskLevel {
  const score = ACTION_SEVERITY[action] + RESOURCE_SENSITIVITY[resource];
  if (score <= 2) return "low";
  if (score <= 4) return "medium";
  if (score <= 6) return "high";
  return "critical";
}

// ─── Intent ID Generation ─────────────────────────────────────────────

/**
 * Deterministic IntentId: SHA-256 of prompt + ISO timestamp, truncated
 * to 32 hex characters and prefixed with `int_`.
 */
function generateIntentId(prompt: string, timestamp: string): IntentId {
  const raw = createHash("sha256")
    .update(prompt + timestamp)
    .digest("hex")
    .slice(0, 32);
  return `int_${raw}` as unknown as IntentId;
}

// ─── Reasoning Extractor ──────────────────────────────────────────────

/**
 * Extract a human-readable reasoning string from the prompt by
 * pulling the clause after the matched action keyword, capped at
 * 200 characters.
 */
function extractReasoning(prompt: string, action: IbacAction): string {
  const lower = prompt.toLowerCase();

  // Find the action keyword that triggered
  const patterns = ACTION_PATTERNS.find((p) => p.action === action);
  if (!patterns) return prompt.slice(0, 200);

  for (const kw of patterns.keywords) {
    const idx = lower.indexOf(kw);
    if (idx !== -1) {
      // Take everything after the keyword
      const rest = prompt.slice(idx + kw.length).trim();
      if (rest.length > 0) {
        return rest.slice(0, 200);
      }
    }
  }

  return prompt.slice(0, 200);
}

// ─── Target Entity Extraction ─────────────────────────────────────────

/**
 * Pull out notable entity references from the prompt:
 * quoted strings, environment names, workspace names, etc.
 */
function extractTargetEntities(prompt: string): string[] {
  const entities: string[] = [];

  // Quoted strings (single or double)
  const quoted = prompt.match(/["']([^"']+)["']/g);
  if (quoted) {
    entities.push(...quoted.map((q) => q.replace(/["']/g, "")));
  }

  // Common environment tokens
  const envPatterns = /\b(production|staging|development|dev|prod|stage|sandbox|test)\b/gi;
  let match: RegExpExecArray | null;
  while ((match = envPatterns.exec(prompt)) !== null) {
    const val = match[1].toLowerCase();
    if (!entities.includes(val)) {
      entities.push(val);
    }
  }

  return entities;
}

// ─── Environment Detection ────────────────────────────────────────────

function detectEnvironment(prompt: string): string | undefined {
  const lower = prompt.toLowerCase();
  const envs = ["production", "staging", "development", "sandbox", "test"];
  for (const env of envs) {
    if (lower.includes(env)) return env;
  }
  // Shorthand
  if (/\bprod\b/.test(lower)) return "production";
  if (/\bdev\b/.test(lower)) return "development";
  if (/\bstage\b/.test(lower)) return "staging";
  return undefined;
}

// ─── Public API ───────────────────────────────────────────────────────

export interface ParseIntentInput {
  prompt: string;
  workspaceId: WorkspaceId;
  userId: UserId;
  metadata?: Record<string, unknown>;
}

/**
 * Parse a natural-language prompt into a structured IntentObject.
 *
 * The function is **deterministic**: identical inputs always produce
 * identical outputs (modulo the timestamp, which is captured once
 * and threaded through every derived field).
 */
export function parseIntent(input: ParseIntentInput): IntentObject {
  const { prompt, workspaceId, userId, metadata = {} } = input;
  const lower = prompt.toLowerCase();
  const parsedAt = new Date().toISOString();

  // 1. Resolve action
  let action: IbacAction = "read"; // safe default
  for (const pattern of ACTION_PATTERNS) {
    const found = pattern.keywords.some((kw) => lower.includes(kw));
    if (found) {
      action = pattern.action;
      break;
    }
  }

  // 2. Resolve resource
  let resource: IbacResource = "workspace"; // safe default
  for (const pattern of RESOURCE_PATTERNS) {
    const found = pattern.keywords.some((kw) => lower.includes(kw));
    if (found) {
      resource = pattern.resource;
      break;
    }
  }

  // 3. Calculate risk
  const riskLevel = calculateRiskLevel(action, resource);

  // 4. Build context
  const context: IntentContext = {
    workspaceId,
    userId,
    environment: detectEnvironment(prompt),
    targetEntities: extractTargetEntities(prompt),
    reasoning: extractReasoning(prompt, action),
    metadata,
  };

  // 5. Generate deterministic ID
  const id = generateIntentId(prompt, parsedAt);

  return {
    id,
    action,
    resource,
    context,
    riskLevel,
    rawPrompt: prompt,
    parsedAt,
  };
}

/**
 * Convenience: parse and return both the intent and the computed risk
 * breakdown (useful for UI display or debugging).
 */
export function parseIntentWithBreakdown(input: ParseIntentInput): {
  intent: IntentObject;
  breakdown: {
    actionSeverity: number;
    resourceSensitivity: number;
    totalScore: number;
  };
} {
  const intent = parseIntent(input);
  return {
    intent,
    breakdown: {
      actionSeverity: ACTION_SEVERITY[intent.action],
      resourceSensitivity: RESOURCE_SENSITIVITY[intent.resource],
      totalScore:
        ACTION_SEVERITY[intent.action] +
        RESOURCE_SENSITIVITY[intent.resource],
    },
  };
}
