/**
 * LoxeAI Agent Orchestrator
 *
 * Manages background agents that spin up during onboarding.
 * When a user selects an integration (e.g., AWS, GitHub, Okta),
 * this module creates and tracks the corresponding agent task.
 */

import type { AgentTrigger, BackgroundAgentStatus } from "../types/index";

// ─── ID Generation ────────────────────────────────────────────────────

let agentCounter = 0;

/**
 * Generate a deterministic agent ID.
 * Format: agent_{type}_{integrationKey}_{counter}
 */
function generateAgentId(trigger: AgentTrigger): string {
  agentCounter += 1;
  return `agent_${trigger.type}_${trigger.integrationKey}_${agentCounter}`;
}

/**
 * Reset the agent counter. Useful for testing.
 */
export function resetAgentCounter(): void {
  agentCounter = 0;
}

// ─── Agent Lifecycle ──────────────────────────────────────────────────

/**
 * Create and start a new background agent based on an integration trigger.
 *
 * Returns a BackgroundAgentStatus object representing the initial state
 * of the agent. For integrations that require setup (e.g., AWS cross-account
 * role), the agent begins in "pending" status awaiting user action.
 * Otherwise, it starts in "running" status immediately.
 */
export function triggerAgent(trigger: AgentTrigger): BackgroundAgentStatus {
  const id = generateAgentId(trigger);
  const now = new Date().toISOString();

  const initialStatus: BackgroundAgentStatus["status"] = trigger.requiresSetup
    ? "pending"
    : "running";

  return {
    id,
    type: trigger.type,
    integration: trigger.integrationKey,
    status: initialStatus,
    progress: 0,
    evidenceCount: 0,
    startedAt: now,
  };
}

/**
 * Get the status of a specific agent by ID from a list of agents.
 */
export function getAgentStatus(
  agents: BackgroundAgentStatus[],
  agentId: string
): BackgroundAgentStatus | undefined {
  return agents.find((a) => a.id === agentId);
}

/**
 * Get all agent statuses, optionally filtered by status or integration.
 */
export function getAllAgentStatuses(
  agents: BackgroundAgentStatus[],
  filter?: {
    status?: BackgroundAgentStatus["status"];
    integration?: string;
    type?: AgentTrigger["type"];
  }
): BackgroundAgentStatus[] {
  if (!filter) return agents;

  return agents.filter((agent) => {
    if (filter.status && agent.status !== filter.status) return false;
    if (filter.integration && agent.integration !== filter.integration) return false;
    if (filter.type && agent.type !== filter.type) return false;
    return true;
  });
}

/**
 * Cancel a running or pending agent.
 * Returns the updated agent status, or null if the agent was not found
 * or is already in a terminal state (completed/failed).
 */
export function cancelAgent(
  agents: BackgroundAgentStatus[],
  agentId: string
): BackgroundAgentStatus | null {
  const agent = agents.find((a) => a.id === agentId);

  if (!agent) return null;

  if (agent.status === "completed" || agent.status === "failed") {
    return null; // Cannot cancel a terminal agent
  }

  agent.status = "failed";
  agent.error = "Cancelled by user.";
  agent.completedAt = new Date().toISOString();

  return agent;
}

// ─── Agent Progress Updates ───────────────────────────────────────────

/**
 * Update an agent's progress. Used by the scan/integration runners
 * to report incremental progress back to the UI.
 */
export function updateAgentProgress(
  agents: BackgroundAgentStatus[],
  agentId: string,
  update: {
    status?: BackgroundAgentStatus["status"];
    progress?: number;
    evidenceCount?: number;
    error?: string;
  }
): BackgroundAgentStatus | null {
  const agent = agents.find((a) => a.id === agentId);
  if (!agent) return null;

  if (update.status !== undefined) {
    agent.status = update.status;
  }
  if (update.progress !== undefined) {
    agent.progress = Math.min(100, Math.max(0, update.progress));
  }
  if (update.evidenceCount !== undefined) {
    agent.evidenceCount = update.evidenceCount;
  }
  if (update.error !== undefined) {
    agent.error = update.error;
  }

  // Set completedAt when reaching a terminal state
  if (
    (agent.status === "completed" || agent.status === "failed") &&
    !agent.completedAt
  ) {
    agent.completedAt = new Date().toISOString();
  }

  return agent;
}

/**
 * Transition a pending agent (one that required setup) to running.
 * Called after the user completes the required setup steps
 * (e.g., provides a role ARN for AWS).
 */
export function startPendingAgent(
  agents: BackgroundAgentStatus[],
  agentId: string
): BackgroundAgentStatus | null {
  const agent = agents.find((a) => a.id === agentId);
  if (!agent || agent.status !== "pending") return null;

  agent.status = "running";
  agent.progress = 0;

  return agent;
}

// ─── Summary Helpers ──────────────────────────────────────────────────

/**
 * Get a high-level summary of all agent activity.
 */
export function getAgentSummary(agents: BackgroundAgentStatus[]): {
  total: number;
  pending: number;
  running: number;
  completed: number;
  failed: number;
  totalEvidence: number;
} {
  return {
    total: agents.length,
    pending: agents.filter((a) => a.status === "pending").length,
    running: agents.filter((a) => a.status === "running").length,
    completed: agents.filter((a) => a.status === "completed").length,
    failed: agents.filter((a) => a.status === "failed").length,
    totalEvidence: agents.reduce((sum, a) => sum + a.evidenceCount, 0),
  };
}
