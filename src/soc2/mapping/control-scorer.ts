/**
 * Control Scorer — aggregates evidence items per control and computes
 * overall scores with configurable severity weights.
 */

import type {
  ControlId,
  ControlScore,
  EvidenceItem,
  EvidenceStatus,
  Finding,
  WorkspaceId,
} from "../../types/index.ts";

// ─── Weight Configuration ────────────────────────────────────────────

/**
 * Severity weights determine how much each finding severity pulls the
 * score down. Higher weight = more impact.
 */
export interface SeverityWeights {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/** Default severity weights used when no custom weights are provided. */
export const DEFAULT_SEVERITY_WEIGHTS: Readonly<SeverityWeights> = Object.freeze({
  critical: 40,
  high: 25,
  medium: 10,
  low: 3,
  info: 0,
});

/** Thresholds for mapping a numeric score to an EvidenceStatus. */
export interface ScoreThresholds {
  /** Score >= pass → "pass" */
  pass: number;
  /** Score >= warn (and < pass) → "warn" */
  warn: number;
  /** Score < warn → "fail" */
}

export const DEFAULT_SCORE_THRESHOLDS: Readonly<ScoreThresholds> = Object.freeze({
  pass: 70,
  warn: 40,
});

// ─── Scorer ──────────────────────────────────────────────────────────

export interface ScorerOptions {
  weights?: SeverityWeights;
  thresholds?: ScoreThresholds;
}

/**
 * Group evidence items by control and compute a score for each control.
 *
 * Scoring algorithm:
 * 1. Start with the average raw score across all evidence items for the control.
 * 2. Apply a penalty for each negative finding based on severity weight.
 *    - Penalty = weight * (count of findings at that severity) / totalEvidenceCount
 *    - Penalties are capped so the score never goes below 0.
 * 3. The resulting score is clamped to [0, 100].
 */
export function scoreControls(
  evidenceItems: ReadonlyArray<EvidenceItem>,
  workspaceId: WorkspaceId,
  options?: ScorerOptions,
): ControlScore[] {
  const weights = options?.weights ?? DEFAULT_SEVERITY_WEIGHTS;
  const thresholds = options?.thresholds ?? DEFAULT_SCORE_THRESHOLDS;

  // Group by control
  const grouped = new Map<string, EvidenceItem[]>();
  for (const item of evidenceItems) {
    if (item.workspaceId !== workspaceId) continue;
    if (item.blacklisted || item.deleted) continue;

    const key = item.controlId as string;
    const list = grouped.get(key) ?? [];
    list.push(item);
    grouped.set(key, list);
  }

  const results: ControlScore[] = [];
  const now = new Date().toISOString();

  for (const [controlId, items] of grouped) {
    const { score, findings } = computeControlScore(items, weights);
    const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
    const status = scoreToStatus(clampedScore, thresholds);

    results.push({
      controlId: controlId as ControlId,
      workspaceId,
      score: clampedScore,
      status,
      evidenceCount: items.length,
      lastEvaluated: now,
      findings,
    });
  }

  // Sort by control ID for deterministic output
  results.sort((a, b) => (a.controlId as string).localeCompare(b.controlId as string));

  return results;
}

/**
 * Compute a single control's score from its evidence items.
 *
 * The base score is the average of all evidence item scores.
 * A severity-weighted penalty is subtracted for negative findings.
 */
function computeControlScore(
  items: EvidenceItem[],
  weights: SeverityWeights,
): { score: number; findings: Finding[] } {
  if (items.length === 0) {
    return { score: 0, findings: [] };
  }

  // Base score: average of evidence item scores
  const totalRawScore = items.reduce((sum, item) => sum + item.score, 0);
  let baseScore = totalRawScore / items.length;

  // Collect all findings
  const allFindings: Finding[] = [];
  const severityCounts: Record<Finding["severity"], number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const item of items) {
    for (const f of item.findings) {
      allFindings.push(f);
      severityCounts[f.severity] += 1;
    }
  }

  // Apply severity penalty
  // Penalty is proportional: each finding's severity weight is divided by item count
  // to avoid double-punishing controls with many evidence items.
  let totalPenalty = 0;
  for (const sev of ["critical", "high", "medium", "low", "info"] as const) {
    totalPenalty += (weights[sev] * severityCounts[sev]) / items.length;
  }

  const finalScore = baseScore - totalPenalty;

  // Deduplicate findings by title
  const seen = new Set<string>();
  const deduped: Finding[] = [];
  for (const f of allFindings) {
    if (!seen.has(f.title)) {
      seen.add(f.title);
      deduped.push(f);
    }
  }

  // Sort findings by severity (critical first)
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  deduped.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return { score: finalScore, findings: deduped };
}

/** Map a numeric score to a status based on thresholds. */
function scoreToStatus(
  score: number,
  thresholds: ScoreThresholds,
): EvidenceStatus {
  if (score >= thresholds.pass) return "pass";
  if (score >= thresholds.warn) return "warn";
  return "fail";
}

// ─── Summary Helpers ─────────────────────────────────────────────────

export interface ControlScoreSummary {
  totalControls: number;
  passing: number;
  warning: number;
  failing: number;
  averageScore: number;
  overallStatus: EvidenceStatus;
  controlsWithoutEvidence: number;
}

/**
 * Compute a summary across all scored controls.
 *
 * @param scores - Array of individual control scores
 * @param totalExpectedControls - The total number of controls in the
 *   framework (33 for SOC 2 CC). Controls not present in `scores` are
 *   counted as "without evidence".
 */
export function summarizeScores(
  scores: ReadonlyArray<ControlScore>,
  totalExpectedControls = 33,
): ControlScoreSummary {
  const passing = scores.filter((s) => s.status === "pass").length;
  const warning = scores.filter((s) => s.status === "warn").length;
  const failing = scores.filter((s) => s.status === "fail").length;
  const averageScore =
    scores.length > 0
      ? Math.round(scores.reduce((sum, s) => sum + s.score, 0) / scores.length)
      : 0;

  const controlsWithoutEvidence = totalExpectedControls - scores.length;

  let overallStatus: EvidenceStatus;
  if (failing > 0 || controlsWithoutEvidence > totalExpectedControls / 2) {
    overallStatus = "fail";
  } else if (warning > 0 || controlsWithoutEvidence > 0) {
    overallStatus = "warn";
  } else {
    overallStatus = "pass";
  }

  return {
    totalControls: totalExpectedControls,
    passing,
    warning,
    failing,
    averageScore,
    overallStatus,
    controlsWithoutEvidence,
  };
}

/**
 * Return the controls that need the most attention, sorted by score ascending
 * (worst first), limited to `limit`.
 */
export function getTopRisks(
  scores: ReadonlyArray<ControlScore>,
  limit = 5,
): ControlScore[] {
  return [...scores]
    .filter((s) => s.status !== "pass")
    .sort((a, b) => a.score - b.score)
    .slice(0, limit);
}
