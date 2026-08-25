/**
 * Evidence Mapping — Maps cloud findings to SOC 2 controls with scoring
 */
export { mapEvidenceToControls, type EvidenceMappingResult } from "./evidence-mapper.js";
export { scoreControls, type ScoringResult } from "./control-scorer.js";
