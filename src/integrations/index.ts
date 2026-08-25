/**
 * Integration Layer — Cloud & SaaS evidence collection
 */
export { AwsScanner } from "./aws/index.js";
export { GitHubScanner } from "./github/index.js";
export { collectEvidence, collectForIntegration, getCollectionProgress } from "./evidence-collector.js";
export { INTEGRATION_REGISTRY, getIntegrationByKey } from "./registry.js";
