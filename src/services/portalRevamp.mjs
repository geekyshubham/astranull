/**
 * Portal revamp service barrel — re-exports stub modules for BE-REV-01 scaffolding.
 */
export { issueDnsOwnershipChallenge, verifyDnsOwnership, listChallenges } from './dnsOwnership.mjs';
export {
  getLadder,
  confirmTarget,
  verifyOwnershipSetup,
  createOwnershipChallenge,
  recordOwnershipSignal,
  recordOwnershipSignalByNonce,
  confirmOwnership,
  listOwnershipVerifications,
  getOwnershipVerification,
} from './ownershipVerification.mjs';
export { sign, revoke, getActive } from './loa.mjs';
export { getTargetDetail } from './targetDetail.mjs';
export { attachToFinding, deliver, updateState } from './remediation.mjs';
export { getEvidenceBundle } from './findings.mjs';
export { getCoverageSummary, getConnectorInventory } from './wafPosture.mjs';
export { restoreArchived, bulkImportTargets } from './targetGroups.mjs';
export { listEvents } from './signupIntake.mjs';