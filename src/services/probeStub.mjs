/**
 * SAFE_PROBE_SIMULATION — metadata-only safe probe simulation.
 * Does not send live traffic to customer targets.
 */

import { generateNonce, hashNonce } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';

export function simulateProbeResult(check, target, overrideProfile) {
  const nonce = generateNonce();
  const nonce_hash = hashNonce(nonce);
  const simulationProfile =
    typeof overrideProfile === 'string'
      ? overrideProfile
      : (check.probe_simulation_profile ?? 'external_blocked');

  let external_result = 'blocked';
  if (simulationProfile === 'external_connected') external_result = 'connected';
  if (simulationProfile === 'external_blocked') external_result = 'blocked';

  const probeProfileKind = check.probe_profile?.kind ?? 'metadata_marker';

  return {
    event_id: newId('event'),
    source: 'probe_simulation_stub',
    signal_type: 'probe_result',
    external_result,
    nonce,
    nonce_hash,
    target_id: target.id,
    check_id: check.check_id,
    metadata: {
      simulation: 'SAFE_PROBE_SIMULATION',
      check_id: check.check_id,
      vector_family: check.vector_family,
      probe_profile_kind: probeProfileKind,
      note: 'Metadata-only safe probe simulation — no live traffic to customer targets.',
      target_value: target.value,
    },
  };
}