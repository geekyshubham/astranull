/**
 * SAFE_PROBE_SIMULATION — metadata-only safe probe simulation.
 * Does not send live traffic to customer targets.
 */

import { generateNonce, hashNonce } from '../lib/crypto.mjs';
import { newId } from '../lib/ids.mjs';
import { enrichProbeMetadataWithWafCatalog } from '../lib/wafProductCatalog.mjs';

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
  const baseMetadata = {
    simulation: 'SAFE_PROBE_SIMULATION',
    check_id: check.check_id,
    vector_family: check.vector_family,
    probe_profile_kind: probeProfileKind,
    target_value: target.value,
  };

  if (probeProfileKind === 'udp_probe') {
    Object.assign(baseMetadata, {
      probe_kind: 'udp_probe',
      datagram_bytes: 24,
      note: 'Simulated single UDP datagram probe.',
    });
  } else if (probeProfileKind === 'quic_reachability') {
    Object.assign(baseMetadata, {
      probe_kind: 'quic_reachability',
      alt_svc_present: true,
      quic_port: 443,
      note: 'Simulated Alt-Svc discovery and UDP-443 datagram.',
    });
  } else if (probeProfileKind === 'alert_webhook_ping') {
    Object.assign(baseMetadata, {
      probe_kind: 'alert_webhook_ping',
      alert_delivery_ok: external_result === 'connected',
      response_status: external_result === 'connected' ? 204 : 503,
      note: 'Simulated alert webhook ping.',
    });
  } else if (probeProfileKind === 'ops_readiness') {
    Object.assign(baseMetadata, {
      probe_kind: 'ops_readiness',
      scenario: check.probe_profile?.scenario ?? 'runbook_contacts',
      ops_validation_ok: external_result === 'connected',
      dry_run: check.probe_profile?.scenario === 'kill_switch_readiness',
      note: 'Simulated ops readiness validation on control plane.',
    });
  } else if (probeProfileKind === 'tls_session') {
    Object.assign(baseMetadata, {
      probe_kind: 'tls_session',
      tls_protocol: 'TLSv1.3',
      cipher: 'TLS_AES_128_GCM_SHA256',
      authorized: true,
      note: 'Simulated bounded TLS session.',
    });
  } else if (probeProfileKind === 'http2_settings') {
    Object.assign(baseMetadata, {
      probe_kind: 'http2_settings',
      max_concurrent_streams: 100,
      enable_push: false,
      note: 'Simulated HTTP/2 SETTINGS read.',
    });
  } else {
    baseMetadata.note = 'Metadata-only safe probe simulation — no live traffic to customer targets.';
  }

  return {
    event_id: newId('event'),
    source: 'probe_simulation_stub',
    signal_type: 'probe_result',
    external_result,
    nonce,
    nonce_hash,
    target_id: target.id,
    check_id: check.check_id,
    metadata: enrichProbeMetadataWithWafCatalog(baseMetadata, check.check_id),
  };
}