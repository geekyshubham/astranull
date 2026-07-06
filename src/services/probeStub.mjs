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
  } else if (probeProfileKind === 'origin_leak_scan') {
    Object.assign(baseMetadata, {
      probe_kind: 'origin_leak_scan',
      leak_signals: external_result === 'connected' ? ['simulated_leak_signal'] : [],
      leak_count: external_result === 'connected' ? 1 : 0,
      note: 'Simulated bounded origin leak scan.',
    });
  } else if (probeProfileKind === 'host_sni_bypass') {
    Object.assign(baseMetadata, {
      probe_kind: 'host_sni_bypass',
      bypass_signal: external_result === 'connected',
      note: 'Simulated direct IP + Host/SNI bypass probe.',
    });
  } else if (probeProfileKind === 'port_scan_bounded') {
    Object.assign(baseMetadata, {
      probe_kind: 'port_scan_bounded',
      open_ports: external_result === 'connected' ? [22] : [],
      risky_admin_ports_open: external_result === 'connected' ? [22] : [],
      note: 'Simulated bounded port scan.',
    });
  } else if (probeProfileKind === 'rate_limit_sequence') {
    Object.assign(baseMetadata, {
      probe_kind: 'rate_limit_sequence',
      throttled: external_result === 'blocked',
      note: 'Simulated rate-limit sequence.',
    });
  } else if (probeProfileKind === 'waf_enforcement_probe') {
    Object.assign(baseMetadata, {
      probe_kind: 'waf_enforcement_probe',
      monitor_only_leak: external_result === 'connected',
      note: 'Simulated WAF enforcement probe.',
    });
  } else if (probeProfileKind === 'outside_in_waf_scan') {
    const blocked = external_result === 'blocked';
    Object.assign(baseMetadata, {
      probe_kind: 'outside_in_waf_scan',
      waf_fingerprint_detected: blocked,
      posture_label: blocked ? 'Detected, not validated' : 'Underprotected',
      posture_status: blocked ? 'unknown' : 'underprotected',
      agent_corroboration_required: true,
      evasion_bypass_suspected: false,
      marker_probes: [
        { family: 'sqli_marker', variant: 'plain', blocked, allowed: !blocked },
        { family: 'sqli_encoded_marker', variant: 'double_url_encoded', blocked, allowed: !blocked },
        { family: 'content_type_confusion', variant: 'json_header_form_body', blocked, allowed: !blocked },
        { family: 'multipart_confusion', variant: 'multipart_form_field', blocked, allowed: !blocked },
      ],
      note: 'Simulated outside-in WAF scanner.',
    });
  } else if (probeProfileKind === 'dnssec_posture') {
    Object.assign(baseMetadata, {
      probe_kind: 'dnssec_posture',
      dnssec_missing: external_result === 'connected',
      note: 'Simulated DNSSEC posture probe.',
    });
  } else if (probeProfileKind === 'dns_open_recursion') {
    Object.assign(baseMetadata, {
      probe_kind: 'dns_open_recursion',
      open_recursion_detected: external_result === 'connected',
      note: 'Simulated open-recursion probe.',
    });
  } else if (probeProfileKind === 'dns_failover_posture') {
    Object.assign(baseMetadata, {
      probe_kind: 'dns_failover_posture',
      weak_failover: external_result === 'connected',
      note: 'Simulated DNS failover posture probe.',
    });
  } else if (probeProfileKind === 'dns_axfr_leak') {
    Object.assign(baseMetadata, {
      probe_kind: 'dns_axfr_leak',
      axfr_refused: external_result === 'blocked',
      note: 'Simulated AXFR leak probe.',
    });
  } else if (probeProfileKind === 'tls_audit') {
    Object.assign(baseMetadata, {
      probe_kind: 'tls_audit',
      tls_issues: external_result === 'connected' ? ['weak_tls_protocol'] : [],
      note: 'Simulated TLS audit.',
    });
  } else if (probeProfileKind === 'cache_abuse_probe') {
    Object.assign(baseMetadata, {
      probe_kind: 'cache_abuse_probe',
      cache_key_weakness: external_result === 'connected',
      note: 'Simulated cache abuse probe.',
    });
  } else if (probeProfileKind === 'api_surface_scan') {
    Object.assign(baseMetadata, {
      probe_kind: 'api_surface_scan',
      exposure_count: external_result === 'connected' ? 1 : 0,
      note: 'Simulated API surface scan.',
    });
  } else if (probeProfileKind === 'cors_posture_probe') {
    Object.assign(baseMetadata, {
      probe_kind: 'cors_posture_probe',
      weak_cors: external_result === 'connected',
      note: 'Simulated CORS posture probe.',
    });
  } else if (probeProfileKind === 'bot_challenge_probe') {
    Object.assign(baseMetadata, {
      probe_kind: 'bot_challenge_probe',
      bot_challenge_missing: external_result === 'connected',
      note: 'Simulated bot/challenge probe.',
    });
  } else if (probeProfileKind === 'graphql_posture_probe') {
    Object.assign(baseMetadata, {
      probe_kind: 'graphql_posture_probe',
      graphql_exposed: external_result === 'connected',
      note: 'Simulated GraphQL posture probe.',
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