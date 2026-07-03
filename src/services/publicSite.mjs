import { SUBSCRIPTION_PLANS } from '../contracts/subscriptions.mjs';

export function getPublicSiteConfig(runtimeConfig) {
  const loginUrl = (runtimeConfig.publicSite?.loginUrl ?? '/app').trim() || '/app';
  const signupEnabled = runtimeConfig.publicSite?.signupEnabled !== false;
  return {
    product_name: 'AstraNull',
    promise: 'No-access-first DDoS readiness validation for customer-declared targets.',
    login_url: loginUrl,
    signup_enabled: signupEnabled,
    signup_path: '/signup',
    customer_portal_path: '/app',
    plans: Object.values(SUBSCRIPTION_PLANS).map((p) => ({
      id: p.id,
      name: p.name,
      limits: p.limits,
      feature_entitlements: p.feature_entitlements,
    })),
    safety_framing: {
      no_default_cloud_access: true,
      no_ip_inventory_discovery: true,
      no_self_service_high_scale_attack_tooling: true,
      outbound_only_agents: true,
      soc_gated_high_scale: true,
    },
  };
}