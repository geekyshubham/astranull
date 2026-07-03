export const SIGNUP_REQUEST_STATES = Object.freeze([
  'submitted',
  'under_review',
  'approved',
  'provisioned',
  'customer_invited',
  'rejected',
]);

export const SIGNUP_PLANS = Object.freeze(['starter', 'professional', 'enterprise']);

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function extractEmailDomain(email) {
  const normalized = String(email ?? '').trim().toLowerCase();
  const at = normalized.lastIndexOf('@');
  if (at < 1 || at === normalized.length - 1) return null;
  return normalized.slice(at + 1);
}

export function validateSignupRequestInput(body) {
  const errors = [];
  const organization = String(body?.organization_name ?? body?.organization ?? '').trim();
  const contactEmail = String(body?.contact_email ?? body?.work_email ?? '').trim().toLowerCase();
  const contactName = String(body?.contact_name ?? body?.primary_contact ?? '').trim();
  const requestedPlan = String(body?.requested_plan ?? 'starter').trim().toLowerCase();
  const intendedUse = String(body?.intended_use ?? '').trim();
  const region = String(body?.region ?? body?.data_residency ?? 'us').trim().toLowerCase();
  const highScaleInterest = Boolean(body?.high_scale_interest);

  if (!organization || organization.length < 2) errors.push('organization_name');
  if (!contactEmail || !EMAIL_RE.test(contactEmail)) errors.push('contact_email');
  if (!contactName || contactName.length < 2) errors.push('contact_name');
  if (!SIGNUP_PLANS.includes(requestedPlan)) errors.push('requested_plan');
  if (!intendedUse || intendedUse.length < 8) errors.push('intended_use');
  if (!region) errors.push('region');

  const domain = extractEmailDomain(contactEmail);
  if (!domain) errors.push('contact_email_domain');

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return {
    ok: true,
    value: {
      organization_name: organization,
      contact_email: contactEmail,
      contact_name: contactName,
      email_domain: domain,
      requested_plan: requestedPlan,
      intended_use: intendedUse,
      region,
      high_scale_interest: highScaleInterest,
    },
  };
}

export function canTransitionSignupState(from, to) {
  const transitions = {
    submitted: new Set(['under_review', 'rejected']),
    under_review: new Set(['approved', 'rejected']),
    approved: new Set(['provisioned', 'rejected']),
    provisioned: new Set(['customer_invited']),
    customer_invited: new Set(),
    rejected: new Set(),
  };
  return Boolean(transitions[from]?.has(to));
}

export function customerSafeRejectionReason(staffReason) {
  const trimmed = String(staffReason ?? '').trim();
  if (!trimmed) {
    return 'We are unable to approve this account request at this time. Contact support if you believe this is an error.';
  }
  if (trimmed.length > 240) {
    return `${trimmed.slice(0, 237)}...`;
  }
  return trimmed;
}