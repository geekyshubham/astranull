# Public Landing and Internal Management

## Goal

AstraNull needs three clearly separated product surfaces:

1. A public landing page for unauthenticated visitors.
2. A customer portal for tenant-scoped DDoS readiness work.
3. A staff-only internal management plane for AstraNull operations, SOC approvals, tenant lifecycle, subscriptions, and customer support.

Customers must not see, navigate to, or depend on the internal management plane. Internal management is an AstraNull staff control surface, protected by staff identity, MFA, role gates, audit logs, and preferably a separate internal host or route group.

## Scope

| Area | In scope | Out of scope |
|---|---|---|
| Public landing | Brand, product positioning, no-access-first promise, sign-up and login redirects | Exposing authenticated product data or internal management links |
| Customer portal | Tenant-scoped onboarding, target groups, agents, safe runs, findings, reports, settings, high-scale request submission | Customer approval/execution of high-scale tests or internal subscription controls |
| Internal management | Staff tenant administration, subscription and entitlement management, user support, request queues, SOC approval/rejection, audit review | Customer-facing self-service execution of SOC-gated workflows |
| SOC operations | High-scale approval, rejection, scheduling, monitoring, stop, closure | Unmanaged traffic generation or bypassing authorization packs |

## Surface Split

| Surface | Example route/host | Audience | Auth boundary | Primary purpose |
|---|---|---|---|---|
| Public landing | `/` | Visitors, prospects, returning users | No auth; rate-limited forms only | Explain AstraNull and route users to sign up or log in. |
| Sign-up intake | `/signup` or hosted IdP registration | Prospects/customers | Public form plus verification controls | Collect account request metadata for review or automated provisioning. |
| Login | `/login` or IdP redirect | Customers and staff | OIDC/SSO | Start the correct authenticated session. |
| Customer portal | `/app` | Customer tenant users | Customer IdP or customer-scoped OIDC claims | Readiness validation workflow. |
| Internal management | `/internal/admin` or `admin.astranull...` | AstraNull staff only | Staff IdP, MFA, staff roles, optional network allowlist | Tenant, subscription, entitlement, support, and approval operations. |
| SOC console | `/internal/soc` | AstraNull SOC only | Staff IdP plus SOC role | Govern high-scale workflows and emergency stops. |

The routing layer must not rely on hidden navigation alone. Internal routes must fail closed for customer principals even if a customer guesses the URL.

## Public Landing Page Requirements

The landing page is the unauthenticated entry point. It should be lightweight, clear, and product-specific.

| Requirement | Detail |
|---|---|
| First viewport | Show the AstraNull name and no-access-first DDoS readiness promise. |
| Primary action | `Sign up` routes to sign-up intake or external registration. |
| Secondary action | `Log in` routes to the configured identity provider. |
| Trust framing | Explain customer-declared scope, outbound-only agents, evidence-backed verdicts, and SOC-gated high-scale validation. |
| Safety framing | State that AstraNull does not require default cloud access, does not auto-discover IP inventory, and does not provide self-service high-scale attack tooling. |
| Customer separation | Do not mention or link to internal management pages. |
| Telemetry | Track only privacy-safe page and conversion events; no sensitive target or infrastructure data. |

## Sign-Up Intake

Sign-up can be automated later, but the first production-safe design should treat account creation as an approval-gated tenant lifecycle event.

| Field | Purpose |
|---|---|
| Organization name | Establish the customer record. |
| Work email and domain | Verify business identity. |
| Primary contact | Provide onboarding and emergency contact path. |
| Requested plan | Map to subscription and entitlements. |
| Intended use | Confirm defensive readiness validation. |
| Region/data residency preference | Seed tenant settings. |
| High-scale interest | Flag SOC program eligibility review without granting execution rights. |

### Sign-Up Request State

```text
Submitted
  -> Under Review
  -> Approved
  -> Provisioned
  -> Customer Invited

Rejected
  -> Customer Notified
```

Provisioning creates a tenant, initial owner invitation, subscription record, entitlements, retention defaults, and audit records. Rejection requires a staff-visible reason and a customer-safe notification reason.

## Internal Management Capabilities

### Tenant Operations

| Capability | Requirement |
|---|---|
| Review sign-up requests | Approve or reject submitted account requests with reason, reviewer, timestamp, and audit record. |
| Create/provision tenant | Create tenant, default environment, retention settings, owner invite, and initial subscription. |
| Suspend/reactivate tenant | Block customer access or risky activity without deleting evidence. |
| Configure tenant metadata | Company details, region, support owner, security contact, legal status. |
| Manage feature flags | Enable optional WAF posture, connector, high-scale program, or beta capabilities by entitlement. |

### Subscription and Entitlements

| Capability | Requirement |
|---|---|
| Plan management | Store plan, billing status, renewal dates, and contract references. |
| Entitlement limits | Enforce limits for users, target groups, agents, safe runs, retention, connectors, WAF add-on, and high-scale eligibility. |
| Billing integration | Keep payment data in an external billing system; store only provider customer IDs and status metadata. |
| Subscription changes | Require staff role approval, reason, effective date, and audit record. |

### Customer User Support

| Capability | Requirement |
|---|---|
| Invite owner/admin | Staff can issue or resend owner/admin invites when contractually approved. |
| Disable user | Staff can disable compromised or departed users with audit evidence. |
| Role correction | Staff can adjust customer roles only with scoped justification. |
| Impersonation policy | Default is no live impersonation. If added later, it must be read-only, time-boxed, customer-approved or break-glass approved, visibly bannered, and fully audited. |

### Request Review

The internal management plane owns queues for customer-submitted requests that require staff action.

| Request type | Owner role | Decision |
|---|---|---|
| Account sign-up | Internal admin / customer operations | Approve, reject, request information. |
| Subscription change | Internal admin / billing operations | Approve, reject, schedule effective date. |
| High-scale validation | SOC analyst and SOC lead | Approve, reject, schedule, start, stop, close. |
| Optional connector enablement | Internal admin / security reviewer | Approve or reject based on plan, security posture, and customer authorization. |
| Data export/legal hold | Security admin / compliance | Approve, reject, apply retention/legal hold. |

High-scale validation remains governed by the existing SOC workflow. Internal management may show the queue and customer/account context, but execution controls stay SOC-role gated.

## Internal Roles

| Role | Allowed scope |
|---|---|
| `internal_admin` | Tenant lifecycle, subscription metadata, entitlements, staff queues, support owner assignment. |
| `billing_ops` | Subscription status, plan metadata, billing references, entitlement requests; no SOC execution. |
| `support_engineer` | Read support context, resend approved invites, view non-sensitive metadata; no subscription or high-scale approval. |
| `soc_analyst` | Review high-scale requests, validate authorization packs, monitor runs, record notes. |
| `soc_lead` | Final high-scale approval, schedule/start/stop/close, kill-switch decisions. |
| `security_admin` | Audit review, legal hold, data export approval, security policy configuration. |

Customer tenant roles (`owner`, `admin`, `engineer`, `auditor`, `viewer`) must never satisfy internal management permissions.

## Backend Design Plan

### Services

| Service | Responsibility |
|---|---|
| Public Site Service | Serve landing content and route sign-up/login actions. |
| Sign-Up Intake Service | Validate and store account requests, deduplicate by organization/domain, notify staff queues. |
| Internal Management Service | Staff-only tenant, subscription, entitlement, and support operations. |
| Subscription Service | Plan, billing status, entitlement, and usage limit enforcement. |
| Staff Auth/RBAC | Separate staff-principal verification from customer tenant auth. |
| Internal Approval Service | Shared approve/reject state machine for sign-up, subscription, connector, export, and high-scale context decisions. |
| Staff Audit Service | Immutable audit records for every internal action. |

### Data Model

| Entity | Key fields |
|---|---|
| `signup_requests` | id, organization, domain, contact, requested_plan, intended_use, state, reviewer, decision_reason, created_at, decided_at |
| `staff_users` | id, email, display_name, staff_roles, status, last_login_at |
| `tenant_accounts` | tenant_id, legal_name, support_owner, region, lifecycle_state, contract_reference |
| `subscription_plans` | id, name, limits, feature_entitlements, default_retention |
| `tenant_subscriptions` | tenant_id, plan_id, status, billing_provider_ref, effective_at, renewal_at |
| `entitlement_grants` | tenant_id, feature, limit_value, source, expires_at |
| `internal_approval_requests` | id, kind, subject_ref, state, assigned_to, decision, reason, evidence_refs |
| `internal_admin_notes` | id, subject_ref, note_type, redacted_body, author, created_at |

All records must be tenant-scoped when they reference a customer tenant. Staff records are platform-scoped and must not be exposed through customer APIs.

### API Shape

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/v1/signup-requests` | Public, rate-limited | Submit account request. |
| GET | `/internal/admin/signup-requests` | Staff only | List sign-up requests. |
| POST | `/internal/admin/signup-requests/{id}/approve` | Internal admin | Approve and optionally provision tenant. |
| POST | `/internal/admin/signup-requests/{id}/reject` | Internal admin | Reject with customer-safe reason. |
| GET | `/internal/admin/tenants` | Staff only | Search customer tenants. |
| GET | `/internal/admin/tenants/{tenantId}` | Staff only | Tenant operations detail. |
| PATCH | `/internal/admin/tenants/{tenantId}` | Internal admin | Update lifecycle, metadata, support owner. |
| GET | `/internal/admin/tenants/{tenantId}/subscription` | Staff only | Read subscription and entitlements. |
| PATCH | `/internal/admin/tenants/{tenantId}/subscription` | Billing ops / internal admin | Update plan/status/effective dates. |
| POST | `/internal/admin/tenants/{tenantId}/entitlements` | Internal admin | Grant or revoke feature entitlements. |
| GET | `/internal/admin/approval-requests` | Staff only | Unified approval queue. |
| POST | `/internal/admin/approval-requests/{id}/decision` | Role-specific staff | Approve/reject with reason. |
| GET | `/internal/admin/audit-log` | Security admin / internal admin | Search internal audit events. |

## UX Plan

| Page | Purpose |
|---|---|
| Public landing | Explain product promise; route to sign up or log in. |
| Sign-up intake | Collect account request fields and show submitted/review state. |
| Internal overview | Staff queue summary: pending sign-ups, subscription requests, high-scale reviews, blocked tenants, support alerts. |
| Tenant detail | Tenant metadata, lifecycle state, subscription, entitlements, owner/admin users, recent audit activity. |
| Sign-up queue | Review submitted requests, approve/provision, reject, request more information. |
| Subscription console | Plan, limits, billing status, contract references, effective-date changes. |
| User support console | Owner/admin invites, disabled users, role corrections, support notes. |
| Approval queue | Unified list of staff decisions with owner, SLA, evidence refs, and decision history. |
| Internal audit | Filter by tenant, staff actor, action, resource, and time. |

## Security and Privacy Requirements

- Internal management must use staff identity, staff roles, MFA, and production OIDC/JWKS or equivalent IdP verification.
- Customer principals must be denied on all `/internal/*` routes, regardless of customer role.
- Internal management should be hosted separately from the customer portal when possible, with stricter edge controls and optional network allowlists.
- Every mutation must write an immutable audit event with staff actor, role, reason, resource, tenant, before/after metadata where safe, and request ID.
- Internal notes must be metadata-only by default. Do not store raw secrets, packet data, payment card data, credentials, or unmanaged provider exports.
- Subscription status must be enforced in backend service logic, not only hidden in the UI.
- Staff support actions must not bypass SOC gates, tenant isolation, retention policy, or evidence custody.

## Acceptance Criteria

- Public landing page loads without auth and exposes working sign-up and login actions.
- Sign-up requests persist with state transitions and audit records.
- Approved sign-up can provision a tenant, subscription, owner invite, default entitlements, and retention settings.
- Rejected sign-up records a staff reason and sends only customer-safe rejection copy.
- Customer portal has no internal management links and customer auth cannot access `/internal/admin` or `/internal/soc`.
- Internal management uses staff-only roles distinct from customer tenant roles.
- Tenant lifecycle and subscription changes are audited and enforced by backend services.
- SOC high-scale approvals remain SOC-role gated and cannot be executed by customer or generic admin roles.
- Tests cover public route access, internal route denial for customers, staff RBAC, approval state transitions, subscription entitlement enforcement, audit logging, and safe error states.

## Implementation Checklist

[x] Add public landing and auth redirect routes.
[x] Add sign-up request model, validation, state machine, and staff review APIs.
[x] Add internal staff roles and staff-auth boundary separate from tenant roles.
[x] Add internal management console pages for sign-ups, tenants, subscriptions, user support, approval queue, and audit.
[x] Add subscription and entitlement enforcement to service-layer checks.
[x] Add audit events for all internal management mutations.
[x] Add tests for public/customer/internal route separation and role gates.
[x] Update release checklist evidence requirements for staff auth, subscription enforcement, and internal audit.
