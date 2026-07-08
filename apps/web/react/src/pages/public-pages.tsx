import { FormEvent, useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  Check,
  CheckCircle2,
  FileCheck2,
  LockKeyhole,
  ShieldCheck,
  Siren,
  TrendingUp,
  TriangleAlert,
  UserRound,
  type LucideIcon
} from 'lucide-react';
import {
  isOidcJwtMode,
  loadSession,
  resolveOidcLoginRedirect,
  saveSession,
  sessionFromLoginResponse
} from '../lib/api';
import { PLATFORM_PROMISE, STAFF_LINKS } from '../lib/navigation';
import type { PortalConfig } from '../lib/types';
import { AnchorButton, Button } from '../components/ui/button';
import { Badge, type BadgeProps } from '../components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Progress } from '../components/ui/progress';
import { Select } from '../components/ui/select';
import { BrandMark } from '../components/layout/brand';

type BadgeTone = NonNullable<BadgeProps['tone']>;

function signupRequestStateTone(state: string): BadgeTone {
  const normalized = state.trim().toLowerCase();
  if (['approved', 'provisioned', 'active'].includes(normalized)) return 'success';
  if (['rejected', 'denied', 'cancelled', 'canceled'].includes(normalized)) return 'danger';
  if (['under_review', 'reviewing', 'in_review'].includes(normalized)) return 'warn';
  if (['submitted', 'pending', 'recorded'].includes(normalized)) return 'info';
  return 'muted';
}

function signupRequestStateLabel(state: string) {
  const normalized = state.trim().toLowerCase();
  const labels: Record<string, string> = {
    under_review: 'Under review',
    in_review: 'In review',
    submitted: 'Submitted',
    provisioned: 'Provisioned'
  };
  return labels[normalized] ?? (state.trim() || 'Recorded');
}

function SignupStateBadge({ state }: { state: unknown }) {
  const raw = String(state ?? 'recorded').trim() || 'recorded';
  return <Badge tone={signupRequestStateTone(raw)}>{signupRequestStateLabel(raw)}</Badge>;
}

function SignupRequestSummary({
  record,
  requestIdFallback,
  organizationFallback = 'Not recorded',
  planFallback = 'professional',
  regionFallback = 'us',
  showPlanBadgeWhenMissing = false,
  statusFallback = 'recorded'
}: {
  record: Record<string, unknown>;
  requestIdFallback?: string;
  organizationFallback?: string;
  planFallback?: string;
  regionFallback?: string;
  showPlanBadgeWhenMissing?: boolean;
  statusFallback?: string;
}) {
  const plan = record.requested_plan ?? (showPlanBadgeWhenMissing ? planFallback : null);
  const region = record.region ?? (showPlanBadgeWhenMissing ? regionFallback : null);
  return (
    <dl>
      <div>
        <dt>Request ID</dt>
        <dd><Badge mono tone="muted">{String(record.id ?? requestIdFallback ?? 'submitted')}</Badge></dd>
      </div>
      <div>
        <dt>Status</dt>
        <dd><SignupStateBadge state={record.state ?? record.status ?? statusFallback} /></dd>
      </div>
      <div>
        <dt>Organization</dt>
        <dd>{String(record.organization_name ?? record.organization ?? organizationFallback)}</dd>
      </div>
      <div>
        <dt>Requested plan</dt>
        <dd>
          {plan != null
            ? <Badge tone="info">{signupPlanLabel(plan)}</Badge>
            : 'Not recorded'}
        </dd>
      </div>
      <div>
        <dt>Region</dt>
        <dd>{region != null ? signupRegionLabel(region) : 'Not recorded'}</dd>
      </div>
    </dl>
  );
}

function AuthAsidePoints({ items }: { items: { icon: LucideIcon; text: string }[] }) {
  return (
    <ul className="auth-points">
      {items.map(({ icon: Icon, text }) => (
        <li key={text}>
          <Icon size={16} aria-hidden="true" />
          {text}
        </li>
      ))}
    </ul>
  );
}

function PublicAccessActions({
  signupEnabled,
  loginUrl,
  showArrowOnPrimary = false
}: {
  signupEnabled: boolean;
  loginUrl: string;
  showArrowOnPrimary?: boolean;
}) {
  return (
    <div className="public-actions">
      {signupEnabled ? (
        <AnchorButton href="/signup">
          Request access
          {showArrowOnPrimary ? <ArrowRight size={15} aria-hidden="true" /> : null}
        </AnchorButton>
      ) : null}
      <AnchorButton href={loginUrl} variant="secondary">Log in</AnchorButton>
    </div>
  );
}

const STAFF_ROLE_LABELS: Record<string, string> = {
  internal_admin: 'Internal admin',
  billing_ops: 'Billing operations',
  support_engineer: 'Support engineer',
  security_admin: 'Security admin',
  soc_analyst: 'SOC analyst',
  soc_lead: 'SOC lead'
};

function staffRoleLabel(slug: string) {
  return STAFF_ROLE_LABELS[slug] ?? slug.replace(/_/g, ' ');
}

function AuthRedirectPanel({ lead, help }: { lead: string; help?: string }) {
  return (
    <div className="success-panel" role="status" aria-live="polite" aria-busy="true">
      <Progress value={38} tone="accent" size="sm" />
      <div className="stack-tight" aria-hidden="true">
        <span className="skeleton skeleton-text" />
        <span className="skeleton skeleton-text" />
      </div>
      <p className="success-panel-lead">{lead}</p>
      {help ? <p className="auth-field-help">{help}</p> : null}
    </div>
  );
}

function SignupFormSkeleton() {
  return (
    <div className="auth-form auth-form--grid" aria-hidden="true">
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label className="auth-field-full"><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
      <label><span className="skeleton skeleton-text" /><span className="skeleton skeleton-row" /></label>
    </div>
  );
}

type PublicPageProps = {
  config: PortalConfig;
};

function usePageMeta({ title, robots }: { title: string; robots?: string }) {
  useEffect(() => {
    const previousTitle = document.title;
    document.title = title;

    const existingRobots = document.querySelector('meta[name="robots"]') as HTMLMetaElement | null;
    const previousRobots = existingRobots?.content;
    let robotsMeta = existingRobots;

    if (robots) {
      if (!robotsMeta) {
        robotsMeta = document.createElement('meta');
        robotsMeta.name = 'robots';
        document.head.appendChild(robotsMeta);
      }
      robotsMeta.content = robots;
    }

    return () => {
      document.title = previousTitle;
      if (!robots) return;
      if (previousRobots && robotsMeta) {
        robotsMeta.content = previousRobots;
      } else if (robotsMeta) {
        robotsMeta.remove();
      }
    };
  }, [title, robots]);
}

function PublicShell({
  children,
  eyebrow = 'No-access-first · Evidence-backed · SOC-gated',
  activeNav,
  loginHref = '/login',
  signupEnabled = true
}: {
  children: React.ReactNode;
  eyebrow?: string;
  activeNav?: 'login' | 'signup';
  loginHref?: string;
  signupEnabled?: boolean;
}) {
  return (
    <div className="public-app">
      <header className="public-topnav">
        <div className="public-topnav-inner">
          <a href="/" className="brand">
            <BrandMark />
            <span>AstraNull</span>
          </a>
          {eyebrow ? <span className="public-topnav-eyebrow eyebrow">{eyebrow}</span> : null}
          <nav className="public-topnav-actions" aria-label="Account access">
            <AnchorButton href={loginHref} variant={activeNav === 'login' ? 'default' : 'ghost'} size="sm">Log in</AnchorButton>
            {signupEnabled ? (
              <AnchorButton href="/signup" variant={activeNav === 'login' ? 'secondary' : 'default'} size="sm">Request access</AnchorButton>
            ) : null}
          </nav>
        </div>
      </header>
      {children}
    </div>
  );
}

function AuthPageLayout({
  aside,
  children,
  footer,
  wide = false
}: {
  aside: React.ReactNode;
  children: React.ReactNode;
  footer?: React.ReactNode;
  wide?: boolean;
}) {
  return (
    <main className={`auth-page${wide ? ' auth-page--wide' : ''}`}>
      <aside className="auth-aside">{aside}</aside>
      <section className="auth-panel">
        {children}
        {footer ? <footer className="auth-footer">{footer}</footer> : null}
      </section>
    </main>
  );
}

function AuthCardHeader({
  badge,
  title,
  description
}: {
  badge: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <CardHeader className="auth-card-header">
      {badge}
      <div className="auth-card-heading">
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </div>
    </CardHeader>
  );
}

const LANDING_PRINCIPLES = [
  {
    title: 'No-access-first',
    body: 'You declare the target groups you want validated. AstraNull never defaults to cloud access and never auto-discovers your IP inventory. Validation uses outside probes and inside agents you place. Nothing more.'
  },
  {
    title: 'Evidence over assumptions',
    body: 'Every verdict is backed by correlated probe results and agent observations, written to an evidence vault you control. Readiness is a number you can defend in an incident review, not a green checkmark.'
  },
  {
    title: 'SOC-gated high-scale',
    body: 'Default validation is low-volume, bounded, and non-disruptive. High-scale assessments are reviewed and executed by the AstraNull SOC after approval. Customers submit requests, never run floods themselves.'
  }
];

const LANDING_FLOW = [
  {
    step: '01',
    title: 'Scope your target groups',
    body: 'Register environments and target groups: the FQDNs, DNS zones, and TCP surfaces you want validated. Declare expected behavior so verdicts map to your real edge topology.'
  },
  {
    step: '02',
    title: 'Place agents, run safe checks',
    body: 'Install outbound-only agents and run the safe-by-default check catalog: origin-bypass, L3/L4, DNS, L7/API. Each check is bounded and metadata-only unless you escalate.'
  },
  {
    step: '03',
    title: 'Correlate probe + agent',
    body: 'Verdicts combine external probe reachability with internal agent path observation. Every result lands in the evidence vault, exportable for audits and incident reviews.'
  },
  {
    step: '04',
    title: 'Escalate through the SOC',
    body: 'When you need high-scale validation, submit a request. The SOC reviews, schedules, and executes under a kill switch, with full custody and audit trail.'
  }
];

const LANDING_COMPARE = [
  ['Requires cloud credentials', 'No. Declared scope only.', 'Often', 'Yes, read/write'],
  ['Default probe posture', 'Bounded & non-disruptive', 'High-volume by default', 'Passive metrics only'],
  ['Inside + outside correlation', 'Probes + placed agents', 'Outside only', 'Inside only'],
  ['High-scale execution', 'SOC-gated after approval', 'Self-service', 'Not available'],
  ['Exportable evidence trail', 'Evidence vault + custody', 'Run logs', 'Metric exports']
];

const LANDING_TRUST_ITEMS = [
  { icon: Check, text: 'No cloud credentials required' },
  { icon: Check, text: 'Low-volume, bounded probes' },
  { icon: Check, text: 'SOC-governed high-scale' },
  { icon: Check, text: 'Evidence-backed verdicts' }
] as const;

const LANDING_USE_CASES = [
  {
    quote: 'Regulated fintech that needs a defensible readiness number for audit, without granting a tool cloud credentials or letting it inventory production IPs.',
    attr: 'Platform & security leads. Declared-scope validation and evidence they can hand to an auditor.'
  },
  {
    quote: 'High-traffic media & CDN teams that want real high-scale assurance, but only under governance. No self-service floods pointed at production.',
    attr: 'SRE & edge owners. SOC-governed high-scale, bounded probes the rest of the time.'
  }
];

function ReadinessConsolePreview() {
  const verdicts: { id: string; kind: string; state: string; tone: BadgeTone }[] = [
    { id: 'chk_origin_bypass', kind: 'Origin-bypass', state: 'Pass', tone: 'success' },
    { id: 'chk_dns_shadow', kind: 'DNS', state: 'Review', tone: 'warn' },
    { id: 'chk_l7_rate', kind: 'L7 / API', state: 'Gap', tone: 'danger' },
    { id: 'chk_l3_l4', kind: 'L3 / L4', state: 'Pass', tone: 'success' }
  ];
  const readiness = 82;
  const circumference = 2 * Math.PI * 53;
  const dashOffset = circumference * (1 - readiness / 100);
  return (
    <aside className="public-card" aria-label="AstraNull readiness console preview" style={{ gap: 'var(--space-4)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
        <span aria-hidden="true" style={{ display: 'inline-flex', gap: '6px' }}>
          <i style={{ width: '9px', height: '9px', borderRadius: 'var(--radius-pill)', background: 'var(--border-strong)' }} />
          <i style={{ width: '9px', height: '9px', borderRadius: 'var(--radius-pill)', background: 'var(--border-strong)' }} />
          <i style={{ width: '9px', height: '9px', borderRadius: 'var(--radius-pill)', background: 'var(--border-strong)' }} />
        </span>
        <span className="muted" style={{ fontSize: 'var(--text-xs)' }}>
          tenant · <b style={{ color: 'var(--fg)' }}>acme-prod</b>
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 'var(--space-5)', alignItems: 'center' }}>
        <div style={{ position: 'relative', width: '120px', height: '120px', display: 'grid', placeItems: 'center' }}>
          <svg viewBox="0 0 120 120" width="120" height="120" aria-hidden="true" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="60" cy="60" r="53" fill="none" stroke="var(--border)" strokeWidth="8" />
            <circle
              cx="60"
              cy="60"
              r="53"
              fill="none"
              stroke="var(--accent)"
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
            />
          </svg>
          <div style={{ position: 'absolute', textAlign: 'center' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xl)', lineHeight: 1, color: 'var(--fg)' }}>{readiness}</div>
            <div className="muted" style={{ fontSize: 'var(--text-xs)', textTransform: 'uppercase', letterSpacing: 'var(--tracking-caps)' }}>Readiness</div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: 'var(--text-xs)', color: 'var(--fg-2)' }}>
              <TrendingUp size={12} aria-hidden="true" style={{ color: 'var(--success)' }} />
              6 vs last cycle
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
          {verdicts.map((verdict) => (
            <div key={verdict.id} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <span className="mono" style={{ fontSize: 'var(--text-xs)', color: 'var(--fg)' }}>{verdict.id}</span>
              <span className="muted" style={{ fontSize: 'var(--text-xs)', marginLeft: 'auto' }}>{verdict.kind}</span>
              <Badge tone={verdict.tone}>{verdict.state}</Badge>
            </div>
          ))}
        </div>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', alignItems: 'center', fontSize: 'var(--text-xs)', borderTop: '1px solid var(--border)', paddingTop: 'var(--space-3)' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', color: 'var(--fg-2)' }}>
          <ShieldCheck size={12} aria-hidden="true" style={{ color: 'var(--success)' }} />
          custody · json-key-sorted-v1
        </span>
        <span className="mono muted">sha256:9f2a…c41e</span>
        <span className="muted" style={{ marginLeft: 'auto' }}>evidence vault · 1,284 artifacts</span>
      </div>
    </aside>
  );
}

function ProofChainSection() {
  const nodes: { label: string; title: string; body: string; src: string[] }[] = [
    {
      label: 'Outside probe',
      title: 'Origin reached directly under bounded load.',
      body: 'A bounded 50 RPS origin-bypass request reached the origin at 47 ms; the scrubber tier was bypassed at the second hop. No high-volume traffic was generated.',
      src: ['probe · probe-eu-west-2', 'bound · 50 RPS · metadata-only']
    },
    {
      label: 'Inside agent',
      title: 'Agent saw the direct-to-origin path.',
      body: 'The outbound-only agent agt_edge_01 observed a direct TCP handshake to the origin, bypassing the declared WAF pool. The agent path agrees with the probe.',
      src: ['agent · agt_edge_01', 'heartbeat · healthy · v1.4.2']
    },
    {
      label: 'Correlated verdict',
      title: 'Origin exposed under bounded load → Gap.',
      body: 'Probe and agent agree the origin is reachable behind the declared edge. Verdict: Gap, severity S2, owner edge-sre. Retest opens automatically on the next safe window.',
      src: ['custody · json-key-sorted-v1', 'sha256 4c1b…e7a9 · signed']
    }
  ];
  return (
    <section className="public-section" id="proof">
      <h2>Every verdict traces back to observed data.</h2>
      <p className="public-section-lead">A readiness verdict in AstraNull is never a green checkmark. It is an outside probe correlated with an inside agent observation, sealed with a custody digest you can hand to an auditor.</p>
      <div className="public-card" style={{ gap: 'var(--space-5)' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-sm)' }}>
          <span className="mono" style={{ color: 'var(--fg)' }}>chk_l7_rate</span>
          <Badge tone="danger">Gap · Severity S2</Badge>
          <span className="muted" style={{ marginLeft: 'auto' }}>run run_8f3c… · sealed with custody digest</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 'var(--space-4)' }}>
          {nodes.map((node) => (
            <article
              key={node.label}
              style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', background: 'var(--proof-surface)', padding: 'var(--space-4)' }}
            >
              <span className="eyebrow" style={{ color: 'var(--accent)' }}>{node.label}</span>
              <h3 style={{ margin: 0, fontSize: 'var(--text-base)', color: 'var(--fg)' }}>{node.title}</h3>
              <p className="muted" style={{ margin: 0, fontSize: 'var(--text-sm)' }}>{node.body}</p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', marginTop: 'auto', paddingTop: 'var(--space-2)' }}>
                {node.src.map((line) => (
                  <span key={line} className="mono muted" style={{ fontSize: 'var(--text-xs)' }}>{line}</span>
                ))}
              </div>
            </article>
          ))}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', alignItems: 'center', fontSize: 'var(--text-xs)', borderTop: '1px solid var(--border)', paddingTop: 'var(--space-3)' }}>
          <Badge tone="muted">Evidence bundle</Badge>
          <span className="muted">3 artifacts · probe-result.json · agent-observation.json · verdict.json</span>
          <span className="muted" style={{ marginLeft: 'auto' }}>Exportable to the evidence vault for audit</span>
        </div>
      </div>
    </section>
  );
}

export function PublicLandingPage({ config }: PublicPageProps) {
  const productName = String(config.siteConfig.product_name ?? 'AstraNull');
  const promise = String(config.siteConfig.promise ?? PLATFORM_PROMISE);
  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const loginUrl = config.loginUrl;

  usePageMeta({
    title: `${productName} · Prove DDoS readiness without handing over your cloud keys`
  });

  return (
    <PublicShell loginHref={loginUrl} signupEnabled={signupEnabled}>
      <main className="public-wrap">
        <p className="auth-field-help">
          <a href="#how">Skip to how it works</a>
        </p>
        <section className="public-hero">
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 'var(--space-8)', alignItems: 'center' }}>
            <div>
              <p className="eyebrow">DDoS readiness validation</p>
              <h1>
                Prove DDoS readiness{' '}
                <span style={{ color: 'var(--accent)' }}>without handing over</span>{' '}
                your cloud keys.
              </h1>
              <p className="public-hero-lead">{promise}</p>
              <div className="public-actions">
                {signupEnabled ? (
                  <AnchorButton href="/signup">
                    Request access
                    <ArrowRight size={15} aria-hidden="true" />
                  </AnchorButton>
                ) : (
                  <AnchorButton href={loginUrl}>Log in</AnchorButton>
                )}
                <AnchorButton href="#how" variant="ghost">See how it works</AnchorButton>
              </div>
              <div className="public-hero-meta" id="trust" aria-label="Platform trust commitments">
                {LANDING_TRUST_ITEMS.map(({ icon: Icon, text }) => (
                  <span key={text}>
                    <Icon size={16} aria-hidden="true" />
                    {text}
                  </span>
                ))}
              </div>
            </div>
            <ReadinessConsolePreview />
          </div>
        </section>

        <section className="public-section" id="principles">
          <h2>A defensive readiness platform, not self-service attack tooling.</h2>
          <p className="public-section-lead">Three commitments shape every screen, every probe, every verdict in AstraNull.</p>
          <div className="public-pillars">
            {LANDING_PRINCIPLES.map((pillar) => (
              <article className="public-pillar" key={pillar.title}>
                <h3>{pillar.title}</h3>
                <p>{pillar.body}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="public-section" id="how">
          <p className="eyebrow">The loop</p>
          <h2>Declare. Validate. Evidence. Govern.</h2>
          <p className="public-section-lead">A four-stage loop that turns a declared scope into a defensible readiness posture.</p>
          <div className="public-flow">
            {LANDING_FLOW.map((item) => (
              <article className="public-flow-step" key={item.step}>
                <p className="public-flow-tag">{item.step}</p>
                <h3>{item.title}</h3>
                <p>{item.body}</p>
              </article>
            ))}
          </div>
        </section>

        <ProofChainSection />

        <section className="public-section public-section--narrow" id="compare">
          <h2>Built for teams that can&apos;t hand over the keys.</h2>
          <div className="public-compare table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col" />
                  <th scope="col">AstraNull</th>
                  <th scope="col">Self-run load tests</th>
                  <th scope="col">Provider DDoS dashboards</th>
                </tr>
              </thead>
              <tbody>
                {LANDING_COMPARE.map(([label, anull, legacy, cloud]) => (
                  <tr key={label}>
                    <th scope="row">{label}</th>
                    <td className="public-compare-yes">{anull}</td>
                    <td>{legacy}</td>
                    <td>{cloud}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        <section className="public-section">
          <h2>Where the no-access model matters most.</h2>
          <p className="public-section-lead">Two profiles that keep hitting the wall between &ldquo;prove the edge holds&rdquo; and &ldquo;don&apos;t hand a validation tool our cloud keys.&rdquo;</p>
          <div className="public-quotes">
            {LANDING_USE_CASES.map((item) => (
              <article className="public-quote" key={item.attr}>
                <blockquote>{item.quote}</blockquote>
                <p>{item.attr}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="public-cta-final">
          <h2>Prove your edge holds. Before an attacker does it for you.</h2>
          <p>Request access. We&apos;ll review your account and stand up a tenant with the full customer portal.</p>
          <PublicAccessActions signupEnabled={signupEnabled} loginUrl={loginUrl} />
        </section>

        <footer className="public-footer">
          <span>© {productName} · DDoS readiness validation. Defensive platform only.</span>
          <nav aria-label="Public footer">
            <a href={loginUrl}>Log in</a>
            {signupEnabled ? <a href="/signup">Request access</a> : null}
            <a href="/signup-status">Request status</a>
            <a href={config.staffLoginPath}>Staff sign-in</a>
            <a href="#principles">Principles</a>
            <a href="#how">How it works</a>
            <a href="#compare">Compare</a>
          </nav>
        </footer>
      </main>
    </PublicShell>
  );
}

export function LoginPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Log in · AstraNull Customer Portal' });

  const [userId, setUserId] = useState('');
  const [role, setRole] = useState('admin');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const isDevHeaders = config.authMode === 'dev-headers';
  const isOidc = isOidcJwtMode(config);
  const showStagingRolePicker = isDevHeaders || config.bundledLoginEnabled;
  const idpRedirect = useMemo(() => resolveOidcLoginRedirect(config, 'customer'), [config]);
  const loginDisabled = isOidc && !config.bundledLoginEnabled && !idpRedirect;

  useEffect(() => {
    const existing = loadSession();
    if (existing?.access_token && existing.principal !== 'staff') {
      window.location.replace(config.portalPath);
    }
  }, [config.portalPath]);

  useEffect(() => {
    if (idpRedirect) window.location.replace(idpRedirect);
  }, [idpRedirect]);

  useEffect(() => {
    if (loginDisabled) {
      setError('Enterprise SSO is required for this deployment. Contact your administrator for a login link.');
    }
  }, [loginDisabled]);

  const cardDescription = isDevHeaders
    ? 'Developer validation mode: continue with local tenant headers (no password required).'
    : config.bundledLoginEnabled
      ? 'Bundled staging login mints a short-lived bearer session for this environment.'
      : idpRedirect
        ? 'Redirecting to your organization sign-in provider.'
        : 'Sign-in is managed by your organization identity provider.';

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (loginDisabled) return;
    setError('');
    setLoading(true);

    if (isDevHeaders) {
      saveSession({
        mode: 'dev-headers',
        principal: 'customer',
        tenant_id: 'ten_demo',
        user_id: userId.trim(),
        role
      });
      window.location.href = config.portalPath;
      return;
    }

    try {
      const response = await fetch('/v1/auth/bundled-staging-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          principal: 'customer',
          tenant_id: 'ten_demo',
          user_id: userId.trim(),
          role
        })
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(String(json.message ?? json.error ?? 'Login failed.'));
      saveSession(sessionFromLoginResponse(json as Record<string, unknown>));
      window.location.href = config.portalPath;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed.');
      setLoading(false);
    }
  }

  return (
    <PublicShell eyebrow="Customer portal" activeNav="login">
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Log in to your readiness console.</h1>
            <p className="auth-lead">
              {isDevHeaders
                ? 'Local developer validation uses tenant headers to preview RBAC without a password.'
                : 'Review declared targets, agent heartbeats, safe validation runs, and SOC-governed high-scale intake from one tenant-scoped surface.'}
            </p>
            <AuthAsidePoints
              items={[
                { icon: ShieldCheck, text: 'Evidence-backed verdicts tied to observed probe data' },
                { icon: LockKeyhole, text: 'No default cloud credentials required' },
                { icon: FileCheck2, text: 'Audit-ready exports and custody references' }
              ]}
            />
          </>
        )}
        footer={(
          <p>
            Need an account? <a href="/signup">Request access</a>
            {' · '}
            <a href="/signup-status">Check request status</a>
          </p>
        )}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">Customer portal</Badge>}
            title="Log in to AstraNull"
            description={cardDescription}
          />
          <CardContent>
            {idpRedirect ? (
              <AuthRedirectPanel
                lead="Redirecting to your identity provider…"
                help="You will be sent to your organization&apos;s sign-in page. If nothing happens, contact your administrator."
              />
            ) : (
              <form className="auth-form" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="login-user-id">
                  <span>{isDevHeaders || config.bundledLoginEnabled ? 'Work email / user ID' : 'User ID'}</span>
                  <input
                    id="login-user-id"
                    value={userId}
                    onChange={(event) => setUserId(event.target.value)}
                    autoComplete="username"
                    required={!loginDisabled}
                    disabled={loginDisabled}
                  />
                </label>
                {isDevHeaders ? (
                  <label htmlFor="login-tenant-id">
                    <span>Tenant</span>
                    <input id="login-tenant-id" value="ten_demo" readOnly aria-readonly="true" disabled={loginDisabled} />
                  </label>
                ) : null}
                {showStagingRolePicker ? (
                  <div className="auth-field-group">
                    <Select
                      label={isDevHeaders ? 'Role' : 'Staging role'}
                      value={role}
                      options={CUSTOMER_STAGING_ROLES.map((item) => ({
                        value: item,
                        label: customerStagingRoleLabel(item)
                      }))}
                      onChange={setRole}
                      disabled={loginDisabled}
                    />
                    {!isDevHeaders && config.bundledLoginEnabled ? (
                      <span className="auth-field-help">Staging only. Production sign-in derives role from your identity provider.</span>
                    ) : null}
                  </div>
                ) : null}
                {error ? <p className="form-error" role="alert">{error}</p> : null}
                <div className="auth-form-actions">
                  <Button type="submit" loading={loading} disabled={loginDisabled}>
                    Continue to portal
                  </Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

const SIGNUP_PLAN_LABELS: Record<string, string> = {
  starter: 'Starter',
  professional: 'Professional',
  enterprise: 'Enterprise'
};

const SIGNUP_REGION_LABELS: Record<string, string> = {
  us: 'United States',
  eu: 'European Union',
  uk: 'United Kingdom',
  apac: 'Asia-Pacific'
};

function signupPlanLabel(slug: unknown) {
  const key = String(slug ?? '').trim();
  return SIGNUP_PLAN_LABELS[key] ?? (key || 'Professional');
}

function signupRegionLabel(slug: unknown) {
  const key = String(slug ?? '').trim();
  return SIGNUP_REGION_LABELS[key] ?? (key || 'United States');
}

type SignupPlanOption = { value: string; label: string };

// Consume plans[] from the public site-config (config.siteConfig.plans) so the
// requested-plan options reflect the server's subscription catalog rather than a
// hardcoded list. Falls back to the static labels if the config omits plans.
function signupPlanOptions(config: PublicPageProps['config']): SignupPlanOption[] {
  const rawPlans = (config.siteConfig as { plans?: unknown }).plans;
  if (Array.isArray(rawPlans)) {
    const options = rawPlans
      .map((plan): SignupPlanOption | null => {
        if (!plan || typeof plan !== 'object') return null;
        const record = plan as Record<string, unknown>;
        const value = String(record.id ?? '').trim();
        if (!value) return null;
        const label = String(record.name ?? '').trim() || signupPlanLabel(value);
        return { value, label };
      })
      .filter((option): option is SignupPlanOption => option !== null);
    if (options.length > 0) return options;
  }
  return Object.entries(SIGNUP_PLAN_LABELS).map(([value, label]) => ({ value, label }));
}

const CUSTOMER_STAGING_ROLES = ['admin', 'engineer', 'soc', 'viewer', 'auditor', 'owner'] as const;

const CUSTOMER_STAGING_ROLE_LABELS: Record<(typeof CUSTOMER_STAGING_ROLES)[number], string> = {
  admin: 'Admin',
  engineer: 'Engineer',
  soc: 'SOC',
  viewer: 'Viewer',
  auditor: 'Auditor',
  owner: 'Owner'
};

function customerStagingRoleLabel(slug: string) {
  return CUSTOMER_STAGING_ROLE_LABELS[slug as (typeof CUSTOMER_STAGING_ROLES)[number]] ?? slug.replace(/_/g, ' ');
}

const STAFF_STAGING_ROLES = [
  'internal_admin',
  'billing_ops',
  'support_engineer',
  'security_admin',
  'soc_analyst',
  'soc_lead'
] as const;

function signupSubmitErrorMessage(status: number, json: Record<string, unknown>) {
  const code = String(json.error ?? '');
  if (status === 429 || code === 'rate_limited') {
    return 'Too many sign-up attempts. Please try again later.';
  }
  if (code === 'duplicate_request') {
    return 'A pending request already exists for this organization or email domain.';
  }
  if (status === 403 || code === 'signup_disabled') {
    return 'Account requests are not being accepted right now. Contact your AstraNull representative.';
  }
  if (code === 'validation_failed') {
    return 'Could not submit request. Check required fields and try again.';
  }
  return String(json.message ?? json.error ?? 'Could not submit request.');
}

export function SignupPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Request access · AstraNull' });

  const signupEnabled = config.siteConfig.signup_enabled !== false;
  const [submitted, setSubmitted] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [hydrating, setHydrating] = useState(false);
  const [requestedPlan, setRequestedPlan] = useState('professional');
  const [region, setRegion] = useState('us');
  const planOptions = useMemo(() => signupPlanOptions(config), [config]);

  useEffect(() => {
    if (planOptions.length > 0 && !planOptions.some((option) => option.value === requestedPlan)) {
      setRequestedPlan(planOptions[0].value);
    }
  }, [planOptions, requestedPlan]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const id = new URLSearchParams(window.location.search).get('id')?.trim();
    if (!id) return;

    let cancelled = false;
    setHydrating(true);
    void (async () => {
      try {
        const response = await fetch(`/v1/signup-requests/${encodeURIComponent(id)}`, {
          headers: { accept: 'application/json' }
        });
        const json = await response.json().catch(() => ({}));
        if (cancelled) return;
        if (!response.ok) return;
        setSubmitted((json.request ?? json) as Record<string, unknown>);
      } finally {
        if (!cancelled) setHydrating(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!signupEnabled) return;
    setError('');
    setLoading(true);
    const data = new FormData(event.currentTarget);
    const body = {
      organization_name: data.get('organization_name'),
      contact_email: data.get('contact_email'),
      contact_name: data.get('contact_name'),
      requested_plan: data.get('requested_plan'),
      intended_use: data.get('intended_use'),
      region: data.get('region'),
      high_scale_interest: data.get('high_scale_interest') === 'on'
    };
    try {
      const response = await fetch('/v1/signup-requests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(signupSubmitErrorMessage(response.status, json as Record<string, unknown>));
      const record = (json.request ?? json) as Record<string, unknown>;
      setSubmitted(record);
      const submittedId = String(record.id ?? '').trim();
      if (submittedId && typeof window !== 'undefined') {
        const url = new URL(window.location.href);
        url.searchParams.set('id', submittedId);
        window.history.replaceState({}, '', `${url.pathname}${url.search}${url.hash}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not submit request.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <PublicShell eyebrow="Approval-gated account intake" activeNav="signup">
      <AuthPageLayout
        wide
        aside={(
          <>
            <h1 className="auth-title">Request governed validation access.</h1>
            <p className="auth-lead">Provisioning is review-gated. Operations validates organization details, intended use, and plan fit before creating a tenant workspace.</p>
            <AuthAsidePoints
              items={[
                { icon: ShieldCheck, text: 'Safe-by-default validation is available immediately after approval' },
                { icon: Siren, text: 'High-scale programs stay SOC-scheduled and pack-gated' },
                { icon: UserRound, text: 'Track request status any time with your request ID' }
              ]}
            />
          </>
        )}
        footer={(
          <p>
            Already have access? <a href="/login">Log in</a>
            {' · '}
            <a href="/signup-status">Check request status</a>
          </p>
        )}
      >
        <Card className="auth-card auth-card--wide">
          <AuthCardHeader
            badge={<Badge tone="info">Reviewed access</Badge>}
            title={submitted ? 'Request submitted' : 'Request an AstraNull account'}
            description="Account creation is reviewed before provisioning a tenant. Save your request ID to check status any time."
          />
          <CardContent>
            {!signupEnabled ? (
              <div className="success-panel">
                <div className="callout warn">
                  <TriangleAlert size={18} aria-hidden="true" />
                  <p className="success-panel-lead">Account intake is temporarily closed for this deployment. Existing customers can sign in; approved request IDs can still be checked on the status page.</p>
                </div>
                <div className="auth-form-actions row-actions">
                  <AnchorButton href="/login" variant="secondary">Log in</AnchorButton>
                  <AnchorButton href="/signup-status">Check request status</AnchorButton>
                </div>
              </div>
            ) : hydrating ? (
              <div role="status" aria-live="polite" aria-busy="true">
                <p className="success-panel-lead">Loading your request confirmation…</p>
                <SignupFormSkeleton />
              </div>
            ) : submitted ? (
              <div className="success-panel" role="status" aria-live="polite">
                <div className="callout info">
                  <CheckCircle2 size={18} aria-hidden="true" />
                  <p className="success-panel-lead">We provision reviewed accounts only. Save your request ID to check status any time.</p>
                </div>
                <SignupRequestSummary record={submitted} organizationFallback="Recorded" showPlanBadgeWhenMissing statusFallback="submitted" />
                <div className="auth-form-actions row-actions">
                  <AnchorButton
                    href={`/signup-status?id=${encodeURIComponent(String(submitted.id ?? ''))}`}
                    variant="secondary"
                  >
                    Check status
                  </AnchorButton>
                  <AnchorButton href="/">Back to landing</AnchorButton>
                </div>
              </div>
            ) : (
              <form className="auth-form auth-form--grid" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="signup-organization"><span>Organization</span><input id="signup-organization" name="organization_name" required placeholder="Acme Corp" autoComplete="organization" disabled={loading} /></label>
                <label htmlFor="signup-contact"><span>Contact name</span><input id="signup-contact" name="contact_name" required placeholder="Jordan Lee" autoComplete="name" disabled={loading} /></label>
                <label className="auth-field-full" htmlFor="signup-email"><span>Contact email</span><input id="signup-email" name="contact_email" type="email" required placeholder="you@company.com" autoComplete="email" disabled={loading} /></label>
                <Select
                  label="Requested plan"
                  name="requested_plan"
                  value={requestedPlan}
                  options={planOptions}
                  onChange={setRequestedPlan}
                  disabled={loading}
                />
                <Select
                  label="Region"
                  name="region"
                  value={region}
                  options={Object.entries(SIGNUP_REGION_LABELS).map(([value, label]) => ({ value, label }))}
                  onChange={setRegion}
                  disabled={loading}
                />
                <label className="auth-field-full" htmlFor="signup-intended-use"><span>Intended use</span><textarea id="signup-intended-use" name="intended_use" required rows={4} placeholder="Defensive readiness for declared production origins." disabled={loading} /></label>
                <label className="auth-field-full auth-check-row" htmlFor="signup-high-scale"><input id="signup-high-scale" name="high_scale_interest" type="checkbox" disabled={loading} /><span>Interested in governed high-scale rehearsal programs.</span></label>
                {error ? <p className="form-error auth-field-full" role="alert">{error}</p> : null}
                <div className="auth-form-actions auth-field-full">
                  <Button type="submit" loading={loading}>Submit request</Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

export function SignupStatusPage() {
  usePageMeta({ title: 'Request status · AstraNull' });

  const [requestId, setRequestId] = useState(() => {
    if (typeof window === 'undefined') return '';
    return new URLSearchParams(window.location.search).get('id')?.trim() ?? '';
  });
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function lookupSignupRequest(id: string) {
    const trimmed = id.trim();
    if (!trimmed) {
      setError('Enter a request ID to check status.');
      return;
    }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const response = await fetch(`/v1/signup-requests/${encodeURIComponent(trimmed)}`, {
        headers: { accept: 'application/json' }
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(String(json.message ?? json.error ?? 'Request status was not found.'));
      setResult((json.request ?? json) as Record<string, unknown>);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request status was not found.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const urlId = new URLSearchParams(window.location.search).get('id')?.trim();
    if (!urlId) return;
    void lookupSignupRequest(urlId);
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    await lookupSignupRequest(requestId);
  }

  return (
    <PublicShell eyebrow="Request status lookup">
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Check your access request.</h1>
            <p className="auth-lead">Track your account request. You&apos;ll find the request ID in the confirmation panel shown after you submit the intake form, or in the email we sent to the work address you registered.</p>
          </>
        )}
        footer={(
          <p>
            Lost your request ID?{' '}
            <a href="mailto:support@astranull.example?subject=Sign-up%20request%20ID%20recovery">Contact support</a>
            {' · '}
            <a href="/login">Log in</a>
          </p>
        )}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="info">Status lookup</Badge>}
            title="Check request status"
            description="Account provisioning remains review-gated and every status change is reviewed by operations."
          />
          <CardContent>
            <form className="auth-form" onSubmit={submit} aria-busy={loading}>
              <label htmlFor="signup-status-request-id">
                <span>Request ID</span>
                <input
                  id="signup-status-request-id"
                  value={requestId}
                  onChange={(event) => setRequestId(event.target.value)}
                  placeholder="sgn_… (from your confirmation)"
                  className="mono"
                  autoComplete="off"
                  required
                  disabled={loading}
                  aria-describedby="signup-status-request-id-help"
                />
                <span className="auth-field-help" id="signup-status-request-id-help">Use the ID returned after intake submission. Case-sensitive.</span>
              </label>
              {error ? <p className="form-error" role="alert">{error}</p> : null}
              <div className="auth-form-actions">
                <Button type="submit" loading={loading}>Look up status</Button>
              </div>
            </form>
            {loading && !result ? (
              <div className="stack-tight" role="status" aria-live="polite" aria-busy="true" aria-label="Loading request status">
                <span className="skeleton skeleton-row" />
                <span className="skeleton skeleton-row" />
                <span className="skeleton skeleton-row" />
              </div>
            ) : null}
            {result ? (
              <div className="success-panel" role="status" aria-live="polite">
                <div className="callout info">
                  <CheckCircle2 size={18} aria-hidden="true" />
                  <p className="success-panel-lead">Request found. Provisioning remains review-gated.</p>
                </div>
                <SignupRequestSummary record={result} requestIdFallback={requestId} />
                {result.customer_notice ? (
                  <p className="auth-field-help">{String(result.customer_notice)}</p>
                ) : null}
              </div>
            ) : null}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

export function StaffLoginPage({ config }: PublicPageProps) {
  usePageMeta({ title: 'Staff sign-in · AstraNull Internal', robots: 'noindex, nofollow' });

  const [staffId, setStaffId] = useState('');
  const [staffRole, setStaffRole] = useState('internal_admin');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const isDevHeaders = config.authMode === 'dev-headers';
  const isOidc = isOidcJwtMode(config);
  const showStagingStaffRolePicker = isDevHeaders || config.bundledLoginEnabled;
  const idpRedirect = useMemo(() => resolveOidcLoginRedirect(config, 'staff'), [config]);
  const loginDisabled = isOidc && !config.bundledLoginEnabled && !idpRedirect;
  const staffLoginPath = typeof window !== 'undefined' ? window.location.pathname : config.staffLoginPath;

  useEffect(() => {
    const existing = loadSession();
    if (existing?.access_token && existing.principal === 'staff') {
      window.location.replace('/internal/admin');
    }
  }, []);

  useEffect(() => {
    if (idpRedirect) window.location.replace(idpRedirect);
  }, [idpRedirect]);

  useEffect(() => {
    if (loginDisabled) setError('Staff SSO is required for this deployment.');
  }, [loginDisabled]);

  const cardDescription = isDevHeaders
    ? 'Developer validation mode: continue with staff dev headers (no password required).'
    : config.bundledLoginEnabled
      ? 'Bundled staging login mints a short-lived staff bearer session for this environment.'
      : idpRedirect
        ? 'Redirecting to your organization staff sign-in provider.'
        : 'Staff sign-in is managed by your organization identity provider.';

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (loginDisabled) return;
    setError('');
    setLoading(true);

    if (isDevHeaders) {
      saveSession({
        mode: 'dev-headers',
        principal: 'staff',
        staff_id: staffId.trim(),
        staff_role: staffRole,
        staff_login_path: staffLoginPath
      });
      window.location.href = '/internal/admin';
      return;
    }

    try {
      const response = await fetch('/v1/auth/bundled-staging-login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          principal: 'staff',
          staff_id: staffId.trim(),
          staff_role: staffRole
        })
      });
      const json = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(String(json.message ?? json.error ?? 'Staff login failed.'));
      saveSession({
        ...sessionFromLoginResponse(json as Record<string, unknown>),
        staff_login_path: staffLoginPath
      });
      window.location.href = '/internal/admin';
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Staff login failed.');
      setLoading(false);
    }
  }

  return (
    <PublicShell eyebrow="Internal staff access">
      <AuthPageLayout
        aside={(
          <>
            <h1 className="auth-title">Sign in to internal management.</h1>
            <p className="auth-lead">
              {isDevHeaders
                ? 'Local developer validation uses staff headers to preview internal RBAC without a password.'
                : 'Review signup intake, tenant lifecycle, entitlement grants, approval queues, and internal audit from a separate staff surface.'}
            </p>
            <p className="auth-field-help" role="note">
              Provisioning and approval actions on this surface are written to the internal audit log.
            </p>
          </>
        )}
        footer={<p><a href="/">Back to site</a> · <a href="/login">Customer login</a></p>}
      >
        <Card className="auth-card">
          <AuthCardHeader
            badge={<Badge tone="warn">Staff plane</Badge>}
            title="Staff sign-in"
            description={cardDescription}
          />
          <CardContent>
            {idpRedirect ? (
              <AuthRedirectPanel
                lead="Redirecting to your staff identity provider…"
                help="You will be sent to your organization&apos;s staff sign-in page. If nothing happens, contact your administrator."
              />
            ) : (
              <form className="auth-form" onSubmit={submit} aria-busy={loading}>
                <label htmlFor="staff-login-id">
                  <span>Staff ID</span>
                  <input
                    id="staff-login-id"
                    value={staffId}
                    onChange={(event) => setStaffId(event.target.value)}
                    autoComplete="username"
                    required={!loginDisabled}
                    disabled={loginDisabled}
                  />
                </label>
                {showStagingStaffRolePicker ? (
                  <div className="auth-field-group">
                    <Select
                      label={isDevHeaders ? 'Staff role' : 'Staging staff role'}
                      value={staffRole}
                      options={STAFF_STAGING_ROLES.map((item) => ({
                        value: item,
                        label: staffRoleLabel(item)
                      }))}
                      onChange={setStaffRole}
                      disabled={loginDisabled}
                    />
                    {!isDevHeaders && config.bundledLoginEnabled ? (
                      <span className="auth-field-help">Staging only. Production staff sign-in derives role from your identity provider.</span>
                    ) : null}
                  </div>
                ) : null}
                {error ? <p className="form-error" role="alert">{error}</p> : null}
                <div className="auth-form-actions">
                  <Button type="submit" loading={loading} disabled={loginDisabled}>
                    Continue to internal admin
                  </Button>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
      </AuthPageLayout>
    </PublicShell>
  );
}

export function InternalAdminPage({ config }: PublicPageProps) {
  void config;
  return (
    <PublicShell eyebrow="Staff management">
      <main className="public-wrap">
        <section className="page-head staff-head">
          <div>
            <Badge tone="warn">Staff plane</Badge>
            <h2>Internal Admin</h2>
            <p className="muted">Tenant lifecycle, sign-up review, subscriptions, support actions, approvals, and audit, separate from the customer portal.</p>
          </div>
          <AnchorButton href="/app" variant="secondary">Customer portal</AnchorButton>
        </section>
        <Card density="compact">
          <CardHeader>
            <CardTitle>Staff destinations</CardTitle>
            <CardDescription>Jump to governed staff surfaces. Tenant detail opens from the admin tenant directory after sign-in.</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="dashboard-link-list">
              {STAFF_LINKS.map((link) => (
                  <li key={link.label}>
                    <div>
                      <strong>{link.label}</strong>
                      <span>{link.description}</span>
                    </div>
                    <AnchorButton href={link.href} size="sm" variant="secondary">
                      Open
                      <ArrowRight size={13} aria-hidden="true" />
                    </AnchorButton>
                  </li>
              ))}
              <li>
                <div>
                  <strong>Tenant detail</strong>
                  <span>Lifecycle state, entitlements, owner users, support notes, and audit activity.</span>
                </div>
                <Badge tone="muted">From admin queue</Badge>
              </li>
            </ul>
          </CardContent>
        </Card>
      </main>
    </PublicShell>
  );
}
