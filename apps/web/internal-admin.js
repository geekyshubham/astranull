let route = 'overview';
let selectedTenantId = null;
let selectedSignupId = null;

const el = (id) => document.getElementById(id);

function staffHeaders() {
  return {
    'x-principal-type': 'staff',
    'x-staff-id': el('staffId')?.value ?? 'staff_admin',
    'x-staff-role': el('staffRole')?.value ?? 'internal_admin',
  };
}

async function staffApi(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...staffHeaders(),
      ...(options.headers ?? {}),
    },
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function renderOverview() {
  const { status, json } = await staffApi('/internal/admin/overview');
  if (status !== 200) {
    return `<div class="empty">Could not load overview (${status}).</div>`;
  }
  const o = json;
  return `
    <div class="grid">
      <div class="card"><div class="metric">${o.pending_signups ?? 0}</div><div class="muted">Pending sign-ups</div></div>
      <div class="card"><div class="metric">${o.high_scale_reviews ?? 0}</div><div class="muted">High-scale reviews</div></div>
      <div class="card"><div class="metric">${o.blocked_tenants ?? 0}</div><div class="muted">Suspended tenants</div></div>
      <div class="card"><div class="metric">${o.tenant_count ?? 0}</div><div class="muted">Total tenants</div></div>
    </div>`;
}

async function renderSignupQueue() {
  const { status, json } = await staffApi('/internal/admin/signup-requests');
  if (status !== 200) {
    return `<div class="empty">Could not load sign-up queue (${status}).</div>`;
  }
  const rows = (json.items ?? []).map((r) => `
    <tr>
      <td><button class="btn secondary btn-sm" data-action="select-signup" data-id="${esc(r.id)}">${esc(r.id)}</button></td>
      <td>${esc(r.organization_name)}</td>
      <td>${esc(r.email_domain)}</td>
      <td>${esc(r.requested_plan)}</td>
      <td><span class="pill">${esc(r.state)}</span></td>
      <td>${esc(r.created_at)}</td>
    </tr>`).join('');
  let detail = '';
  if (selectedSignupId) {
    const item = (json.items ?? []).find((r) => r.id === selectedSignupId);
    if (item) {
      detail = `
        <div class="card">
          <h3>Review ${esc(item.organization_name)}</h3>
          <p class="muted">${esc(item.contact_email)} · ${esc(item.contact_name)} · ${esc(item.region)}</p>
          <p>${esc(item.intended_use)}</p>
          <div class="friendly-empty-actions">
            <button class="btn" data-action="approve-signup" data-id="${esc(item.id)}">Approve &amp; provision</button>
            <button class="btn secondary" data-action="reject-signup" data-id="${esc(item.id)}">Reject</button>
          </div>
          <p id="signupActionOut" class="muted"></p>
        </div>`;
    }
  }
  return `
    ${detail}
    <div class="card">
      <table>
        <thead><tr><th>ID</th><th>Organization</th><th>Domain</th><th>Plan</th><th>State</th><th>Created</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="muted">No sign-up requests.</td></tr>'}</tbody>
      </table>
    </div>`;
}

async function renderTenants() {
  const { status, json } = await staffApi('/internal/admin/tenants');
  if (status !== 200) {
    return `<div class="empty">Could not load tenants (${status}).</div>`;
  }
  const rows = (json.items ?? []).map((t) => `
    <tr>
      <td><button class="btn secondary btn-sm" data-action="select-tenant" data-id="${esc(t.tenant_id)}">${esc(t.tenant_id)}</button></td>
      <td>${esc(t.name)}</td>
      <td>${esc(t.plan_id ?? '—')}</td>
      <td>${esc(t.lifecycle_state ?? 'active')}</td>
      <td>${t.user_count ?? 0}</td>
    </tr>`).join('');

  let detail = '';
  if (selectedTenantId) {
    const { status: dStatus, json: detailJson } = await staffApi(
      `/internal/admin/tenants/${encodeURIComponent(selectedTenantId)}`,
    );
    if (dStatus === 200) {
      const users = (detailJson.users ?? []).map((u) => `
        <tr>
          <td>${esc(u.email)}</td><td>${esc(u.role)}</td><td>${esc(u.status)}</td>
          <td>
            <button class="btn secondary btn-sm" data-action="resend-invite" data-tenant="${esc(selectedTenantId)}" data-user="${esc(u.id)}">Resend invite</button>
            <button class="btn secondary btn-sm" data-action="disable-user" data-tenant="${esc(selectedTenantId)}" data-user="${esc(u.id)}">Disable</button>
          </td>
        </tr>`).join('');
      const sub = detailJson.subscription ?? {};
      detail = `
        <div class="card">
          <h3>${esc(detailJson.tenant?.name)}</h3>
          <p class="muted">Plan: ${esc(sub.plan_id)} · Status: ${esc(sub.status)} · Region: ${esc(detailJson.account?.region ?? '—')}</p>
          <div class="friendly-empty-actions">
            <button class="btn secondary" data-action="suspend-tenant" data-id="${esc(selectedTenantId)}">Suspend tenant</button>
            <button class="btn secondary" data-action="reactivate-tenant" data-id="${esc(selectedTenantId)}">Reactivate tenant</button>
          </div>
          <h4>Users</h4>
          <table><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>Support</th></tr></thead><tbody>${users}</tbody></table>
          <p id="tenantActionOut" class="muted"></p>
        </div>`;
    }
  }

  return `${detail}<div class="card"><table><thead><tr><th>Tenant</th><th>Name</th><th>Plan</th><th>Lifecycle</th><th>Users</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

async function renderApprovals() {
  const { status, json } = await staffApi('/internal/admin/approval-requests');
  if (status !== 200) {
    return `<div class="empty">Could not load approval queue (${status}).</div>`;
  }
  const rows = (json.items ?? []).map((r) => `
    <tr>
      <td>${esc(r.id)}</td><td>${esc(r.kind)}</td><td>${esc(r.state)}</td><td>${esc(r.tenant_id ?? '—')}</td>
    </tr>`).join('');
  return `<div class="card"><table><thead><tr><th>ID</th><th>Kind</th><th>State</th><th>Tenant</th></tr></thead><tbody>${rows || '<tr><td colspan="4" class="muted">No pending approval requests.</td></tr>'}</tbody></table></div>`;
}

async function renderAudit() {
  const { status, json } = await staffApi('/internal/admin/audit-log?limit=50');
  if (status !== 200) {
    return `<div class="empty">Could not load internal audit (${status}).</div>`;
  }
  const rows = (json.items ?? []).map((a) => `
    <tr>
      <td>${esc(a.created_at)}</td>
      <td>${esc(a.staff_id ?? '—')}</td>
      <td>${esc(a.action)}</td>
      <td>${esc(a.tenant_id ?? '—')}</td>
      <td>${esc(a.resource_type)}:${esc(a.resource_id ?? '—')}</td>
    </tr>`).join('');
  return `<div class="card"><table><thead><tr><th>Time</th><th>Staff</th><th>Action</th><th>Tenant</th><th>Resource</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

const ROUTE_TITLES = {
  overview: 'Internal overview',
  'signup-queue': 'Sign-up queue',
  tenants: 'Tenant management',
  approvals: 'Approval queue',
  audit: 'Internal audit',
};

async function render() {
  const view = el('staffView');
  el('staffPageTitle').textContent = ROUTE_TITLES[route] ?? 'Internal management';
  document.querySelectorAll('#staffNav a').forEach((a) => {
    a.classList.toggle('active', a.dataset.route === route);
  });
  try {
    if (route === 'overview') view.innerHTML = await renderOverview();
    else if (route === 'signup-queue') view.innerHTML = await renderSignupQueue();
    else if (route === 'tenants') view.innerHTML = await renderTenants();
    else if (route === 'approvals') view.innerHTML = await renderApprovals();
    else if (route === 'audit') view.innerHTML = await renderAudit();
    bindStaffHandlers();
  } catch (err) {
    view.innerHTML = `<div class="empty">Render error: ${esc(err.message)}</div>`;
  }
}

function bindStaffHandlers() {
  document.querySelectorAll('[data-action="select-signup"]').forEach((btn) => {
    btn.onclick = () => {
      selectedSignupId = btn.dataset.id;
      render();
    };
  });
  document.querySelectorAll('[data-action="select-tenant"]').forEach((btn) => {
    btn.onclick = () => {
      selectedTenantId = btn.dataset.id;
      render();
    };
  });
  document.querySelectorAll('[data-action="approve-signup"]').forEach((btn) => {
    btn.onclick = async () => {
      const result = await staffApi(`/internal/admin/signup-requests/${btn.dataset.id}/approve`, {
        method: 'POST',
        body: JSON.stringify({ reason: 'Approved during staff review' }),
      });
      const out = el('signupActionOut');
      if (out) {
        out.textContent = result.status === 200
          ? `Provisioned tenant ${result.json?.provisioning?.tenant_id ?? result.json?.request?.provisioned_tenant_id ?? ''}`
          : `Action failed (${result.status})`;
      }
      render();
    };
  });
  document.querySelectorAll('[data-action="reject-signup"]').forEach((btn) => {
    btn.onclick = async () => {
      const reason = window.prompt('Staff rejection reason (customer-safe copy will be derived):', 'Unable to verify organization.');
      if (!reason) return;
      await staffApi(`/internal/admin/signup-requests/${btn.dataset.id}/reject`, {
        method: 'POST',
        body: JSON.stringify({ reason }),
      });
      render();
    };
  });
  document.querySelectorAll('[data-action="suspend-tenant"]').forEach((btn) => {
    btn.onclick = async () => {
      await staffApi(`/internal/admin/tenants/${btn.dataset.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ lifecycle_state: 'suspended', reason: 'Staff suspension' }),
      });
      render();
    };
  });
  document.querySelectorAll('[data-action="reactivate-tenant"]').forEach((btn) => {
    btn.onclick = async () => {
      await staffApi(`/internal/admin/tenants/${btn.dataset.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ lifecycle_state: 'active', reason: 'Staff reactivation' }),
      });
      render();
    };
  });
  document.querySelectorAll('[data-action="resend-invite"]').forEach((btn) => {
    btn.onclick = async () => {
      await staffApi(
        `/internal/admin/tenants/${btn.dataset.tenant}/users/${btn.dataset.user}/resend-invite`,
        { method: 'POST', body: '{}' },
      );
      render();
    };
  });
  document.querySelectorAll('[data-action="disable-user"]').forEach((btn) => {
    btn.onclick = async () => {
      await staffApi(
        `/internal/admin/tenants/${btn.dataset.tenant}/users/${btn.dataset.user}/disable`,
        { method: 'POST', body: JSON.stringify({ reason: 'Staff disable' }) },
      );
      render();
    };
  });
}

document.querySelectorAll('#staffNav a').forEach((a) => {
  a.onclick = (event) => {
    event.preventDefault();
    route = a.dataset.route;
    location.hash = route;
    render();
  };
});

el('staffId').onchange = () => render();
el('staffRole').onchange = () => render();

window.addEventListener('hashchange', () => {
  route = location.hash.replace('#', '') || 'overview';
  render();
});

route = location.hash.replace('#', '') || 'overview';
render();