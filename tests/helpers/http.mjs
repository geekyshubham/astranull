export async function request(baseUrl, method, path, { headers = {}, body, rawBody } = {}) {
  let payload;
  if (rawBody !== undefined) {
    payload = rawBody;
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
  }
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      ...(payload !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...headers,
    },
    body: payload,
    signal: AbortSignal.timeout(Number(process.env.ASTRANULL_TEST_HTTP_TIMEOUT_MS ?? 30_000)),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return {
    status: res.status,
    json,
    text,
    headers: Object.fromEntries(res.headers.entries()),
  };
}

export function demoHeaders(role = 'admin', tenant = 'ten_demo', user = 'usr_admin') {
  return {
    'x-tenant-id': tenant,
    'x-user-id': user,
    'x-role': role,
  };
}

export function signedSessionHeaders(
  role = 'admin',
  tenant = 'ten_demo',
  user = 'usr_admin',
  secret,
  mintFn,
) {
  const token = mintFn(
    { tenantId: tenant, userId: user, role },
    secret,
  );
  return { Authorization: `Bearer ${token}` };
}

export function staffHeaders(role = 'internal_admin', staffId = 'staff_admin') {
  return {
    'x-principal-type': 'staff',
    'x-staff-id': staffId,
    'x-staff-role': role,
  };
}

export function agentHeaders(credential, tenant = 'ten_demo') {
  return {
    'x-tenant-id': tenant,
    'x-user-id': 'agent',
    Authorization: `Bearer ${credential}`,
  };
}