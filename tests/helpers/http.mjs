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
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json, text };
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

export function agentHeaders(credential, tenant = 'ten_demo') {
  return {
    'x-tenant-id': tenant,
    'x-user-id': 'agent',
    Authorization: `Bearer ${credential}`,
  };
}