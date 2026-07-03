import { createHash, createHmac } from 'node:crypto';

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function hmac(key, value, encoding = 'hex') {
  return createHmac('sha256', key).update(value, 'utf8').digest(encoding);
}

function toAmzDate(date) {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

function getSignatureKey(secretAccessKey, dateStamp, region, service) {
  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp, undefined);
  const kRegion = hmac(kDate, region, undefined);
  const kService = hmac(kRegion, service, undefined);
  return hmac(kService, 'aws4_request', undefined);
}

/**
 * Minimal AWS SigV4 signer for JSON 1.1 service calls via fetch.
 */
export function signAwsJsonRequest({
  method = 'POST',
  host,
  path = '/',
  region,
  service,
  body,
  credentials,
  amzTarget,
  now = new Date(),
}) {
  const amzDate = toAmzDate(now);
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(body ?? '');
  const canonicalHeaders = [
    `content-type:application/x-amz-json-1.1`,
    `host:${host}`,
    `x-amz-date:${amzDate}`,
    `x-amz-target:${amzTarget}`,
    ...(credentials.session_token ? [`x-amz-security-token:${credentials.session_token}`] : []),
  ].join('\n');
  const signedHeaders = credentials.session_token
    ? 'content-type;host;x-amz-date;x-amz-target;x-amz-security-token'
    : 'content-type;host;x-amz-date;x-amz-target';
  const canonicalRequest = [
    method,
    path,
    '',
    `${canonicalHeaders}\n`,
    signedHeaders,
    payloadHash,
  ].join('\n');
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');
  const signingKey = getSignatureKey(credentials.secret_access_key, dateStamp, region, service);
  const signature = hmac(signingKey, stringToSign);
  const authorization = [
    'AWS4-HMAC-SHA256',
    `Credential=${credentials.access_key_id}/${credentialScope},`,
    `SignedHeaders=${signedHeaders},`,
    `Signature=${signature}`,
  ].join(' ');

  return {
    'content-type': 'application/x-amz-json-1.1',
    host,
    'x-amz-date': amzDate,
    'x-amz-target': amzTarget,
    authorization,
    ...(credentials.session_token ? { 'x-amz-security-token': credentials.session_token } : {}),
  };
}