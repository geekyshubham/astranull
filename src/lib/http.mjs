import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const WEB_ROOT = path.join(__dirname, '../../apps/web');

export class HttpBodyError extends Error {
  constructor(code, status) {
    super(code);
    this.name = 'HttpBodyError';
    this.code = code;
    this.status = status;
  }
}

export function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

export function text(res, status, body, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType });
  res.end(body);
}

export async function readBodyText(req, maxBytes) {
  if (!Number.isInteger(maxBytes) || maxBytes < 1) {
    throw new Error('readBodyText requires a positive integer maxBytes');
  }
  const chunks = [];
  let total = 0;
  let tooLarge = false;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) tooLarge = true;
    else chunks.push(chunk);
  }
  if (tooLarge) {
    throw new HttpBodyError('payload_too_large', 413);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export async function readJsonBody(req, maxBytes) {
  const raw = await readBodyText(req, maxBytes);
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpBodyError('invalid_json', 400);
  }
}

export function parseUrl(req) {
  const host = req.headers.host ?? 'localhost';
  return new URL(req.url ?? '/', `http://${host}`);
}

const STATIC_ROUTE_ALIASES = {
  '/': '/landing.html',
  '/app': '/index.html',
  '/login': '/login.html',
  '/signup': '/signup.html',
  '/internal/admin': '/internal/admin/index.html',
  '/internal/admin/login': '/staff-login.html',
};

export async function serveStatic(req, res, url) {
  let rel = decodeURIComponent(url.pathname);
  if (STATIC_ROUTE_ALIASES[rel]) {
    rel = STATIC_ROUTE_ALIASES[rel];
  } else if (rel === '/app/') {
    rel = '/index.html';
  }
  if (rel === '/favicon.ico') {
    res.writeHead(204);
    res.end();
    return true;
  }
  if (rel.includes('..')) {
    text(res, 403, 'Forbidden');
    return true;
  }
  const filePath = path.join(WEB_ROOT, rel);
  if (!filePath.startsWith(WEB_ROOT)) {
    text(res, 403, 'Forbidden');
    return true;
  }
  try {
    const data = await readFile(filePath);
    const ext = path.extname(filePath);
    const types = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.svg': 'image/svg+xml',
      '.json': 'application/json',
    };
    res.writeHead(200, { 'Content-Type': types[ext] ?? 'application/octet-stream' });
    res.end(data);
    return true;
  } catch {
    return false;
  }
}