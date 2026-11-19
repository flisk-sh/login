import { beforeAll, expect, test } from 'bun:test';
import worker from '../src/index.js';
import { withSecurityHeaders } from '../src/security-headers.js';
import { makeKeys } from '../src/token.js';

const EXPECTED = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'SAMEORIGIN',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
};
const expectBaseline = (res, skip = []) => {
  for (const [k, v] of Object.entries(EXPECTED)) if (!skip.includes(k)) expect(res.headers.get(k)).toBe(v);
  expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'self'");
};

let env;
beforeAll(async () => {
  const keys = await makeKeys();
  env = { PUBLIC_ORIGIN: 'https://login.flisk.si', GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'sec', STATE_SECRET: 's3', SIGNING_KEY: keys.signingKey, PUBLIC_KEY: keys.publicKey };
});
const call = (path) => worker.fetch(new Request(`https://login.flisk.si${path}`), env);

test('every route carries the baseline headers', async () => {
  for (const path of ['/', '/key', '/llms.txt', '/favicon.ico', '/missing', '/start?return=https%3A%2F%2Fevil.example']) expectBaseline(await call(path));
});

test('the OAuth redirect still goes to GitHub, keeps its cookie and carries the headers', async () => {
  const res = await call('/start?return=' + encodeURIComponent('https://chat.flisk.si/'));
  expect(res.status).toBe(302);
  expect(new URL(res.headers.get('location')).origin).toBe('https://github.com');
  expect(res.headers.get('set-cookie')).toContain('login_state=');
  expect(res.headers.get('cache-control')).toBe('no-store');
  expectBaseline(res);
});

test('the callback keeps its own stricter no-referrer policy and the redirect back', async () => {
  const res = withSecurityHeaders(new Response(null, { status: 302, headers: { location: 'https://chat.flisk.si/?flisk_token=x', 'referrer-policy': 'no-referrer', 'set-cookie': 'login_state=; Max-Age=0' } }));
  expect(res.status).toBe(302);
  expect(res.headers.get('location')).toBe('https://chat.flisk.si/?flisk_token=x');
  expect(res.headers.get('referrer-policy')).toBe('no-referrer');
  expect(res.headers.get('set-cookie')).toBe('login_state=; Max-Age=0');
  expectBaseline(res, ['referrer-policy']);
});

test('a missing header is added, an existing one is kept and an existing CSP gets frame-ancestors', () => {
  const res = withSecurityHeaders(new Response('x', { headers: { 'x-frame-options': 'DENY', 'content-security-policy': "default-src 'none'" } }));
  expect(res.headers.get('x-frame-options')).toBe('DENY');
  expect(res.headers.get('content-security-policy')).toBe("default-src 'none'; frame-ancestors 'self'");
  const kept = withSecurityHeaders(new Response('x', { headers: { 'content-security-policy': "frame-ancestors 'none'" } }));
  expect(kept.headers.get('content-security-policy')).toBe("frame-ancestors 'none'");
});
