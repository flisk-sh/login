import { beforeAll, describe, expect, test } from 'bun:test';
import { allowedReturn, handle } from '../src/index.js';
import { makeKeys, signToken, TOKEN_SECONDS, verifyToken } from '../src/token.js';

let keys, env;
beforeAll(async () => {
  keys = await makeKeys();
  env = { PUBLIC_ORIGIN: 'https://login.flisk.si', GITHUB_CLIENT_ID: 'cid', GITHUB_CLIENT_SECRET: 'sec', STATE_SECRET: 's3', SIGNING_KEY: keys.signingKey, PUBLIC_KEY: keys.publicKey };
});
const github = (login, seen = []) => async (u, init) => {
  seen.push(String(u));
  if (String(u).includes('access_token')) return Response.json({ access_token: 'gho_SECRET' });
  return Response.json({ login, id: 4242 });
};
const get = (path, env2 = env, deps = {}, cookie = '') => handle(new Request('https://login.flisk.si' + path, { headers: cookie ? { cookie } : {} }), env2, deps);
// Runs /start then /callback the way a browser does.
async function signIn(returnTo, login = 'odykyi', deps = {}) {
  const s = await get('/start?return=' + encodeURIComponent(returnTo));
  const state = new URL(s.headers.get('location')).searchParams.get('state');
  const cookie = s.headers.get('set-cookie').split(';')[0];
  return get(`/callback?code=c&state=${state}`, env, { fetch: github(login), ...deps }, cookie);
}

describe('where a visitor may be sent back', () => {
  test.each([
    'https://grow.flisk.si/auth/done', 'https://chat.flisk.si/', 'https://learn.flisk.si/x?y=1',
  ])('allows %s', (u) => expect(allowedReturn(u)?.href).toBe(new URL(u).href));
  test.each([
    'https://evil.com/', 'https://flisk.si.evil.com/', 'https://evil.com/?https://grow.flisk.si', 'http://grow.flisk.si/',
    'https://pages.flisk.si/@x/y', 'https://user:pw@grow.flisk.si/', 'https://grow.flisk.si:8443/', 'javascript:alert(1)', '', 'https://flisk.si/', 'http://localhost:3000/',
  ])('refuses %s', (u) => expect(allowedReturn(u)).toBeNull());
  test('localhost only when dev mode is on', () => {
    expect(allowedReturn('http://localhost:3000/a', { ALLOW_LOCAL: '1' })?.origin).toBe('http://localhost:3000');
    expect(allowedReturn('http://evil.com/', { ALLOW_LOCAL: '1' })).toBeNull();
  });
});

describe('sign-in flow', () => {
  test('/start sends the visitor to GitHub with a state and our one callback', async () => {
    const r = await get('/start?return=' + encodeURIComponent('https://grow.flisk.si/auth/done'));
    const g = new URL(r.headers.get('location'));
    expect(g.origin + g.pathname).toBe('https://github.com/login/oauth/authorize');
    expect(g.searchParams.get('redirect_uri')).toBe('https://login.flisk.si/callback');
    expect(g.searchParams.get('scope')).toBeNull();
    expect(r.headers.get('set-cookie')).toContain('HttpOnly');
  });
  test('/start refuses a stranger as return address and when login is not set up', async () => {
    expect((await get('/start?return=https://evil.com/')).status).toBe(400);
    expect((await get('/start?return=https://grow.flisk.si/', { ...env, GITHUB_CLIENT_ID: '' })).status).toBe(400);
  });
  test('a good sign-in comes back to the site with a token for that site only', async () => {
    const r = await signIn('https://grow.flisk.si/auth/done?next=%2Fme');
    expect(r.status).toBe(302);
    const to = new URL(r.headers.get('location'));
    expect(to.origin + to.pathname).toBe('https://grow.flisk.si/auth/done');
    expect(to.searchParams.get('next')).toBe('/me');
    const token = to.searchParams.get('flisk_token');
    expect(await verifyToken(token, keys.publicKey, 'https://grow.flisk.si')).toEqual({ login: 'odykyi', id: 4242 });
    expect(await verifyToken(token, keys.publicKey, 'https://chat.flisk.si')).toBeNull();
  });
  test('the GitHub token never leaves the Worker', async () => {
    const r = await signIn('https://grow.flisk.si/auth/done');
    expect(r.headers.get('location')).not.toContain('gho_SECRET');
    expect(JSON.stringify([...r.headers])).not.toContain('gho_SECRET');
    expect(r.headers.get('referrer-policy')).toBe('no-referrer');
  });
  test('wrong state, missing cookie or a forged cookie is refused', async () => {
    const s = await get('/start?return=' + encodeURIComponent('https://grow.flisk.si/'));
    const cookie = s.headers.get('set-cookie').split(';')[0];
    expect((await get('/callback?code=c&state=wrong', env, { fetch: github('x') }, cookie)).status).toBe(400);
    expect((await get('/callback?code=c&state=wrong', env, { fetch: github('x') })).status).toBe(400);
    const forged = cookie.replace(/encodeURIComponent|https%3A%2F%2Fgrow/, 'https%3A%2F%2Fevil');
    expect((await get('/callback?code=c&state=x', env, { fetch: github('x') }, forged)).status).toBe(400);
  });
  test('GitHub refusing the code, or a strange name, gives no token', async () => {
    const s = await get('/start?return=' + encodeURIComponent('https://grow.flisk.si/'));
    const state = new URL(s.headers.get('location')).searchParams.get('state');
    const cookie = s.headers.get('set-cookie').split(';')[0];
    expect((await get(`/callback?code=c&state=${state}`, env, { fetch: async () => Response.json({ error: 'bad_code' }) }, cookie)).status).toBe(400);
    expect((await signIn('https://grow.flisk.si/', 'a b<script>')).status).toBe(400);
  });
  test('the public key is published at /key', async () => {
    expect(await (await get('/key')).text()).toBe(keys.publicKey);
  });
  test('/key is cacheable, while every sign-in route stays no-store', async () => {
    const key = await get('/key');
    const cache = key.headers.get('cache-control');
    expect(cache).toContain('public');
    expect(Number(/max-age=(\d+)/.exec(cache)[1])).toBeGreaterThanOrEqual(300);
    expect(await key.text()).toBe(keys.publicKey);
    for (const path of ['/', '/start?return=https://grow.flisk.si/', '/callback?code=c&state=x', '/start?return=https://evil.com/']) {
      expect((await get(path)).headers.get('cache-control')).toBe('no-store');
    }
  });
  test('the landing and error pages declare a language and a viewport', async () => {
    for (const r of [await get('/'), await get('/start?return=https://evil.com/')]) {
      const html = await r.text();
      expect(html).toContain('lang="en"');
      expect(html).toContain('name="viewport"');
    }
  });
});

describe('tokens', () => {
  test('expire after a minute', async () => {
    const t = await signToken(keys.signingKey, { login: 'a', id: 1, aud: 'https://grow.flisk.si' }, 1_000_000);
    expect(await verifyToken(t, keys.publicKey, 'https://grow.flisk.si', 1_000_000 + (TOKEN_SECONDS - 1) * 1000)).toEqual({ login: 'a', id: 1 });
    expect(await verifyToken(t, keys.publicKey, 'https://grow.flisk.si', 1_000_000 + (TOKEN_SECONDS + 1) * 1000)).toBeNull();
  });
  test('a changed name, a swapped key or junk is refused', async () => {
    const t = await signToken(keys.signingKey, { login: 'a', id: 1, aud: 'https://grow.flisk.si' });
    const [p, s] = t.split('.');
    const evil = btoa(JSON.stringify({ login: 'admin', aud: 'https://grow.flisk.si', exp: 9e9 })).replace(/=+$/, '');
    expect(await verifyToken(`${evil}.${s}`, keys.publicKey, 'https://grow.flisk.si')).toBeNull();
    expect(await verifyToken(t, (await makeKeys()).publicKey, 'https://grow.flisk.si')).toBeNull();
    for (const junk of ['', 'a', 'a.b', '...', undefined]) expect(await verifyToken(junk, keys.publicKey, 'https://grow.flisk.si')).toBeNull();
  });
});
