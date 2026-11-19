import { signToken } from './token.js';

const enc = new TextEncoder();
const COOKIE = 'login_state';
const ok = (body, status = 200, type = 'text/html; charset=utf-8', cache = 'no-store') => new Response(body, { status, headers: { 'content-type': type, 'cache-control': cache, 'x-robots-tag': 'noindex' } });
// The tab icon travels inline so the Worker needs no static assets; /favicon.ico answers with the same drawing for the
// browsers and crawlers that ask for it by name.
const ICON_SVG = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' fill='#0b0b0d'/><path d='M12 8H8v16h4M14 16h10m-4-4 4 4-4 4' fill='none' stroke='#22c55e' stroke-width='3.5'/></svg>";
const ICON = `data:image/svg+xml,${ICON_SVG.replace(/</g, '%3C').replace(/>/g, '%3E').replace(/#/g, '%23')}`;
// The sign-in pages carry redirects and state, so they are never stored; /key is a public value that only changes when the
// signing key is rotated, so a site may reuse it for a few minutes instead of asking the Worker on every check.
const PAGE = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="${ICON}">`;

// Which pages may a visitor be sent back to: https on a flisk.si site. pages.flisk.si is left out on purpose, because
// visitors publish their own pages there. Local dev (http://localhost) only when ALLOW_LOCAL=1.
const NEVER = new Set(['pages.flisk.si']);
export function allowedReturn(value, env = {}) {
  let u;
  try { u = new URL(String(value)); } catch { return null; }
  if (u.username || u.password) return null;
  const local = env.ALLOW_LOCAL === '1' && u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
  const flisk = u.protocol === 'https:' && /^([a-z0-9-]+\.)+flisk\.si$/.test(u.hostname) && !NEVER.has(u.hostname) && !u.port;
  return local || flisk ? u : null;
}

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const cookieOf = (req) => new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`).exec(req.headers.get('cookie') || '')?.[1] || '';
const stateCookie = (value, age) => `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
const rand = () => [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
const fail = (why) => ok(`${PAGE}<title>Sign-in failed</title><p>Sign-in did not work: ${why}. Go back to the site and try again.</p>`, 400);

export async function handle(req, env, deps = {}) {
  const fetchImpl = deps.fetch || fetch;
  const now = deps.now ?? Date.now();
  const url = new URL(req.url);

  if (url.pathname === '/key') return ok(env.PUBLIC_KEY || '', 200, 'text/plain', 'public, max-age=300');
  if (url.pathname === '/') {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return new Response('Method Not Allowed', {
        status: 405,
        headers: {
          'Allow': 'GET, HEAD',
          'Content-Type': 'text/plain; charset=utf-8',
        },
      });
    }

    return ok(`${PAGE}<title>Flisk Login</title><p>One sign-in for every Flisk site. Open a Flisk site and press Sign in.</p>`);
  }
  if (url.pathname === '/favicon.ico') return ok(ICON_SVG, 200, 'image/svg+xml', 'public, max-age=86400');

  if (url.pathname === '/start') {
    const back = allowedReturn(url.searchParams.get('return'), env);
    if (!back) return fail('that return address is not a Flisk site');
    if (!env.GITHUB_CLIENT_ID || !env.STATE_SECRET) return fail('login is not set up yet');
    const state = rand();
    const body = `${state}.${encodeURIComponent(back.href)}`;
    const g = new URL('https://github.com/login/oauth/authorize');
    g.searchParams.set('client_id', env.GITHUB_CLIENT_ID);
    g.searchParams.set('redirect_uri', `${env.PUBLIC_ORIGIN}/callback`);
    g.searchParams.set('state', state);
    return new Response(null, { status: 302, headers: { location: g.href, 'set-cookie': stateCookie(`${body}.${await hmac(env.STATE_SECRET, body)}`, 600), 'cache-control': 'no-store' } });
  }

  if (url.pathname === '/callback') {
    const raw = cookieOf(req);
    const at = raw.lastIndexOf('.');
    const body = raw.slice(0, at);
    if (!raw || !env.STATE_SECRET || (await hmac(env.STATE_SECRET, body)) !== raw.slice(at + 1)) return fail('the sign-in expired');
    const [state, enc2] = [body.slice(0, body.indexOf('.')), body.slice(body.indexOf('.') + 1)];
    const back = allowedReturn(decodeURIComponent(enc2), env);
    const code = url.searchParams.get('code');
    if (!back || !code || url.searchParams.get('state') !== state) return fail('the sign-in did not match');
    const tok = await fetchImpl('https://github.com/login/oauth/access_token', { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/json' }, body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code }) }).then((r) => r.json()).catch(() => null);
    if (!tok?.access_token) return fail('GitHub did not accept the code');
    const gh = await fetchImpl('https://api.github.com/user', { headers: { authorization: `Bearer ${tok.access_token}`, 'user-agent': 'flisk-login', accept: 'application/vnd.github+json' } }).then((r) => r.json()).catch(() => null);
    // The GitHub token is never stored and never sent on: only the name leaves this Worker.
    const login = gh?.login;
    if (!Number.isSafeInteger(gh?.id) || typeof login !== 'string' || !/^[A-Za-z0-9-]{1,39}$/.test(login)) return fail('GitHub did not say who you are');
    const token = await signToken(env.SIGNING_KEY, { login, id: gh.id, aud: back.origin }, now);
    const to = new URL(back.href);
    to.searchParams.set('flisk_token', token);
    return new Response(null, { status: 302, headers: { location: to.href, 'set-cookie': stateCookie('', 0), 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' } });
  }
  return ok('not found', 404, 'text/plain');
}

export default { fetch: (req, env, ctx) => handle(req, env) };
