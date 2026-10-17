const crypto = require('crypto');
const U = process.env.SUPABASE_URL;
const K = process.env.SUPABASE_SERVICE_KEY;
const PUB = 'sb_publishable_L1joup6cLTwCnb6M4Zxlrg_W7nSJBdi';
const H = K && K.startsWith('eyJ')
  ? { apikey: K, Authorization: 'Bearer ' + K, 'Content-Type': 'application/json' }
  : { apikey: K, 'Content-Type': 'application/json' };
const res = (s, o) => ({ statusCode: s, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(o) });
const rnd = (n, chars) => Array.from(crypto.randomBytes(n), b => chars[b % chars.length]).join('');
const WORDS = ['VORTEX', 'SHADOW', 'SPECTRE', 'CIPHER', 'ONYX', 'ZENITH', 'CROWN', 'VAULT', 'NOVA', 'PULSE'];

exports.handler = async (ev) => {
  if (ev.httpMethod !== 'POST') return res(405, { error: 'POST only' });
  if (!U || !K) return res(500, { error: 'Server is not configured (missing Netlify environment variables).' });

  // 1. Who is calling?
  const token = (ev.headers.authorization || '').replace('Bearer ', '');
  const caller = await fetch(U + '/auth/v1/user', { headers: { apikey: PUB, Authorization: 'Bearer ' + token } })
    .then(r => (r.ok ? r.json() : null)).catch(() => null);
  if (!caller) return res(401, { error: 'Not signed in.' });

  // 2. Are they an active admin?
  const rows = await fetch(`${U}/rest/v1/profiles?id=eq.${caller.id}&select=role,status`, { headers: H }).then(r => r.json());
  const p = Array.isArray(rows) ? rows[0] : null;
  if (!p || p.role !== 'admin' || p.status !== 'active') return res(403, { error: 'Admin only.' });

  let b;
  try { b = JSON.parse(ev.body || '{}'); } catch { return res(400, { error: 'Bad request.' }); }
  const uuid = /^[0-9a-f-]{36}$/i;

  if (b.action === 'create') {
    const alias = String(b.alias || '').trim().slice(0, 60);
    if (!alias) return res(400, { error: 'Name is required.' });
    const code = `WSP-${1000 + (crypto.randomBytes(2).readUInt16BE() % 9000)}-${WORDS[crypto.randomBytes(1)[0] % WORDS.length]}`;
    const password = rnd(10, 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789');
    const a = await fetch(U + '/auth/v1/admin/users', { method: 'POST', headers: H,
      body: JSON.stringify({ email: code.toLowerCase() + '@whisper.local', password, email_confirm: true }) });
    const user = await a.json();
    if (!a.ok) return res(400, { error: user.msg || user.message || 'Could not create account.' });
    const pr = await fetch(U + '/rest/v1/profiles', { method: 'POST', headers: H,
      body: JSON.stringify({ id: user.id, whisper_code: code, alias, bio: String(b.bio || '').slice(0, 120), role: 'client', status: 'active' }) });
    if (!pr.ok) {
      await fetch(`${U}/auth/v1/admin/users/${user.id}`, { method: 'DELETE', headers: H });
      return res(400, { error: 'Could not save profile. Please try again.' });
    }
    return res(200, { code, password });
  }

  if (!uuid.test(b.id || '') || b.id === caller.id) return res(400, { error: 'Invalid client.' });

  if (b.action === 'status') {
    if (!['active', 'paused'].includes(b.status)) return res(400, { error: 'Invalid status.' });
    await fetch(`${U}/rest/v1/profiles?id=eq.${b.id}&role=eq.client`, { method: 'PATCH', headers: H, body: JSON.stringify({ status: b.status }) });
    await fetch(`${U}/auth/v1/admin/users/${b.id}`, { method: 'PUT', headers: H,
      body: JSON.stringify({ ban_duration: b.status === 'paused' ? '876000h' : 'none' }) });
    return res(200, { ok: true });
  }

  if (b.action === 'delete') {
    await fetch(`${U}/auth/v1/admin/users/${b.id}`, { method: 'DELETE', headers: H });
    return res(200, { ok: true });
  }

  return res(400, { error: 'Unknown action.' });
};
