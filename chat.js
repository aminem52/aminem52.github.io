window.WhisperChat = (function () {
  const S = { tab: 'chats', open: null, contacts: [], msgs: [], cache: {}, shown: false, subs: [], timers: {}, blocked: [], groups: [], calls: [] };
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = u => { const a = new Uint8Array(u); let t = ''; for (let i = 0; i < a.length; i += 8192) t += String.fromCharCode.apply(null, a.subarray(i, i + 8192)); return btoa(t); };
  const ub = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const q = s => S.el.querySelector(s);
  const uid = () => (crypto.randomUUID ? crypto.randomUUID() : ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)));

  // Local-only storage (IndexedDB): keys, contacts and messages never leave this device
  const dbp = new Promise((ok, no) => { const r = indexedDB.open('whisper-v2', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error); });
  const kv = {
    get: k => dbp.then(db => new Promise(ok => { const r = db.transaction('kv').objectStore('kv').get(k); r.onsuccess = () => ok(r.result); r.onerror = () => ok(null); })),
    set: (k, v) => dbp.then(db => new Promise(ok => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').put(v, k); t.oncomplete = ok; t.onerror = ok; })),
  };
  const save = () => Promise.all([kv.set(S.me.id + ':contacts', S.contacts), kv.set(S.me.id + ':msgs', S.msgs), kv.set(S.me.id + ':timers', S.timers), kv.set(S.me.id + ':blocked', S.blocked), kv.set(S.me.id + ':groups', S.groups), kv.set(S.me.id + ':calls', S.calls)]);

  // Identity key: private key is generated on this device and can never be exported
  async function ensureKeys() {
    let k = await kv.get(S.me.id + ':keys');
    if (!k) {
      const p = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey']);
      k = { priv: p.privateKey, pub: await crypto.subtle.exportKey('jwk', p.publicKey) };
      await kv.set(S.me.id + ':keys', k);
    }
    const pk = S.me.public_key;
    if (!pk || pk.x !== k.pub.x || pk.y !== k.pub.y) {
      await S.sb.from('profiles').update({ public_key: k.pub }).eq('id', S.me.id);
      S.me.public_key = k.pub;
    }
    return k;
  }
  async function shared(peerId) {
    if (S.cache[peerId]) return S.cache[peerId];
    const { data } = await S.sb.rpc('get_profiles', { p_ids: [peerId] });
    const p = data && data[0];
    if (!p || !p.public_key) throw new Error('This client has not opened Whisper yet, so they cannot receive encrypted messages.');
    const pub = await crypto.subtle.importKey('jwk', p.public_key, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    return (S.cache[peerId] = await crypto.subtle.deriveKey({ name: 'ECDH', public: pub }, S.keys.priv, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']));
  }
  async function seal(k, o) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    return b64(iv) + '.' + b64(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, enc.encode(JSON.stringify(o))));
  }
  async function unseal(k, s) {
    const [i, c] = s.split('.');
    return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub(i) }, k, ub(c))));
  }

  const addC = p => {
    const c = S.contacts.find(x => x.id === p.id);
    if (c) Object.assign(c, { alias: p.alias, bio: p.bio, whisper_code: p.whisper_code });
    else S.contacts.push({ id: p.id, whisper_code: p.whisper_code, alias: p.alias, bio: p.bio });
  };
  async function ensureContact(id) {
    if (S.contacts.some(c => c.id === id)) return;
    const { data } = await S.sb.rpc('get_profiles', { p_ids: [id] });
    if (data && data[0]) addC(data[0]);
  }

  const conv = id => S.contacts.find(c => c.id === id) || S.groups.find(g => g.id === id);
  const targetsOf = peer => (peer.members ? peer.members.filter(x => x !== S.me.id) : [peer.id]);
  async function keyed(ids) {
    const out = [];
    for (const id of ids) { try { out.push([id, await shared(id)]); } catch (e) { /* no key yet */ } }
    return out;
  }
  async function send(peer, text, opts = {}) {
    const ts = Date.now(), id = uid(), isG = !!peer.members;
    const ks = await keyed(targetsOf(peer));
    if (!ks.length) throw new Error(isG ? 'No group member can receive encrypted messages yet.' : 'This client has not opened Whisper yet, so they cannot receive encrypted messages.');
    const m = { id, peer: peer.id, mine: true, t: text, ts, st: 's', rp: opts.rp, fw: opts.fw, att: opts.att, exp: opts.ex ? ts + opts.ex : undefined };
    for (const [tid, k] of ks) {
      const att = opts.attFor ? opts.attFor(tid) : opts.att;
      const { error } = await S.sb.from('relay_messages').insert({
        sender_id: S.me.id, recipient_id: tid, conv_id: [S.me.id, tid].sort().join('_'),
        ciphertext: await seal(k, { id, t: text, ts, rp: opts.rp, ex: opts.ex, fw: opts.fw, att, gid: isG ? peer.id : undefined }),
      });
      if (error) throw new Error('Could not send. Check your connection.');
    }
    S.msgs.push(m);
    if (opts.localBlob) await kv.set(S.me.id + ':blob:' + m.id, opts.localBlob);
    await save(); render();
  }
  function fanout(id, obj) {
    const c = conv(id); if (!c) return;
    if (c.members) targetsOf(c).forEach(t => evt(t, { ...obj, gid: id })); else evt(id, obj);
  }
  async function evt(peerId, obj) {
    try {
      const k = await shared(peerId);
      await S.sb.from('relay_messages').insert({
        sender_id: S.me.id, recipient_id: peerId, conv_id: [S.me.id, peerId].sort().join('_'),
        ciphertext: await seal(k, obj),
      });
    } catch (e) { /* best effort */ }
  }
  const dropBlobs = list => list.forEach(m => { if (m.att) kv.set(S.me.id + ':blob:' + m.id, null); });
  const receipt = (peerId, ids, st) => evt(peerId, { k: 'r', ids, s: st });
  async function ingest(row) {
    if (S.blocked.includes(row.sender_id)) { await S.sb.from('relay_messages').delete().eq('id', row.id); return; }
    try {
      const o = await unseal(await shared(row.sender_id), row.ciphertext);
      if (o.k === 'r') {
        const rank = { s: 1, d: 2, r: 3 };
        (o.ids || []).forEach(id => { const m = S.msgs.find(x => x.id === id && x.mine); if (m && (rank[o.s] || 0) > (rank[m.st] || 1)) m.st = o.s; });
      } else if (o.k === 'x') {
        const m = S.msgs.find(x => x.id === o.id && (x.peer === row.sender_id || x.peer === o.gid));
        if (m) { m.rx = { ...(m.rx || {}) }; if (o.e) m.rx[row.sender_id] = o.e; else delete m.rx[row.sender_id]; }
      } else if (o.k === 't') {
        S.timers[o.gid || row.sender_id] = o.ms || 0;
      } else if (o.k === 'g') {
        let g = S.groups.find(x => x.id === o.gid);
        if (!g || g.owner === row.sender_id) {
          if (!g) { g = { id: o.gid }; S.groups.push(g); }
          Object.assign(g, { name: String(o.name || 'Group').slice(0, 60), members: o.members || [], owner: row.sender_id });
          for (const mid of g.members) if (mid !== S.me.id) await ensureContact(mid);
        }
      } else if (o.k === 'c') {
        if (S.onCall && o.ts && Math.abs(Date.now() - o.ts) < 60000) { await ensureContact(row.sender_id); S.onCall(row.sender_id, o); }
      } else if (o.k === 'gl') {
        const g = S.groups.find(x => x.id === o.gid);
        if (g) g.members = g.members.filter(x => x !== row.sender_id);
      } else {
        const gid = o.gid;
        if (gid && !S.groups.some(g => g.id === gid)) S.groups.push({ id: gid, name: 'Group', members: [row.sender_id, S.me.id], owner: row.sender_id });
        const g0 = gid && S.groups.find(g => g.id === gid);
        if (g0 && !g0.members.includes(row.sender_id)) { await S.sb.from('relay_messages').delete().eq('id', row.id); return; }
        if (!S.msgs.some(x => x.id === o.id)) S.msgs.push({ id: o.id, peer: gid || row.sender_id, from: gid ? row.sender_id : undefined, mine: false, t: o.t, ts: o.ts, unread: true, rp: o.rp, fw: o.fw, att: o.att, exp: o.ex ? Date.now() + o.ex : undefined });
        await ensureContact(row.sender_id);
        if (!gid) receipt(row.sender_id, [o.id], 'd');
      }
      await S.sb.from('relay_messages').delete().eq('id', row.id); // delivered: remove from server
    } catch (e) {
      if (e && e.name === 'OperationError') await S.sb.from('relay_messages').delete().eq('id', row.id); // undecryptable
    }
  }
  async function pull() {
    const { data } = await S.sb.from('relay_messages').select('*').eq('recipient_id', S.me.id).order('created_at');
    if (!data || !data.length) return;
    for (const r of data) await ingest(r);
    await save(); render();
  }

  // ---- UI ----
  const ini = c => esc((c.alias || '?').charAt(0));
  const lastOf = c => S.msgs.filter(m => m.peer === c.id).sort((a, b) => a.ts - b.ts).pop();
  const unread = () => S.msgs.filter(m => m.unread).length;
  const openChat = id => { S.open = id; S.msgs.forEach(m => { if (m.peer === id) m.unread = false; }); save(); window.goTab('chats'); };

  function render() {
    S.subs.forEach(f => f());
    if (!S.el) return;
    if (S.shown && S.tab === 'chats' && S.open && q('#msgs')) fillMsgs();
    else if (S.shown) full();
    if (S.onUpdate) S.onUpdate(unread());
  }
  function full() { if (S.tab === 'contacts') contactsView(); else if (S.open) chatView(); else listView(); }

  function listView() {
    const rows = S.contacts.map(c => ({ c, l: lastOf(c) })).filter(x => x.l).sort((a, b) => b.l.ts - a.l.ts);
    S.el.innerHTML = '<h2 style="margin:8px 0">Chats</h2>' + (rows.length ? rows.map(({ c, l }) => {
      const u = S.msgs.filter(m => m.peer === c.id && m.unread).length;
      return `<div class="card row" data-c="${c.id}" style="cursor:pointer"><div class="row" style="justify-content:flex-start;gap:12px"><div class="av">${ini(c)}</div><div><b>${esc(c.alias)}</b><div class="s">${esc(l.t.slice(0, 40))}</div></div></div>${u ? `<span class="bd">${u}</span>` : ''}</div>`;
    }).join('') : '<div class="card s">No chats yet. Open the Clients tab and tap Chat on someone.</div>');
    S.el.onclick = e => { const r = e.target.closest('[data-c]'); if (r) openChat(r.dataset.c); };
  }

  function chatView() {
    const c = S.contacts.find(x => x.id === S.open);
    if (!c) { S.open = null; return listView(); }
    S.el.innerHTML = `<div class="row" style="justify-content:flex-start;gap:10px;margin:6px 0"><button class="g" id="bk">&#8249;</button><b>${esc(c.alias)}</b><span class="s">&#128274; end-to-end encrypted</span></div>
      <div id="msgs"></div><form class="inp" id="f"><input id="t" placeholder="Encrypted message..." autocomplete="off" style="margin:0"><button>Send</button></form>`;
    S.el.onclick = null;
    fillMsgs();
    q('#bk').onclick = () => { S.open = null; render(); };
    q('#f').onsubmit = async e => {
      e.preventDefault();
      const inp = q('#t'), v = inp.value.trim(); if (!v) return;
      inp.value = '';
      try { await send(c, v); } catch (x) { inp.value = v; toast(x.message || 'Could not send.'); }
    };
  }
  function fillMsgs() {
    const b = q('#msgs'); if (!b) return;
    const list = S.msgs.filter(m => m.peer === S.open).sort((a, b) => a.ts - b.ts);
    b.innerHTML = list.map(m => `<div style="display:flex;justify-content:${m.mine ? 'flex-end' : 'flex-start'}"><div class="bub ${m.mine ? 'me' : ''}">${esc(m.t)}<div style="opacity:.6;font-size:10px;text-align:right">${new Date(m.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div></div></div>`).join('');
    S.msgs.forEach(m => { if (m.peer === S.open) m.unread = false; });
    document.getElementById('app').scrollTop = 1e9;
  }

  function contactsView() {
    S.el.innerHTML = `<h2 style="margin:8px 0">Clients</h2><form id="af" class="card"><label class="s">Add by Whisper-Code</label>
      <input id="ac" class="m" placeholder="WSP-0000-NAME" autocapitalize="characters"><button style="width:100%">Add &amp; chat</button></form>` +
      S.contacts.map(c => `<div class="card row"><div class="row" style="justify-content:flex-start;gap:12px"><div class="av">${ini(c)}</div><div><b>${esc(c.alias)}</b><div class="s m">${esc(c.whisper_code)}</div></div></div><button data-c="${c.id}">Chat</button></div>`).join('');
    S.el.onclick = e => { const b = e.target.closest('[data-c]'); if (b) openChat(b.dataset.c); };
    q('#af').onsubmit = async e => {
      e.preventDefault();
      const { data, error } = await S.sb.rpc('lookup_by_code', { p_code: q('#ac').value });
      const p = data && data[0];
      if (error || !p) return toast('Whisper-Code not found.');
      if (p.id === S.me.id) return toast('That is your own Whisper-Code.');
      addC(p); await save(); openChat(p.id);
    };
  }

  return {
    async start(sb, me, onUpdate) {
      this.stop();
      Object.assign(S, { sb, me, onUpdate, cache: {}, open: null });
      S.keys = await ensureKeys();
      S.contacts = (await kv.get(me.id + ':contacts')) || [];
      S.msgs = (await kv.get(me.id + ':msgs')) || [];
      S.timers = (await kv.get(me.id + ':timers')) || {};
      S.blocked = (await kv.get(me.id + ':blocked')) || [];
      S.groups = (await kv.get(me.id + ':groups')) || [];
      S.calls = (await kv.get(me.id + ':calls')) || [];
      if (me.role === 'admin') {
        const { data } = await sb.from('profiles').select('id,whisper_code,alias,bio').neq('id', me.id);
        (data || []).forEach(addC);
      } else {
        const { data } = await sb.rpc('lookup_by_code', { p_code: 'WSP-1842-ROOT' });
        if (data && data[0]) addC(data[0]);
      }
      await save();
      sb.channel('inbox').on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'relay_messages', filter: 'recipient_id=eq.' + me.id },
        async p => { await ingest(p.new); await save(); render(); }).subscribe();
      S.iv = setInterval(pull, 20000);
      S.pv = setInterval(() => { const n = Date.now(), c = S.msgs.length; dropBlobs(S.msgs.filter(m => m.exp && m.exp <= n)); S.msgs = S.msgs.filter(m => !m.exp || m.exp > n); if (S.msgs.length !== c) { save(); render(); } }, 1000);
      document.addEventListener('visibilitychange', S.vis = () => { if (!document.hidden) pull(); });
      pull();
      render();
    },
    stop() {
      clearInterval(S.iv); clearInterval(S.pv);
      if (S.vis) document.removeEventListener('visibilitychange', S.vis);
      if (S.sb) S.sb.removeAllChannels();
    },
    getState() { return { contacts: S.contacts, msgs: S.msgs, timers: S.timers, blocked: S.blocked, groups: S.groups, calls: S.calls }; },
    subscribe(f) { S.subs.push(f); return () => { S.subs = S.subs.filter(x => x !== f); }; },
    async sendTo(id, text, opts) { const p = conv(id); if (!p) throw new Error('Unknown client.'); if (!p.members && S.blocked.includes(id)) throw new Error('Unblock this client to send messages.'); await send(p, text, opts); },
    react(peerId, msgId, emoji) {
      const m = S.msgs.find(x => x.id === msgId); if (!m) return;
      m.rx = { ...(m.rx || {}) }; if (emoji) m.rx.me = emoji; else delete m.rx.me;
      save(); render(); fanout(peerId, { k: 'x', id: msgId, e: emoji || '' });
    },
    async sendMedia(peerId, blob, meta, opts = {}) {
      const peer = conv(peerId);
      if (!peer) throw new Error('Unknown client.');
      if (!peer.members && S.blocked.includes(peerId)) throw new Error('Unblock this client to send messages.');
      if (blob.size > 25 * 1024 * 1024) throw new Error('Files can be up to 25 MB.');
      const ks = await keyed(targetsOf(peer));
      if (!ks.length) throw new Error('Nobody here can receive encrypted messages yet.');
      const buf = await blob.arrayBuffer();
      const fk = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ctBlob = new Blob([await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fk, buf)], { type: 'application/octet-stream' });
      const paths = {};
      for (const [tid] of ks) {
        paths[tid] = tid + '/' + uid();
        const up = await S.sb.storage.from('relay-files').upload(paths[tid], ctBlob);
        if (up.error) throw new Error('Upload failed. Check your connection.');
      }
      const base = { k: b64(await crypto.subtle.exportKey('raw', fk)), iv: b64(iv), n: meta.name, s: blob.size, m: meta.mime, d: meta.dur, kind: meta.kind };
      const label = meta.kind === 'v' ? 'Voice message (' + meta.dur + 's)' : meta.name;
      await send(peer, label, { ...opts, att: base, attFor: tid => ({ ...base, p: paths[tid] }), localBlob: { buf, mime: meta.mime } });
    },
    onCall(fn) { S.onCall = fn; },
    me() { return S.me.id; },
    async ensureContacts(ids) { for (const id of ids) if (id !== S.me.id) await ensureContact(id); render(); },
    signal(peerId, obj) { return evt(peerId, { k: 'c', ts: Date.now(), ...obj }); },
    addCall(c) { S.calls.unshift(c); S.calls = S.calls.slice(0, 100); save(); render(); },
    async createGroup(name, ids) {
      const gid = uid();
      const g = { id: gid, name: name.slice(0, 60), members: [S.me.id, ...ids], owner: S.me.id };
      S.groups.push(g); await save(); render();
      ids.forEach(tid => evt(tid, { k: 'g', gid, name: g.name, members: g.members }));
      return gid;
    },
    addMembers(gid, ids) {
      const g = S.groups.find(x => x.id === gid); if (!g || g.owner !== S.me.id) return;
      g.members = Array.from(new Set([...g.members, ...ids]));
      save(); render();
      g.members.filter(x => x !== S.me.id).forEach(tid => evt(tid, { k: 'g', gid, name: g.name, members: g.members }));
    },
    leaveGroup(gid) {
      const g = S.groups.find(x => x.id === gid); if (!g) return;
      g.members.filter(x => x !== S.me.id).forEach(tid => evt(tid, { k: 'gl', gid }));
      dropBlobs(S.msgs.filter(m => m.peer === gid));
      S.msgs = S.msgs.filter(m => m.peer !== gid); S.groups = S.groups.filter(x => x.id !== gid);
      save(); render();
    },
    async getMedia(msgId) {
      const cached = await kv.get(S.me.id + ':blob:' + msgId);
      if (cached) return cached;
      const m = S.msgs.find(x => x.id === msgId);
      if (!m || !m.att || m.mine) throw new Error('This file is not available on this phone.');
      const dl = await S.sb.storage.from('relay-files').download(m.att.p);
      if (dl.error || !dl.data) throw new Error('This file is no longer available.');
      const key = await crypto.subtle.importKey('raw', ub(m.att.k), { name: 'AES-GCM' }, false, ['decrypt']);
      let buf;
      try { buf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub(m.att.iv) }, key, await dl.data.arrayBuffer()); }
      catch (e) { throw new Error('Could not decrypt this file.'); }
      const out = { buf, mime: m.att.m || 'application/octet-stream' };
      await kv.set(S.me.id + ':blob:' + msgId, out);
      S.sb.storage.from('relay-files').remove([m.att.p]); // delivered: remove from server
      return out;
    },
    toggleBlock(id) {
      const was = S.blocked.includes(id);
      S.blocked = was ? S.blocked.filter(x => x !== id) : [...S.blocked, id];
      save(); render(); return !was;
    },
    deleteChat(id) { dropBlobs(S.msgs.filter(m => m.peer === id)); S.msgs = S.msgs.filter(m => m.peer !== id); save(); render(); },
    wipe() { dropBlobs(S.msgs); S.msgs = []; save(); render(); },
    async safety(peerId) {
      const { data } = await S.sb.rpc('get_profiles', { p_ids: [peerId] });
      const p = data && data[0]; if (!p || !p.public_key) return '';
      const a = S.keys.pub, b = p.public_key;
      const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode([a.x + a.y, b.x + b.y].sort().join('|'))));
      return Array.from(h.slice(0, 10), x => String(x).padStart(3, '0')).join('').match(/.{1,5}/g).join(' ');
    },
    async exportBackup(pass) {
      const data = JSON.stringify({ v: 1, contacts: S.contacts, msgs: S.msgs, timers: S.timers, blocked: S.blocked, groups: S.groups });
      const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
      const km = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(data));
      return JSON.stringify({ app: 'whisper-backup', v: 1, salt: b64(salt), iv: b64(iv), data: b64(ct) });
    },
    async importBackup(text, pass) {
      let d;
      try {
        const f = JSON.parse(text);
        const km = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
        const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: ub(f.salt), iterations: 150000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
        d = JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub(f.iv) }, key, ub(f.data))));
      } catch (e) { throw new Error('Wrong password or invalid backup file.'); }
      let n = 0;
      (d.msgs || []).forEach(m => { if (!S.msgs.some(x => x.id === m.id)) { S.msgs.push(m); n++; } });
      (d.contacts || []).forEach(addC);
      (d.groups || []).forEach(g => { if (!S.groups.some(x => x.id === g.id)) S.groups.push(g); });
      Object.assign(S.timers, d.timers || {});
      S.blocked = Array.from(new Set([...S.blocked, ...(d.blocked || [])]));
      await save(); render(); return n;
    },
    deleteMsg(msgId) { dropBlobs(S.msgs.filter(m => m.id === msgId)); S.msgs = S.msgs.filter(m => m.id !== msgId); save(); render(); },
    setTimer(peerId, ms) { S.timers[peerId] = ms; save(); render(); fanout(peerId, { k: 't', ms }); },
    async addByCode(code) {
      const { data, error } = await S.sb.rpc('lookup_by_code', { p_code: code });
      const p = data && data[0];
      if (error || !p) throw new Error('Whisper-Code not found.');
      if (p.id === S.me.id) throw new Error('That is your own Whisper-Code.');
      addC(p); await save(); render(); return p;
    },
    markRead(id) {
      let ch = false;
      const ids = S.msgs.filter(m => m.peer === id && !m.mine && !m.rs).map(m => m.id);
      S.msgs.forEach(m => { if (m.peer === id && m.unread) { m.unread = false; ch = true; } });
      if (ids.length && !S.groups.some(g => g.id === id)) { S.msgs.forEach(m => { if (ids.includes(m.id)) m.rs = true; }); receipt(id, ids, 'r'); ch = true; }
      if (ch) { save(); render(); }
    },
    show(tab, el) { S.tab = tab; S.el = el; S.shown = true; full(); },
    hide() { S.shown = false; },
  };
})();
