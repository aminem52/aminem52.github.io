window.WhisperChat = (function () {
  const S = { tab: 'chats', open: null, contacts: [], msgs: [], cache: {}, shown: false, subs: [], timers: {} };
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = u => btoa(String.fromCharCode(...new Uint8Array(u)));
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
  const save = () => Promise.all([kv.set(S.me.id + ':contacts', S.contacts), kv.set(S.me.id + ':msgs', S.msgs), kv.set(S.me.id + ':timers', S.timers)]);

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

  async function send(peer, text, opts = {}) {
    const k = await shared(peer.id);
    const ts = Date.now();
    const m = { id: uid(), peer: peer.id, mine: true, t: text, ts, st: 's', rp: opts.rp, exp: opts.ex ? ts + opts.ex : undefined };
    const { error } = await S.sb.from('relay_messages').insert({
      sender_id: S.me.id, recipient_id: peer.id, conv_id: [S.me.id, peer.id].sort().join('_'),
      ciphertext: await seal(k, { id: m.id, t: text, ts, rp: opts.rp, ex: opts.ex }),
    });
    if (error) throw new Error('Could not send. Check your connection.');
    S.msgs.push(m); await save(); render();
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
  const receipt = (peerId, ids, st) => evt(peerId, { k: 'r', ids, s: st });
  async function ingest(row) {
    try {
      const o = await unseal(await shared(row.sender_id), row.ciphertext);
      if (o.k === 'r') {
        const rank = { s: 1, d: 2, r: 3 };
        (o.ids || []).forEach(id => { const m = S.msgs.find(x => x.id === id && x.mine); if (m && (rank[o.s] || 0) > (rank[m.st] || 1)) m.st = o.s; });
      } else if (o.k === 'x') {
        const m = S.msgs.find(x => x.id === o.id && x.peer === row.sender_id);
        if (m) { m.rx = { ...(m.rx || {}) }; if (o.e) m.rx.them = o.e; else delete m.rx.them; }
      } else if (o.k === 't') {
        S.timers[row.sender_id] = o.ms || 0;
      } else {
        if (!S.msgs.some(x => x.id === o.id)) S.msgs.push({ id: o.id, peer: row.sender_id, mine: false, t: o.t, ts: o.ts, unread: true, rp: o.rp, exp: o.ex ? Date.now() + o.ex : undefined });
        await ensureContact(row.sender_id);
        receipt(row.sender_id, [o.id], 'd');
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
      S.pv = setInterval(() => { const n = Date.now(), c = S.msgs.length; S.msgs = S.msgs.filter(m => !m.exp || m.exp > n); if (S.msgs.length !== c) { save(); render(); } }, 1000);
      document.addEventListener('visibilitychange', S.vis = () => { if (!document.hidden) pull(); });
      pull();
      render();
    },
    stop() {
      clearInterval(S.iv); clearInterval(S.pv);
      if (S.vis) document.removeEventListener('visibilitychange', S.vis);
      if (S.sb) S.sb.removeAllChannels();
    },
    getState() { return { contacts: S.contacts, msgs: S.msgs, timers: S.timers }; },
    subscribe(f) { S.subs.push(f); return () => { S.subs = S.subs.filter(x => x !== f); }; },
    async sendTo(id, text, opts) { const p = S.contacts.find(c => c.id === id); if (!p) throw new Error('Unknown client.'); await send(p, text, opts); },
    react(peerId, msgId, emoji) {
      const m = S.msgs.find(x => x.id === msgId); if (!m) return;
      m.rx = { ...(m.rx || {}) }; if (emoji) m.rx.me = emoji; else delete m.rx.me;
      save(); render(); evt(peerId, { k: 'x', id: msgId, e: emoji || '' });
    },
    deleteMsg(msgId) { S.msgs = S.msgs.filter(m => m.id !== msgId); save(); render(); },
    setTimer(peerId, ms) { S.timers[peerId] = ms; save(); render(); evt(peerId, { k: 't', ms }); },
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
      if (ids.length) { S.msgs.forEach(m => { if (ids.includes(m.id)) m.rs = true; }); receipt(id, ids, 'r'); ch = true; }
      if (ch) { save(); render(); }
    },
    show(tab, el) { S.tab = tab; S.el = el; S.shown = true; full(); },
    hide() { S.shown = false; },
  };
})();
