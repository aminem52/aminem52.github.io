window.WhisperCall = (function () {
  const ICE = { iceServers: [{ urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] }] };
  let eng = null, cb = () => {}, local = null, peers = {}, early = {}, greeted = {}, timer = null, ringT = null, ringI = null, actx = null;
  let st = { phase: 'idle' };
  const nm = id => (eng.getState().contacts.find(c => c.id === id) || {}).alias || 'Client';
  const parts = () => Object.keys(peers).map(id => ({ id, name: nm(id), stream: peers[id].remote, live: peers[id].live }));
  const emit = () => cb({ ...st, local, parts: parts() });
  const set = p => { st = { ...st, ...p }; emit(); };
  const sig = (to, o) => eng.signal(to, { ...o, cid: st.cid });
  const vc = (facing, low) => (low
    ? { facingMode: facing || 'user', width: { ideal: 320 }, height: { ideal: 240 }, frameRate: { ideal: 15, max: 20 } }
    : { facingMode: facing || 'user', width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { ideal: 24, max: 30 } });
  const media = (video, facing, low) => navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true }, video: video ? vc(facing, low) : false });
  async function cap() { // limit video bitrate per connection so several streams stay smooth
    const kbps = (st.members || []).length > 2 ? 220 : 700;
    for (const p of Object.values(peers)) for (const s of p.pc.getSenders()) {
      if (!s.track || s.track.kind !== 'video') continue;
      try { const prm = s.getParameters(); if (!prm.encodings || !prm.encodings.length) prm.encodings = [{}]; prm.encodings[0].maxBitrate = kbps * 1000; await s.setParameters(prm); } catch (e) { /* not supported */ }
    }
  }

  function ring(on) {
    clearInterval(ringI); ringI = null;
    if (!on) return;
    const beep = () => {
      try {
        actx = actx || new (window.AudioContext || window.webkitAudioContext)();
        if (actx.state === 'suspended') actx.resume();
        [440, 523].forEach((f, i) => {
          const o = actx.createOscillator(), g = actx.createGain(), t = actx.currentTime + i * 0.25;
          o.frequency.value = f; g.gain.value = 0.15; o.connect(g); g.connect(actx.destination); o.start(t); o.stop(t + 0.2);
        });
      } catch (e) { /* sound is optional */ }
    };
    beep(); ringI = setInterval(beep, 2000);
  }

  function mkPeer(id) {
    const p = (peers[id] = { pc: new RTCPeerConnection(ICE), remote: null, queued: early[st.cid + id] || [], live: false });
    delete early[st.cid + id];
    local.getTracks().forEach(t => p.pc.addTrack(t, local));
    p.pc.onicecandidate = e => { if (e.candidate) sig(id, { t: 'ice', c: e.candidate.toJSON() }); };
    p.pc.ontrack = e => { if (e.streams && e.streams[0]) p.remote = e.streams[0]; emit(); };
    p.pc.onconnectionstatechange = () => {
      const s = p.pc.connectionState;
      if (s === 'connected' && !p.live) {
        p.live = true; ring(false); cap();
        if (st.phase !== 'connected') {
          const t0 = Date.now(); clearInterval(timer);
          timer = setInterval(() => set({ dur: Math.floor((Date.now() - t0) / 1000) }), 1000);
          set({ phase: 'connected', dur: 0 });
        } else emit();
      }
      if (s === 'failed') drop(id, 'Connection failed');
    };
    return p;
  }
  async function flush(p) { for (const c of p.queued.splice(0)) { try { await p.pc.addIceCandidate(c); } catch (e) { /* ignore */ } } }

  async function offerTo(id, extra) {
    const p = mkPeer(id);
    const offer = await p.pc.createOffer(); await p.pc.setLocalDescription(offer);
    sig(id, { t: 'offer', sdp: offer.sdp, video: st.video, members: st.members, gid: st.gid, title: st.title, ...extra });
    if (!(extra && extra.join)) setTimeout(() => { if (peers[id] && !peers[id].live) { sig(id, { t: 'leave' }); drop(id, 'No answer'); } }, 45000);
  }
  async function answerOffer(from, sdp) {
    const p = mkPeer(from);
    await p.pc.setRemoteDescription({ type: 'offer', sdp });
    await flush(p);
    const ans = await p.pc.createAnswer(); await p.pc.setLocalDescription(ans);
    sig(from, { t: 'answer', sdp: ans.sdp });
  }

  function finish(msg, missed) {
    ring(false); clearTimeout(ringT); clearInterval(timer);
    const was = st;
    Object.values(peers).forEach(p => { try { p.pc.close(); } catch (e) { /* ignore */ } });
    peers = {}; early = {}; greeted = {};
    if (local) local.getTracks().forEach(t => t.stop());
    local = null;
    if (was.phase !== 'idle') eng.addCall({ id: was.cid + was.dir, peerId: was.from || (was.members || []).find(x => x !== eng.me()) || '', name: was.name, type: was.video ? 'video' : 'voice', dir: missed ? 'missed' : was.dir, ts: Date.now(), dur: was.dur || 0, gid: was.gid, members: was.members });
    st = { phase: 'idle', msg }; emit();
  }
  function drop(id, why) {
    const p = peers[id]; if (!p) return;
    try { p.pc.close(); } catch (e) { /* ignore */ }
    delete peers[id]; delete greeted[id];
    st = { ...st, members: (st.members || []).filter(x => x !== id) };
    if (!Object.keys(peers).length) finish(why || 'Call ended'); else emit();
  }

  async function start(targets, video, opts = {}) {
    if (st.phase !== 'idle' || !targets.length) return;
    try { local = await media(video, null, targets.length > 1); } catch (e) { throw new Error('Camera or microphone access was not allowed.'); }
    const title = opts.title || nm(targets[0]);
    st = { phase: 'calling', cid: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()), video, dir: 'out', name: title, title, gid: opts.gid, members: [eng.me(), ...targets], muted: false, camOff: false, facing: 'user', dur: 0 };
    emit(); ring(true);
    for (const id of targets) await offerTo(id);
  }
  async function invite(ids) {
    if (st.phase !== 'connected' && st.phase !== 'connecting') return;
    const add = ids.filter(id => !peers[id]);
    set({ members: Array.from(new Set([...st.members, ...add])) });
    for (const id of add) await offerTo(id);
  }
  async function accept() {
    if (st.phase !== 'ringing') return;
    ring(false); clearTimeout(ringT);
    try { local = await media(st.video, null, st.members.length > 2); } catch (e) { sig(st.from, { t: 'decline' }); finish('Camera or microphone access was not allowed.'); return; }
    const { from, offer, members } = st;
    set({ phase: 'connecting' });
    await answerOffer(from, offer);
    members.filter(m => m !== eng.me() && m !== from).forEach(m => { greeted[m] = true; sig(m, { t: 'hello' }); });
  }
  function decline() { sig(st.from, { t: 'decline' }); finish(''); }
  function end() { Object.keys(peers).forEach(id => sig(id, { t: 'leave' })); finish('Call ended'); }

  async function handle(from, o) {
    if (o.t === 'offer') {
      if (st.phase !== 'idle' && o.join && o.cid === st.cid && local) { if (!peers[from]) await answerOffer(from, o.sdp); return; }
      if (st.phase !== 'idle') { eng.signal(from, { t: 'busy', cid: o.cid }); return; }
      eng.ensureContacts(o.members || []);
      st = { phase: 'ringing', cid: o.cid, from, offer: o.sdp, video: !!o.video, dir: 'in', name: o.title || nm(from), title: o.title, gid: o.gid, members: o.members || [from], muted: false, camOff: false, facing: 'user', dur: 0 };
      early[o.cid + from] = early[o.cid + from] || [];
      emit(); ring(true);
      ringT = setTimeout(() => finish('Missed call', true), 45000);
      return;
    }
    if (st.phase === 'idle' || o.cid !== st.cid) { if (o.t === 'ice') (early[o.cid + from] = early[o.cid + from] || []).push(o.c); return; }
    const p = peers[from];
    if (o.t === 'ice') {
      if (p && p.pc.remoteDescription) { try { await p.pc.addIceCandidate(o.c); } catch (e) { /* ignore */ } }
      else if (p) p.queued.push(o.c); else (early[o.cid + from] = early[o.cid + from] || []).push(o.c);
    } else if (o.t === 'answer' && p) {
      await p.pc.setRemoteDescription({ type: 'answer', sdp: o.sdp }); await flush(p);
      ring(false); if (st.phase === 'calling') set({ phase: 'connecting' });
    } else if (o.t === 'hello') {
      if (!local || peers[from]) return;
      set({ members: Array.from(new Set([...st.members, from])) });
      if (!greeted[from]) { greeted[from] = true; sig(from, { t: 'hello' }); }
      if (eng.me() < from) await offerTo(from, { join: true });
    } else if (o.t === 'leave') {
      if (st.phase === 'ringing' && from === st.from) finish('Missed call', true); else drop(from, 'Call ended');
    } else if (o.t === 'decline' || o.t === 'busy') {
      drop(from, o.t === 'busy' ? 'Client is busy on another call' : 'Call declined');
    }
  }

  function toggleMute() { if (!local) return; local.getAudioTracks().forEach(t => { t.enabled = !t.enabled; }); set({ muted: !st.muted }); }
  function toggleCam() { if (!local || !st.video) return; local.getVideoTracks().forEach(t => { t.enabled = !t.enabled; }); set({ camOff: !st.camOff }); }
  async function switchCam() {
    if (!local || !st.video) return;
    const f = st.facing === 'user' ? 'environment' : 'user';
    try {
      const nt = (await navigator.mediaDevices.getUserMedia({ video: vc(f, st.members.length > 2) })).getVideoTracks()[0];
      for (const p of Object.values(peers)) { const s = p.pc.getSenders().find(x => x.track && x.track.kind === 'video'); if (s) await s.replaceTrack(nt); }
      local.getVideoTracks().forEach(t => { t.stop(); local.removeTrack(t); });
      local.addTrack(nt); set({ facing: f, camOff: false });
    } catch (e) { /* keep current camera */ }
  }
  return {
    init(engine, callback) { eng = engine; cb = callback; eng.onCall((from, o) => handle(from, o)); },
    start, invite, accept, decline, end, toggleMute, toggleCam, switchCam,
  };
})();
