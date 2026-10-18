window.WhisperCall = (function () {
  const ICE = { iceServers: [{ urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] }] };
  let eng = null, cb = () => {}, pc = null, local = null, remote = null, queued = [], early = {};
  let timer = null, ringT = null, ringI = null, actx = null, st = { phase: 'idle' };
  const emit = () => cb({ ...st, local, remote });
  const set = p => { st = { ...st, ...p }; emit(); };
  const send = o => eng.signal(st.peerId, { ...o, cid: st.cid });
  const nm = id => (eng.getState().contacts.find(c => c.id === id) || {}).alias || 'Client';
  const media = (video, facing) => navigator.mediaDevices.getUserMedia({ audio: true, video: video ? { facingMode: facing || 'user' } : false });

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

  function mkPc() {
    pc = new RTCPeerConnection(ICE);
    local.getTracks().forEach(t => pc.addTrack(t, local));
    pc.onicecandidate = e => { if (e.candidate) send({ t: 'ice', c: e.candidate.toJSON() }); };
    pc.ontrack = e => { if (e.streams && e.streams[0]) remote = e.streams[0]; emit(); };
    pc.onconnectionstatechange = () => {
      if (!pc) return;
      if (pc.connectionState === 'connected' && st.phase !== 'connected') {
        ring(false); clearTimeout(ringT);
        const t0 = Date.now();
        timer = setInterval(() => set({ dur: Math.floor((Date.now() - t0) / 1000) }), 1000);
        set({ phase: 'connected', dur: 0 });
      }
      if (pc.connectionState === 'failed') finish('Connection failed');
    };
  }
  async function flush() { for (const c of queued.splice(0)) { try { await pc.addIceCandidate(c); } catch (e) { /* ignore */ } } }

  function finish(msg, missed) {
    ring(false); clearTimeout(ringT); clearInterval(timer);
    const was = st;
    if (pc) { try { pc.close(); } catch (e) { /* ignore */ } pc = null; }
    if (local) local.getTracks().forEach(t => t.stop());
    local = null; remote = null; queued = []; early = {};
    if (was.phase !== 'idle') eng.addCall({ id: was.cid + was.dir, peerId: was.peerId, name: was.name, type: was.video ? 'video' : 'voice', dir: missed ? 'missed' : was.dir, ts: Date.now(), dur: was.dur || 0 });
    st = { phase: 'idle', msg }; emit();
  }

  async function start(peerId, video) {
    if (st.phase !== 'idle') return;
    try { local = await media(video); } catch (e) { throw new Error('Camera or microphone access was not allowed.'); }
    st = { phase: 'calling', peerId, name: nm(peerId), video, cid: crypto.randomUUID ? crypto.randomUUID() : String(Date.now()), dir: 'out', muted: false, camOff: false, facing: 'user', dur: 0 };
    emit(); ring(true); mkPc();
    const offer = await pc.createOffer(); await pc.setLocalDescription(offer);
    send({ t: 'offer', sdp: offer.sdp, video });
    ringT = setTimeout(() => { send({ t: 'end' }); finish('No answer'); }, 45000);
  }
  async function accept() {
    if (st.phase !== 'ringing') return;
    ring(false); clearTimeout(ringT);
    try { local = await media(st.video); } catch (e) { send({ t: 'decline' }); finish('Camera or microphone access was not allowed.'); return; }
    mkPc();
    await pc.setRemoteDescription({ type: 'offer', sdp: st.offer });
    await flush();
    const ans = await pc.createAnswer(); await pc.setLocalDescription(ans);
    send({ t: 'answer', sdp: ans.sdp }); set({ phase: 'connecting' });
  }
  function decline() { send({ t: 'decline' }); finish(''); }
  function end() { send({ t: 'end' }); finish('Call ended'); }

  async function handle(from, o) {
    if (o.t === 'offer') {
      if (st.phase !== 'idle') { eng.signal(from, { t: 'busy', cid: o.cid }); return; }
      st = { phase: 'ringing', peerId: from, name: nm(from), video: !!o.video, cid: o.cid, dir: 'in', offer: o.sdp, muted: false, camOff: false, facing: 'user', dur: 0 };
      queued = early[o.cid] || []; early = {};
      emit(); ring(true);
      ringT = setTimeout(() => finish('Missed call', true), 45000);
      return;
    }
    if (st.phase === 'idle') { if (o.t === 'ice') (early[o.cid] = early[o.cid] || []).push(o.c); return; }
    if (o.cid !== st.cid || from !== st.peerId) return;
    if (o.t === 'answer' && pc) {
      await pc.setRemoteDescription({ type: 'answer', sdp: o.sdp }); await flush();
      ring(false); clearTimeout(ringT); set({ phase: 'connecting' });
    } else if (o.t === 'ice') {
      if (pc && pc.remoteDescription) { try { await pc.addIceCandidate(o.c); } catch (e) { /* ignore */ } } else queued.push(o.c);
    } else if (o.t === 'end') finish(st.phase === 'ringing' ? 'Missed call' : 'Call ended', st.phase === 'ringing');
    else if (o.t === 'decline') finish('Call declined');
    else if (o.t === 'busy') finish('Client is busy on another call');
  }

  function toggleMute() { if (!local) return; local.getAudioTracks().forEach(t => { t.enabled = !t.enabled; }); set({ muted: !st.muted }); }
  function toggleCam() { if (!local || !st.video) return; local.getVideoTracks().forEach(t => { t.enabled = !t.enabled; }); set({ camOff: !st.camOff }); }
  async function switchCam() {
    if (!local || !st.video || !pc) return;
    const f = st.facing === 'user' ? 'environment' : 'user';
    try {
      const nt = (await navigator.mediaDevices.getUserMedia({ video: { facingMode: f } })).getVideoTracks()[0];
      const sender = pc.getSenders().find(s => s.track && s.track.kind === 'video');
      if (sender) await sender.replaceTrack(nt);
      local.getVideoTracks().forEach(t => { t.stop(); local.removeTrack(t); });
      local.addTrack(nt); set({ facing: f, camOff: false });
    } catch (e) { /* keep current camera */ }
  }
  return {
    init(engine, callback) { eng = engine; cb = callback; eng.onCall((from, o) => handle(from, o)); },
    start, accept, decline, end, toggleMute, toggleCam, switchCam,
  };
})();
