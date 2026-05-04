import React, { useState, useEffect, useRef } from 'react';
import './App.css';

const INITIAL_MESSAGE = {
  role: 'ai',
  type: 'text',
  text: 'PacketIQ Ready. Upload a PCAP file with the + button, paste one in, or type a file path and click Analyze.',
};

const SESSIONS_KEY = 'packetiq_sessions';

function loadStoredSessions() {
  try { return JSON.parse(localStorage.getItem(SESSIONS_KEY) || '[]'); }
  catch { return []; }
}
const SEVERITY_COLOR = { high: '#f85149', medium: '#e3b341', low: '#3fb950' };
const SEVERITY_BG    = { high: 'rgba(248,81,73,0.12)', medium: 'rgba(227,179,65,0.12)', low: 'rgba(63,185,80,0.12)' };

const STATE_COLORS = {
  SF: '#3fb950', S0: '#f85149', REJ: '#f85149', RSTO: '#e3b341',
  RSTR: '#e3b341', RSTOS0: '#f85149', RSTRH: '#e3b341', OTH: '#8b949e',
};
const STATE_LABELS = {
  SF: 'Normal close', S0: 'No reply', REJ: 'Rejected', RSTO: 'Reset by orig.',
  RSTR: 'Reset by resp.', RSTOS0: 'Reset before reply', OTH: 'Mid-stream',
};

function parseEvidence(text) {
  if (!text) return null;
  const out = {
    totalConnections: 0, totalWeird: 0, totalDNS: 0,
    uniqueSrcIPs: 0, uniqueDstIPs: 0,
    topServices: [], topPorts: [], connectionStates: [],
    dnsQueries: [], weirdEvents: [], indicators: [],
  };
  let section = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) { section = null; continue; }
    if (line.startsWith('Total connections:'))      { out.totalConnections = parseInt(line.split(':')[1]) || 0; continue; }
    if (line.startsWith('Total weird events:'))     { out.totalWeird       = parseInt(line.split(':')[1]) || 0; continue; }
    if (line.startsWith('Total DNS events:'))       { out.totalDNS         = parseInt(line.split(':')[1]) || 0; continue; }
    if (line.startsWith('Unique source IPs:'))      { out.uniqueSrcIPs     = parseInt(line.split(':')[1]) || 0; continue; }
    if (line.startsWith('Unique destination IPs:')) { out.uniqueDstIPs     = parseInt(line.split(':')[1]) || 0; continue; }
    if (line === 'Top services:')              { section = 'services';   continue; }
    if (line === 'Top destination ports:')    { section = 'ports';      continue; }
    if (line === 'Connection states:')        { section = 'states';     continue; }
    if (line === 'Top DNS queries:')          { section = 'dns';        continue; }
    if (line === 'Top weird events:')         { section = 'weird';      continue; }
    if (line === 'Potential indicators observed:') { section = 'indicators'; continue; }
    if (!line.startsWith('- ')) continue;
    const item = line.slice(2);
    if (section === 'services') {
      const m = item.match(/^(.+?):\s+(\d+)/);
      if (m) out.topServices.push({ name: m[1].trim(), count: parseInt(m[2]) });
    } else if (section === 'ports') {
      const pm = item.match(/^Port (\d+):\s+(\d+)/);
      const sm = item.match(/Likely service:\s+([^|]+)/);
      if (pm) out.topPorts.push({ port: parseInt(pm[1]), count: parseInt(pm[2]), service: sm ? sm[1].trim() : 'unknown' });
    } else if (section === 'states') {
      const m = item.match(/^([A-Z0-9]+):\s+(\d+)/);
      if (m) out.connectionStates.push({ state: m[1], count: parseInt(m[2]) });
    } else if (section === 'dns') {
      const m = item.match(/^(.+?):\s+(\d+)/);
      if (m) out.dnsQueries.push({ query: m[1].trim(), count: parseInt(m[2]) });
    } else if (section === 'weird') {
      const m = item.match(/^(.+?):\s+(\d+)/);
      if (m) out.weirdEvents.push({ name: m[1].trim(), count: parseInt(m[2]) });
    } else if (section === 'indicators') {
      out.indicators.push(item);
    }
  }
  return out;
}

function formatBytes(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B','KB','MB','GB'], i = Math.floor(Math.log(b) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}

function App() {
  const [input, setInput]       = useState('');
  const [messages, setMessages] = useState([INITIAL_MESSAGE]);
  const [evidence, setEvidence] = useState(null);
  const [detections, setDetections] = useState(null);
  const [pcapName, setPcapName] = useState(null);
  const [loading, setLoading]   = useState(false);
  const [processingSeconds, setProcessingSeconds] = useState(0);
  const [pcapList, setPcapList] = useState([]);
  const [view, setView]         = useState('chat');
  const [aiSummary, setAiSummary]     = useState('');
  const [aiLoading, setAiLoading]     = useState(false);
  const [savedSessions, setSavedSessions] = useState(loadStoredSessions);
  const chatEndRef = useRef(null);

  const totalAlerts = detections
    ? (detections.port_scans?.length || 0) + (detections.ddos?.length || 0) + (detections.brute_force?.length || 0)
    : 0;

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  useEffect(() => {
    if (!loading) return;

    setProcessingSeconds(0);

    const timer = setInterval(() => {
      setProcessingSeconds(prev => prev + 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [loading]);

  useEffect(() => {
    fetch('/api/pcaps').then(r => r.json()).then(setPcapList).catch(() => {});
  }, []);

  useEffect(() => {
    if (view !== 'overview' || !evidence || aiSummary) return;
    setAiLoading(true);
    fetch('/api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        question:
          'In 2-3 sentences describe what this network traffic represents and its overall context. ' +
          'Then list exactly 5 specific, actionable next investigation steps numbered 1 through 5.',
        evidence,
      }),
    })
      .then(r => r.json())
      .then(d => setAiSummary(d.answer || 'No response.'))
      .catch(() => setAiSummary('Unable to load AI analysis.'))
      .finally(() => setAiLoading(false));
  }, [view, evidence]);

  const addMessage = (msg) => setMessages(prev => [...prev, msg]);

  const saveSession = (pcap, evidence, detections) => {
    const session = { pcapName: pcap, evidence, detections: detections || null, timestamp: Date.now() };
    const updated = [session, ...loadStoredSessions().filter(s => s.pcapName !== pcap)].slice(0, 10);
    localStorage.setItem(SESSIONS_KEY, JSON.stringify(updated));
    setSavedSessions(updated);
  };

  const loadSession = (session) => {
    setEvidence(session.evidence);
    setDetections(session.detections);
    setPcapName(session.pcapName);
    setAiSummary('');
    setView('chat');
    setMessages([
      INITIAL_MESSAGE,
      { role: 'system', text: `Loaded saved session: ${session.pcapName}` },
      { role: 'ai', type: 'text', text: 'Session restored from cache. Ask a follow-up question or switch to the Overview and Detections tabs.' },
    ]);
  };

  const afterAnalysis = (data) => {
    setEvidence(data.evidence);
    setDetections(data.detections || null);
    setPcapName(data.pcap);
    setAiSummary('');
    setView('chat');
    saveSession(data.pcap, data.evidence, data.detections);
  };

  const analyzeFile = async (file) => {
    setLoading(true);
    addMessage({ role: 'user', type: 'file', text: file.name });
    addMessage({ role: 'system', text: `Zeek: Extracting metadata from ${file.name}…` });
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await fetch('/api/analyze', { method: 'POST', body: formData });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Analysis failed');
      afterAnalysis(data);
      fetch('/api/pcaps').then(r => r.json()).then(setPcapList).catch(() => {});
      addMessage({ role: 'system', text: 'Zeek: Parsing complete. Querying PacketIQ AI…' });
      await getInitialSummary(data.evidence);
    } catch (err) {
      addMessage({ role: 'system', text: `Error: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const analyzePath = async (path) => {
    setLoading(true);
    addMessage({ role: 'user', type: 'text', text: path });
    addMessage({ role: 'system', text: `Zeek: Extracting metadata from ${path}…` });
    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Analysis failed');
      afterAnalysis(data);
      addMessage({ role: 'system', text: 'Zeek: Parsing complete. Querying PacketIQ AI…' });
      await getInitialSummary(data.evidence);
    } catch (err) {
      addMessage({ role: 'system', text: `Error: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const getInitialSummary = async (ev) => {
    const res = await fetch('/api/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: 'Summarize suspicious activity and recommend next investigation steps.', evidence: ev }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'AI analysis failed');
    addMessage({ role: 'ai', type: 'text', text: data.answer });
  };

  const askQuestion = async (question) => {
    setLoading(true);
    addMessage({ role: 'user', type: 'text', text: question });
    try {
      const res = await fetch('/api/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, evidence }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'AI query failed');
      addMessage({ role: 'ai', type: 'text', text: data.answer });
    } catch (err) {
      addMessage({ role: 'system', text: `Error: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed || loading) return;
    setInput('');
    evidence ? askQuestion(trimmed) : analyzePath(trimmed);
  };

  const handlePaste = (e) => {
    const items = e.clipboardData.items;
    for (let i = 0; i < items.length; i++) {
      if (items[i].kind === 'file') { analyzeFile(items[i].getAsFile()); e.preventDefault(); return; }
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) analyzeFile(file);
    e.target.value = '';
  };

  const handleNewSession = () => {
    setEvidence(null); setDetections(null); setPcapName(null);
    setAiSummary(''); setView('chat');
    setMessages([INITIAL_MESSAGE]);
  };


  const stats = parseEvidence(evidence);
  const portScans  = detections?.port_scans  || [];
  const ddos       = detections?.ddos        || [];
  const bruteForce = detections?.brute_force || [];
  const allAlerts  = [...portScans, ...ddos, ...bruteForce];

  return (
    <div className="container" onPaste={handlePaste}>

      {/* ── Sidebar ── */}
      <div className="sidebar">
        <div className="sidebar-logo">PacketIQ</div>
        <div className="history-item active">Current Session</div>
        <div className="history-item" onClick={handleNewSession}>+ New Session</div>
        {savedSessions.length > 0 && (
          <>
            <div className="sidebar-section-label">Past Sessions</div>
            {savedSessions.map(s => (
              <div
                key={s.pcapName}
                className={`session-item${s.pcapName === pcapName ? ' active' : ''}`}
                title={s.pcapName}
                onClick={() => !loading && loadSession(s)}
              >
                <div className="session-name">{s.pcapName}</div>
                <div className="session-date">{new Date(s.timestamp).toLocaleDateString()}</div>
              </div>
            ))}
          </>
        )}

        {pcapList.length > 0 && (
          <>
            <div className="sidebar-section-label">Available PCAPs</div>
            {pcapList.map(name => (
              <div key={name} className="pcap-item" title={name} onClick={() => !loading && analyzePath(name)}>
                {name}
              </div>
            ))}
          </>
        )}
      </div>

      {/* ── Main ── */}
      <div className="main">

        {/* Tab bar — only visible after a PCAP is loaded */}
        {evidence && (
          <div className="view-tabs">
            <button className={`tab${view === 'chat' ? ' active' : ''}`} onClick={() => setView('chat')}>Chat</button>
            <button className={`tab${view === 'overview' ? ' active' : ''}`} onClick={() => setView('overview')}>Overview</button>
            <button className={`tab${view === 'detection' ? ' active' : ''}`} onClick={() => setView('detection')}>
              Detections
              {totalAlerts > 0 && <span className="tab-badge">{totalAlerts}</span>}
            </button>
          </div>
        )}

        {/* ── Chat view ── */}
        {view === 'chat' && (
          <>
            <div className="chat-window">
              {messages.map((msg, i) =>
                msg.role === 'system' ? (
                  <div key={i} className="system-text">{msg.text}</div>
                ) : (
                  <div key={i} className={`message-row ${msg.role}`}>
                    <div className={`bubble ${msg.type === 'file' ? 'file-bubble' : ''}`}>
                      <div className="label">{msg.role === 'user' ? 'YOU' : 'PACKETIQ AI'}</div>
                      {msg.type === 'file' && <span className="file-icon">📄</span>}
                      {msg.text}
                    </div>
                  </div>
                )
              )}
              {loading && <div className="system-text loading-text">Analyzing<span className="dots" /></div>}
              <div ref={chatEndRef} />
            </div>

            <div className="input-area">
              <label className="upload-btn" title="Upload PCAP">
                +
                <input type="file" accept=".pcap,.pcapng,.cap" onChange={handleFileChange} style={{ display: 'none' }} />
              </label>
              <input
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSend()}
                placeholder={evidence ? 'Ask a follow-up question…' : 'Type a PCAP filename or path…'}
                disabled={loading}
              />
              <button onClick={handleSend} disabled={loading || !input.trim()}>
                {loading ? '…' : evidence ? 'Ask' : 'Analyze'}
              </button>
            </div>
          </>
        )}

        {/* ── Overview view ── */}
        {view === 'overview' && stats && (
          <div className="view-scroll">
            <div className="view-content">

              <div className="view-header">
                <div>
                  <h2>Traffic Overview</h2>
                  {pcapName && <div className="ov-pcap-name">{pcapName}</div>}
                  { (
                    <div className="ov-processing-timer">
                      Processing time: {processingSeconds}s
                    </div>
                  )}
                </div>
              </div>

              {/* Stat cards */}
              <div className="ov-stats-row">
                {[
                  { value: stats.totalConnections.toLocaleString(), label: 'Connections', color: '#58a6ff' },
                  { value: stats.uniqueSrcIPs,                      label: 'Source IPs',  color: '#bc8cff' },
                  { value: stats.uniqueDstIPs,                      label: 'Dest. IPs',   color: '#e3b341' },
                  { value: stats.totalDNS.toLocaleString(),         label: 'DNS Events',  color: '#3fb950' },
                  ...(stats.totalWeird > 0 ? [{ value: stats.totalWeird, label: 'Weird Events', color: '#f85149' }] : []),
                ].map(({ value, label, color }) => (
                  <div key={label} className="ov-stat-card" style={{ borderTopColor: color }}>
                    <div className="ov-stat-value" style={{ color }}>{value}</div>
                    <div className="ov-stat-label">{label}</div>
                  </div>
                ))}
              </div>

              {/* Top services bar chart */}
              {stats.topServices.length > 0 && (
                <div className="ov-section">
                  <div className="ov-section-title">Top Services</div>
                  {(() => {
                    const max = Math.max(...stats.topServices.map(s => s.count), 1);
                    return stats.topServices.map((s, i) => (
                      <div key={i} className="bar-row">
                        <span className="bar-label">{s.name}</span>
                        <div className="bar-track"><div className="bar-fill" style={{ width: `${(s.count / max) * 100}%`, background: '#58a6ff' }} /></div>
                        <span className="bar-value">{s.count.toLocaleString()}</span>
                      </div>
                    ));
                  })()}
                </div>
              )}

              {/* Top ports bar chart */}
              {stats.topPorts.length > 0 && (
                <div className="ov-section">
                  <div className="ov-section-title">Top Destination Ports</div>
                  {(() => {
                    const max = Math.max(...stats.topPorts.map(p => p.count), 1);
                    return stats.topPorts.map((p, i) => (
                      <div key={i} className="bar-row">
                        <span className="bar-label">
                          <span className="bar-port">:{p.port}</span>
                          {p.service !== 'unknown' && <span className="bar-service">{p.service}</span>}
                        </span>
                        <div className="bar-track"><div className="bar-fill" style={{ width: `${(p.count / max) * 100}%`, background: '#bc8cff' }} /></div>
                        <span className="bar-value">{p.count.toLocaleString()}</span>
                      </div>
                    ));
                  })()}
                </div>
              )}

              {/* Connection states bar chart */}
              {stats.connectionStates.length > 0 && (
                <div className="ov-section">
                  <div className="ov-section-title">Connection States</div>
                  {(() => {
                    const max = Math.max(...stats.connectionStates.map(s => s.count), 1);
                    return stats.connectionStates.map((s, i) => (
                      <div key={i} className="bar-row">
                        <span className="bar-label">
                          <span className="bar-state" style={{ color: STATE_COLORS[s.state] || '#8b949e' }}>{s.state}</span>
                          {STATE_LABELS[s.state] && <span className="bar-state-desc">{STATE_LABELS[s.state]}</span>}
                        </span>
                        <div className="bar-track"><div className="bar-fill" style={{ width: `${(s.count / max) * 100}%`, background: STATE_COLORS[s.state] || '#8b949e' }} /></div>
                        <span className="bar-value">{s.count.toLocaleString()}</span>
                      </div>
                    ));
                  })()}
                </div>
              )}

              {/* DNS queries + weird events */}
              {(stats.dnsQueries.length > 0 || stats.weirdEvents.length > 0) && (
                <div className="ov-two-col">
                  {stats.dnsQueries.length > 0 && (
                    <div className="ov-section ov-col">
                      <div className="ov-section-title">Top DNS Queries</div>
                      <div className="ov-list">
                        {stats.dnsQueries.map((q, i) => (
                          <div key={i} className="ov-list-item">
                            <span className="ov-list-label">{q.query}</span>
                            <span className="ov-list-count">{q.count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {stats.weirdEvents.length > 0 && (
                    <div className="ov-section ov-col">
                      <div className="ov-section-title">Weird Events</div>
                      <div className="ov-list">
                        {stats.weirdEvents.map((w, i) => (
                          <div key={i} className="ov-list-item">
                            <span className="ov-list-label ov-weird-label">{w.name}</span>
                            <span className="ov-list-count ov-weird-count">{w.count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Potential indicators */}
              {stats.indicators.length > 0 && (
                <div className="ov-section">
                  <div className="ov-section-title">Potential Indicators</div>
                  {stats.indicators.map((ind, i) => (
                    <div key={i} className="ov-indicator">
                      <span className="ov-indicator-dot">⚠</span>
                      <span>{ind}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* AI analysis */}
              <div className="ov-section">
                <div className="ov-section-title">AI Analysis & Next Steps</div>
                <div className="ov-ai-box">
                  {aiLoading
                    ? <div className="system-text loading-text">Consulting PacketIQ AI<span className="dots" /></div>
                    : <div className="ov-ai-content">{aiSummary}</div>
                  }
                </div>
              </div>

            </div>
          </div>
        )}

        {/* ── Detection view ── */}
        {view === 'detection' && (
          <div className="view-scroll">
            <div className="view-content">

              <div className="view-header">
                <h2>Threat Detections</h2>
                <span className={`total-badge ${totalAlerts > 0 ? 'has-alerts' : 'clean'}`}>
                  {totalAlerts > 0 ? `${totalAlerts} Alert${totalAlerts !== 1 ? 's' : ''}` : 'All Clear'}
                </span>
              </div>

              {/* Summary count cards */}
              <div className="det-summary-row">
                {[
                  { count: portScans.length,  label: 'Port Scans',  severity: 'medium', icon: (
                    <svg className="det-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                      <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" />
                      <circle cx="12" cy="12" r="6" strokeDasharray="3 2" />
                      <circle cx="12" cy="12" r="10" strokeDasharray="3 2" />
                      <line x1="12" y1="12" x2="19" y2="5" strokeWidth="2" />
                    </svg>
                  )},
                  { count: ddos.length,        label: 'DDoS',        severity: 'high', icon: (
                    <svg className="det-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
                      <line x1="4" y1="4" x2="11" y2="11" /><line x1="20" y1="4" x2="13" y2="11" />
                      <line x1="4" y1="20" x2="11" y2="13" /><line x1="20" y1="20" x2="13" y2="13" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )},
                  { count: bruteForce.length, label: 'Brute Force', severity: 'high', icon: (
                    <svg className="det-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                      <rect x="5" y="11" width="14" height="10" rx="2" />
                      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
                      <circle cx="12" cy="16" r="1.5" fill="currentColor" stroke="none" />
                    </svg>
                  )},
                ].map(({ count, label, severity, icon }) => {
                  const color = count > 0 ? SEVERITY_COLOR[severity] : '#3fb950';
                  return (
                    <div key={label} className="det-summary-card" style={{ borderColor: count > 0 ? color : 'var(--border)' }}>
                      <div className="det-summary-icon" style={{ color }}>{icon}</div>
                      <div className="det-summary-count" style={{ color }}>{count}</div>
                      <div className="det-summary-label">{label}</div>
                    </div>
                  );
                })}
              </div>

              {/* No threats state */}
              {totalAlerts === 0 && (
                <div className="det-clean">
                  <svg className="shield-ok-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 2L3 6v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V6L12 2z" />
                    <path d="M9 12l2 2 4-4" />
                  </svg>
                  <div className="det-clean-title">No Threats Detected</div>
                  <div className="det-clean-sub">PacketIQ found no port scans, DDoS patterns, or brute force attempts in this capture.</div>
                </div>
              )}

              {/* Alert cards */}
              <div className="det-alerts-list">
                {allAlerts.map((alert, i) => {
                  const color = SEVERITY_COLOR[alert.severity] || '#58a6ff';
                  const bg    = SEVERITY_BG[alert.severity]    || 'rgba(88,166,255,0.12)';
                  return (
                    <div key={i} className="det-alert-card" style={{ borderLeftColor: color }}>

                      <div className="det-alert-header">
                        <span className="det-alert-type-label">
                          {{ port_scan: 'Port Scan', ddos: 'DDoS', brute_force: 'Brute Force' }[alert.type] || alert.type}
                        </span>
                        <span className="det-severity-badge" style={{ background: bg, color }}>
                          {alert.severity?.toUpperCase()}
                        </span>
                      </div>

                      <p className="det-evidence">{alert.evidence}</p>

                      {alert.type === 'port_scan' && (
                        <>
                          <div className="det-stats">
                            <div className="det-stat"><span>Source</span><strong>{alert.src_ip}</strong></div>
                            <div className="det-stat"><span>Unique Ports</span><strong>{alert.unique_ports}</strong></div>
                            <div className="det-stat"><span>Unique Hosts</span><strong>{alert.unique_hosts}</strong></div>
                            <div className="det-stat"><span>Window</span><strong>{alert.window_secs}s</strong></div>
                          </div>
                          {alert.sample_ports?.length > 0 && (
                            <div className="det-port-dots">
                              {alert.sample_ports.map(p => <span key={p} className="det-port-dot">{p}</span>)}
                            </div>
                          )}
                        </>
                      )}

                      {alert.type === 'ddos' && (
                        <div className="det-stats">
                          <div className="det-stat"><span>Target</span><strong>{alert.dst_ip}</strong></div>
                          <div className="det-stat"><span>Source IPs</span><strong>{alert.unique_src_ips}</strong></div>
                          <div className="det-stat"><span>Connections</span><strong>{alert.total_connections}</strong></div>
                          <div className="det-stat"><span>Total Bytes</span><strong>{formatBytes(alert.total_bytes)}</strong></div>
                        </div>
                      )}

                      {alert.type === 'brute_force' && (
                        <>
                          <div className="det-stats">
                            <div className="det-stat"><span>Source</span><strong>{alert.src_ip}</strong></div>
                            <div className="det-stat"><span>Target</span><strong>{alert.dst_ip}:{alert.dst_port}</strong></div>
                            <div className="det-stat"><span>Failed</span><strong>{alert.failed_attempts}</strong></div>
                            <div className="det-stat"><span>Total</span><strong>{alert.total_attempts}</strong></div>
                          </div>
                          <div className="det-attempt-bar-wrap">
                            <div className="det-attempt-bar-label">
                              <span>Failed attempts</span>
                              <span>{alert.failed_attempts} / {alert.total_attempts}</span>
                            </div>
                            <div className="det-attempt-track">
                              <div className="det-attempt-failed" style={{ width: `${(alert.failed_attempts / Math.max(alert.total_attempts, 1)) * 100}%` }} />
                            </div>
                          </div>
                        </>
                      )}

                      {alert.recommendation && (
                        <div className="det-recommendation">
                          <span className="det-rec-label">Recommendation</span>
                          <span>{alert.recommendation}</span>
                        </div>
                      )}

                    </div>
                  );
                })}
              </div>

            </div>
          </div>
        )}

      </div>
    </div>
  );
}

export default App;
