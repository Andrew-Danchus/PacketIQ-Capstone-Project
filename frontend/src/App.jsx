import React, { useState, useEffect, useRef } from 'react';
import './App.css';

import * as api from './api';
import Sidebar from './components/Sidebar';
import ChatPanel from './components/ChatPanel';
import OverviewView from './components/OverviewView';
import DetectionsView from './components/DetectionsView';
import ConnectionsView from './components/ConnectionsView';
import ProtocolsView from './components/ProtocolsView';
import WelcomeView from './components/WelcomeView';
import AnalysisProgress from './components/AnalysisProgress';

const INITIAL_MESSAGE = {
  role: 'ai',
  type: 'text',
  text: "I'm PacketIQ. Drop a PCAP anywhere in this window (or use the + button) and I'll parse it, flag threats, and answer questions while you dig through the tabs.",
};

const STAGE_LABELS = {
  zeek: 'Zeek: parsing packets into protocol logs…',
  detection: 'Scanning for port scans, DDoS, and brute force…',
  ingest: 'Ingesting logs into the database…',
  rag_index: 'Building the AI retrieval index…',
  summary: 'Summarizing traffic…',
};

const VIEW_LABELS = {
  overview: 'Overview',
  detection: 'Detections',
  connections: 'Connections',
  protocols: 'Protocols',
};

const SUGGESTED_QUESTIONS = [
  'What looks suspicious in this capture?',
  'Who are the top talkers?',
  'What should I investigate next?',
];

const PCAP_RE = /\.(pcap|pcapng|cap)$/i;

function App() {
  const [input, setInput]         = useState('');
  const [messages, setMessages]   = useState([INITIAL_MESSAGE]);
  const [session, setSession]     = useState(null);
  const [loading, setLoading]     = useState(false);
  const [view, setView]           = useState('overview');
  const [aiSummary, setAiSummary] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [savedSessions, setSavedSessions] = useState([]);
  const [filterContext, setFilterContext] = useState('');
  const [connPreset, setConnPreset] = useState(null);

  // Analysis progress shown in the main area.
  const [analyzing, setAnalyzing]         = useState(false);
  const [analysisStage, setAnalysisStage] = useState(null);
  const [analysisFile, setAnalysisFile]   = useState('');
  const [analysisError, setAnalysisError] = useState(null);

  // Whole-window drag & drop.
  const [dragActive, setDragActive] = useState(false);
  const dragDepth = useRef(0);

  const [chatCollapsed, setChatCollapsed] = useState(
    () => localStorage.getItem('packetiq_chat_collapsed') === '1'
  );
  const [chatWidth, setChatWidth] = useState(
    () => Number(localStorage.getItem('packetiq_chat_width')) || 380
  );
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => localStorage.getItem('packetiq_sidebar_collapsed') === '1'
  );

  const detections = session?.detections;
  const totalAlerts = detections
    ? (detections.port_scans?.length || 0) + (detections.ddos?.length || 0) + (detections.brute_force?.length || 0)
    : 0;

  useEffect(() => { localStorage.setItem('packetiq_chat_collapsed', chatCollapsed ? '1' : '0'); }, [chatCollapsed]);
  useEffect(() => { localStorage.setItem('packetiq_chat_width', String(chatWidth)); }, [chatWidth]);
  useEffect(() => { localStorage.setItem('packetiq_sidebar_collapsed', sidebarCollapsed ? '1' : '0'); }, [sidebarCollapsed]);

  const refreshSidebar = () => {
    api.listJobs()
      .then(jobsList => setSavedSessions(
        jobsList.map(j => ({ jobId: j.id, pcapName: j.filename, timestamp: j.created_at }))
      ))
      .catch(() => {});
  };

  useEffect(refreshSidebar, []);

  // Describe what the analyst is looking at, so "is this normal?" has a referent.
  const buildViewContext = () => {
    if (!session) return '';
    let ctx = `The analyst is on the ${VIEW_LABELS[view] || view} view of capture "${session.pcap}".`;
    if (view === 'connections' && filterContext) ctx += ` ${filterContext}`;
    return ctx;
  };

  // Overview tab lazily streams its AI summary once per session.
  useEffect(() => {
    if (view !== 'overview' || !session || aiSummary || aiLoading) return;
    setAiLoading(true);
    setAiSummary('');
    api.askQuestionStream(
      session.job_id,
      'In 2-3 sentences describe what this network traffic represents and its overall context. ' +
      'Then list exactly 5 specific, actionable next investigation steps numbered 1 through 5.',
      (_token, fullText) => setAiSummary(fullText),
    )
      .then(fullText => { if (!fullText) setAiSummary('No response.'); })
      .catch(() => setAiSummary(prev => prev || 'Unable to load AI analysis.'))
      .finally(() => setAiLoading(false));
  }, [view, session]);

  const addMessage = (msg) => setMessages(prev => [...prev, msg]);

  const updateLastMessage = (text) =>
    setMessages(prev => prev.map((m, i) => (i === prev.length - 1 ? { ...m, text } : m)));

  const streamAnswer = async (jobId, question, viewContext) => {
    addMessage({ role: 'ai', type: 'text', text: '' });
    const fullText = await api.askQuestionStream(
      jobId, question, (_token, soFar) => updateLastMessage(soFar), viewContext,
    );
    if (!fullText) updateLastMessage('No response.');
  };

  const loadSession = async (saved) => {
    if (loading) return;
    setLoading(true);
    try {
      const result = await api.getJobResult(saved.jobId);
      setSession(result);
      setAiSummary('');
      setFilterContext('');
      setConnPreset(null);
      setView('overview');
      setMessages([
        INITIAL_MESSAGE,
        { role: 'system', text: `Loaded saved session: ${result.pcap}` },
        { role: 'ai', type: 'text', text: 'Session restored — ask me anything about this capture.' },
      ]);
    } catch (err) {
      setChatCollapsed(false);
      addMessage({ role: 'system', text: `Error loading session: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const runAnalysis = async (label, request) => {
    setLoading(true);
    setAnalyzing(true);
    setAnalysisStage(null);
    setAnalysisError(null);
    setAnalysisFile(label);
    addMessage({ role: 'system', text: `Queued analysis of ${label}…` });
    try {
      const { job_id } = await request();
      const result = await api.waitForJob(job_id, (stage) => {
        setAnalysisStage(stage);
        updateLastMessage(STAGE_LABELS[stage] || `${stage}…`);
      });

      setSession(result);
      setAiSummary('');
      setFilterContext('');
      setConnPreset(null);
      setView('overview');
      setAnalyzing(false);
      refreshSidebar();

      updateLastMessage('Analysis complete. Querying PacketIQ AI…');
      await streamAnswer(job_id, 'Summarize suspicious activity and recommend next investigation steps.', '');
    } catch (err) {
      setAnalysisError(err.message);
      addMessage({ role: 'system', text: `Error: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const analyzeFile = (file) => {
    addMessage({ role: 'user', type: 'file', text: file.name });
    runAnalysis(file.name, () => api.analyzeUpload(file));
  };

  const askQuestion = async (question) => {
    if (chatCollapsed) setChatCollapsed(false);
    setLoading(true);
    addMessage({ role: 'user', type: 'text', text: question });
    try {
      await streamAnswer(session.job_id, question, buildViewContext());
    } catch (err) {
      addMessage({ role: 'system', text: `Error: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed || loading || !session) return;
    setInput('');
    askQuestion(trimmed);
  };

  const handlePaste = (e) => {
    const items = e.clipboardData.items;
    for (let i = 0; i < items.length; i++) {
      if (items[i].kind === 'file') { analyzeFile(items[i].getAsFile()); e.preventDefault(); return; }
    }
  };

  // ── Whole-window drag & drop ──
  const onDragEnter = (e) => {
    e.preventDefault();
    if (!e.dataTransfer?.types?.includes('Files')) return;
    dragDepth.current += 1;
    setDragActive(true);
  };
  const onDragLeave = (e) => {
    e.preventDefault();
    dragDepth.current = Math.max(0, dragDepth.current - 1);
    if (dragDepth.current === 0) setDragActive(false);
  };
  const onDragOver = (e) => e.preventDefault();
  const onDrop = (e) => {
    e.preventDefault();
    dragDepth.current = 0;
    setDragActive(false);
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    if (!PCAP_RE.test(file.name)) {
      setChatCollapsed(false);
      addMessage({ role: 'system', text: `"${file.name}" isn't a capture file — expected .pcap, .pcapng, or .cap.` });
      return;
    }
    if (!loading) analyzeFile(file);
  };

  // Jump to the Connections tab with filters pre-applied (from alerts, stat cards…).
  const openConnections = (filters = {}) => {
    setConnPreset({ ...filters, nonce: Date.now() });
    setView('connections');
  };

  const handleExport = async () => {
    try {
      await api.downloadReport(session.job_id, session.pcap);
    } catch (err) {
      setChatCollapsed(false);
      addMessage({ role: 'system', text: `Report export failed: ${err.message}` });
    }
  };

  const handleNewSession = () => {
    setSession(null);
    setAiSummary('');
    setFilterContext('');
    setConnPreset(null);
    setView('overview');
    setMessages([INITIAL_MESSAGE]);
  };

  const deleteSession = async (jobId) => {
    try {
      await api.deleteJob(jobId);
      if (session?.job_id === jobId) handleNewSession();
      refreshSidebar();
    } catch (err) {
      setChatCollapsed(false);
      addMessage({ role: 'system', text: `Couldn't delete session: ${err.message}` });
    }
  };

  return (
    <div
      className="container"
      onPaste={handlePaste}
      onDragEnter={onDragEnter}
      onDragLeave={onDragLeave}
      onDragOver={onDragOver}
      onDrop={onDrop}
    >

      {dragActive && (
        <div className="drop-overlay">
          <div className="drop-overlay-box">
            <div className="drop-overlay-icon">⇪</div>
            Drop to analyze
          </div>
        </div>
      )}

      <Sidebar
        savedSessions={savedSessions}
        activePcapName={session?.pcap}
        loading={loading}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(c => !c)}
        onNewSession={handleNewSession}
        onLoadSession={loadSession}
        onDeleteSession={deleteSession}
        onFileSelected={analyzeFile}
      />

      <ChatPanel
        collapsed={chatCollapsed}
        onToggle={() => setChatCollapsed(c => !c)}
        width={chatWidth}
        onResize={setChatWidth}
        contextLabel={session ? (VIEW_LABELS[view] || view) : ''}
        messages={messages}
        loading={loading}
        input={input}
        setInput={setInput}
        hasSession={!!session}
        onSend={handleSend}
        suggestions={session && !loading ? SUGGESTED_QUESTIONS : []}
        onSuggestion={askQuestion}
      />

      <div className="main">

        {analyzing ? (
          <AnalysisProgress
            fileName={analysisFile}
            stage={analysisStage}
            error={analysisError}
            onDismiss={() => { setAnalyzing(false); setAnalysisError(null); }}
          />
        ) : session ? (
          <>
            <div className="view-tabs">
              <button className={`tab${view === 'overview' ? ' active' : ''}`} onClick={() => setView('overview')}>Overview</button>
              <button className={`tab${view === 'detection' ? ' active' : ''}`} onClick={() => setView('detection')}>
                Detections
                {totalAlerts > 0 && <span className="tab-badge">{totalAlerts}</span>}
              </button>
              <button className={`tab${view === 'connections' ? ' active' : ''}`} onClick={() => setView('connections')}>Connections</button>
              <button className={`tab${view === 'protocols' ? ' active' : ''}`} onClick={() => setView('protocols')}>Protocols</button>
              <div className="view-tabs-spacer" />
              <button className="export-btn" onClick={handleExport} title="Download markdown report">↓ Export Report</button>
            </div>

            {view === 'overview' && (
              <OverviewView
                jobId={session.job_id}
                stats={session.stats}
                pcapName={session.pcap}
                timings={session.timings}
                aiSummary={aiSummary}
                aiLoading={aiLoading}
                onOpenConnections={openConnections}
                onOpenProtocols={() => setView('protocols')}
              />
            )}

            {view === 'detection' && (
              <DetectionsView
                detections={detections}
                onAskAbout={askQuestion}
                onViewConnections={openConnections}
              />
            )}

            {view === 'connections' && (
              <ConnectionsView
                jobId={session.job_id}
                preset={connPreset}
                onContextChange={setFilterContext}
                onAskAbout={askQuestion}
              />
            )}

            {view === 'protocols' && (
              <ProtocolsView jobId={session.job_id} />
            )}
          </>
        ) : (
          <WelcomeView onFileSelected={analyzeFile} />
        )}

      </div>
    </div>
  );
}

export default App;
