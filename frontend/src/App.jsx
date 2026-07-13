import React, { useState, useEffect } from 'react';
import './App.css';

import * as api from './api';
import Sidebar from './components/Sidebar';
import ChatView from './components/ChatView';
import OverviewView from './components/OverviewView';
import DetectionsView from './components/DetectionsView';
import ConnectionsView from './components/ConnectionsView';
import ProtocolsView from './components/ProtocolsView';

const INITIAL_MESSAGE = {
  role: 'ai',
  type: 'text',
  text: 'PacketIQ Ready. Upload a PCAP file with the + button, paste one in, or type a file path and click Analyze.',
};

const STAGE_LABELS = {
  zeek: 'Zeek: parsing packets into protocol logs…',
  detection: 'Scanning for port scans, DDoS, and brute force…',
  ingest: 'Ingesting logs into the database…',
  rag_index: 'Building the AI retrieval index…',
  summary: 'Summarizing traffic…',
};

function App() {
  const [input, setInput]         = useState('');
  const [messages, setMessages]   = useState([INITIAL_MESSAGE]);
  const [session, setSession]     = useState(null); // { job_id, pcap, stats, evidence, detections, timings }
  const [loading, setLoading]     = useState(false);
  const [pcapList, setPcapList]   = useState([]);
  const [view, setView]           = useState('chat');
  const [aiSummary, setAiSummary] = useState('');
  const [aiLoading, setAiLoading] = useState(false);
  const [savedSessions, setSavedSessions] = useState([]);

  const detections = session?.detections;
  const totalAlerts = detections
    ? (detections.port_scans?.length || 0) + (detections.ddos?.length || 0) + (detections.brute_force?.length || 0)
    : 0;

  const refreshSidebar = () => {
    api.listPcaps().then(setPcapList).catch(() => {});
    api.listJobs()
      .then(jobsList => setSavedSessions(
        jobsList.map(j => ({ jobId: j.id, pcapName: j.filename, timestamp: j.created_at }))
      ))
      .catch(() => {});
  };

  useEffect(refreshSidebar, []);

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

  // Replace the text of the last message (used for stage updates and streaming).
  const updateLastMessage = (text) =>
    setMessages(prev => prev.map((m, i) => (i === prev.length - 1 ? { ...m, text } : m)));

  const streamAnswer = async (jobId, question) => {
    addMessage({ role: 'ai', type: 'text', text: '' });
    const fullText = await api.askQuestionStream(jobId, question, (_token, soFar) => {
      updateLastMessage(soFar);
    });
    if (!fullText) updateLastMessage('No response.');
  };

  const loadSession = async (saved) => {
    if (loading) return;
    setLoading(true);
    try {
      const result = await api.getJobResult(saved.jobId);
      setSession(result);
      setAiSummary('');
      setView('chat');
      setMessages([
        INITIAL_MESSAGE,
        { role: 'system', text: `Loaded saved session: ${result.pcap}` },
        { role: 'ai', type: 'text', text: 'Session restored. Ask a follow-up question or switch to the Overview and Detections tabs.' },
      ]);
    } catch (err) {
      addMessage({ role: 'system', text: `Error loading session: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const runAnalysis = async (label, request) => {
    setLoading(true);
    addMessage({ role: 'system', text: `Queued analysis of ${label}…` });
    try {
      const { job_id } = await request();
      const result = await api.waitForJob(job_id, (stage) => {
        updateLastMessage(STAGE_LABELS[stage] || `${stage}…`);
      });

      setSession(result);
      setAiSummary('');
      setView('chat');
      refreshSidebar();

      updateLastMessage('Analysis complete. Querying PacketIQ AI…');
      await streamAnswer(job_id, 'Summarize suspicious activity and recommend next investigation steps.');
    } catch (err) {
      addMessage({ role: 'system', text: `Error: ${err.message}` });
    } finally {
      setLoading(false);
    }
  };

  const analyzeFile = (file) => {
    addMessage({ role: 'user', type: 'file', text: file.name });
    runAnalysis(file.name, () => api.analyzeUpload(file));
  };

  const analyzePath = (path) => {
    addMessage({ role: 'user', type: 'text', text: path });
    runAnalysis(path, () => api.analyzePath(path));
  };

  const askQuestion = async (question) => {
    setLoading(true);
    addMessage({ role: 'user', type: 'text', text: question });
    try {
      await streamAnswer(session.job_id, question);
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
    session ? askQuestion(trimmed) : analyzePath(trimmed);
  };

  const handlePaste = (e) => {
    const items = e.clipboardData.items;
    for (let i = 0; i < items.length; i++) {
      if (items[i].kind === 'file') { analyzeFile(items[i].getAsFile()); e.preventDefault(); return; }
    }
  };

  const handleNewSession = () => {
    setSession(null);
    setAiSummary('');
    setView('chat');
    setMessages([INITIAL_MESSAGE]);
  };

  return (
    <div className="container" onPaste={handlePaste}>

      <Sidebar
        savedSessions={savedSessions}
        activePcapName={session?.pcap}
        pcapList={pcapList}
        loading={loading}
        onNewSession={handleNewSession}
        onLoadSession={loadSession}
        onAnalyzePath={analyzePath}
      />

      <div className="main">

        {session && (
          <div className="view-tabs">
            <button className={`tab${view === 'chat' ? ' active' : ''}`} onClick={() => setView('chat')}>Chat</button>
            <button className={`tab${view === 'overview' ? ' active' : ''}`} onClick={() => setView('overview')}>Overview</button>
            <button className={`tab${view === 'detection' ? ' active' : ''}`} onClick={() => setView('detection')}>
              Detections
              {totalAlerts > 0 && <span className="tab-badge">{totalAlerts}</span>}
            </button>
            <button className={`tab${view === 'connections' ? ' active' : ''}`} onClick={() => setView('connections')}>Connections</button>
            <button className={`tab${view === 'protocols' ? ' active' : ''}`} onClick={() => setView('protocols')}>Protocols</button>
          </div>
        )}

        {view === 'chat' && (
          <ChatView
            messages={messages}
            loading={loading}
            input={input}
            setInput={setInput}
            hasSession={!!session}
            onSend={handleSend}
            onFileSelected={analyzeFile}
          />
        )}

        {view === 'overview' && session && (
          <OverviewView
            stats={session.stats}
            pcapName={session.pcap}
            timings={session.timings}
            aiSummary={aiSummary}
            aiLoading={aiLoading}
          />
        )}

        {view === 'detection' && (
          <DetectionsView detections={detections} />
        )}

        {view === 'connections' && session && (
          <ConnectionsView jobId={session.job_id} />
        )}

        {view === 'protocols' && session && (
          <ProtocolsView jobId={session.job_id} />
        )}

      </div>
    </div>
  );
}

export default App;
