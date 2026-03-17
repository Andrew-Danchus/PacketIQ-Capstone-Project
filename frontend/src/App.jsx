import React, { useState, useEffect, useRef } from 'react';
import './App.css';

const INITIAL_MESSAGE = {
  role: 'ai',
  type: 'text',
  text: 'PacketIQ Ready. Upload a PCAP file with the + button, paste one in, or type a file path and click Analyze.',
};

function App() {
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState([INITIAL_MESSAGE]);
  const [evidence, setEvidence] = useState(null);
  const [loading, setLoading] = useState(false);
  const [pcapList, setPcapList] = useState([]);
  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  useEffect(() => {
    fetch('/api/pcaps')
      .then(r => r.json())
      .then(setPcapList)
      .catch(() => {});
  }, []);

  const addMessage = (msg) => setMessages(prev => [...prev, msg]);

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

      setEvidence(data.evidence);
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

      setEvidence(data.evidence);
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
      body: JSON.stringify({
        question: 'Summarize suspicious activity and recommend next investigation steps.',
        evidence: ev,
      }),
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
    if (evidence) {
      askQuestion(trimmed);
    } else {
      analyzePath(trimmed);
    }
  };

  const handlePaste = (e) => {
    const items = e.clipboardData.items;
    for (let i = 0; i < items.length; i++) {
      if (items[i].kind === 'file') {
        const file = items[i].getAsFile();
        analyzeFile(file);
        e.preventDefault();
        return;
      }
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) analyzeFile(file);
    e.target.value = '';
  };

  const handleNewSession = () => {
    setEvidence(null);
    setMessages([INITIAL_MESSAGE]);
  };

  return (
    <div className="container" onPaste={handlePaste}>
      <div className="sidebar">
        <div className="sidebar-logo">PacketIQ</div>

        <div className="history-item active">Current Session</div>
        <div className="history-item" onClick={handleNewSession}>+ New Session</div>

        {pcapList.length > 0 && (
          <>
            <div className="sidebar-section-label">Available PCAPs</div>
            {pcapList.map((name) => (
              <div
                key={name}
                className="pcap-item"
                title={name}
                onClick={() => !loading && analyzePath(name)}
              >
                {name}
              </div>
            ))}
          </>
        )}
      </div>

      <div className="main">
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
          {loading && (
            <div className="system-text loading-text">
              Analyzing<span className="dots" />
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        <div className="input-area">
          <label className="upload-btn" title="Upload PCAP">
            +
            <input
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileChange}
              style={{ display: 'none' }}
            />
          </label>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            placeholder={evidence ? 'Ask a follow-up question…' : 'Type a PCAP filename or path…'}
            disabled={loading}
          />
          <button onClick={handleSend} disabled={loading || !input.trim()}>
            {loading ? '…' : evidence ? 'Ask' : 'Analyze'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
