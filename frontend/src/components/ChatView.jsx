import React, { useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';

export default function ChatView({
  messages,
  loading,
  input,
  setInput,
  hasSession,
  onSend,
  suggestions = [],
  onSuggestion,
}) {
  const chatEndRef = useRef(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  return (
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
                {msg.role === 'ai'
                  ? <div className="markdown"><ReactMarkdown>{msg.text}</ReactMarkdown></div>
                  : msg.text}
              </div>
            </div>
          )
        )}
        {loading && <div className="system-text loading-text">Analyzing<span className="dots" /></div>}
        <div ref={chatEndRef} />
      </div>

      {suggestions.length > 0 && (
        <div className="suggestion-chips">
          {suggestions.map((q, i) => (
            <button key={i} className="suggestion-chip" onClick={() => onSuggestion?.(q)}>
              {q}
            </button>
          ))}
        </div>
      )}

      <div className="input-area">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && onSend()}
          placeholder={hasSession ? 'Ask a follow-up question…' : 'Add a PCAP from the sidebar to start'}
          disabled={loading || !hasSession}
        />
        <button onClick={onSend} disabled={loading || !hasSession || !input.trim()}>
          {loading ? '…' : 'Ask'}
        </button>
      </div>
    </>
  );
}
