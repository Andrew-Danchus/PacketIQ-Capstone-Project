import React, { useState } from 'react';

// "just now", "5m ago", "3h ago", "2d ago", then a plain date.
function timeAgo(ts) {
  const then = new Date(ts).getTime();
  if (Number.isNaN(then)) return '';
  const secs = Math.floor((Date.now() - then) / 1000);
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  if (secs < 7 * 86400) return `${Math.floor(secs / 86400)}d ago`;
  return new Date(ts).toLocaleDateString();
}

const TrashIcon = () => (
  <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
       strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 6h18" />
    <path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" />
    <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
    <line x1="10" y1="11" x2="10" y2="17" />
    <line x1="14" y1="11" x2="14" y2="17" />
  </svg>
);

export default function Sidebar({
  savedSessions,
  activePcapName,
  loading,
  collapsed,
  onToggleCollapse,
  onNewSession,
  onLoadSession,
  onDeleteSession,
  onFileSelected,
}) {
  const [confirmId, setConfirmId] = useState(null);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) onFileSelected?.(file);
    e.target.value = '';
  };

  if (collapsed) {
    return (
      <div className="sidebar collapsed">
        <button className="sidebar-icon-btn" onClick={onToggleCollapse} title="Expand sidebar">☰</button>
        <label className="sidebar-icon-btn accent" title="Upload PCAP">
          ⬆
          <input type="file" accept=".pcap,.pcapng,.cap" onChange={handleFileChange} style={{ display: 'none' }} />
        </label>
        <button className="sidebar-icon-btn" onClick={onNewSession} title="New session">+</button>
      </div>
    );
  }

  const handleDelete = (e, jobId) => {
    e.stopPropagation();
    setConfirmId(jobId);
  };
  const confirmDelete = (e, jobId) => {
    e.stopPropagation();
    setConfirmId(null);
    onDeleteSession?.(jobId);
  };
  const cancelDelete = (e) => {
    e.stopPropagation();
    setConfirmId(null);
  };

  return (
    <div className="sidebar">
      <div className="sidebar-top">
        <div className="sidebar-brand">PacketIQ</div>
        <button className="sidebar-collapse-btn" onClick={onToggleCollapse} title="Collapse sidebar">«</button>
      </div>

      <label className="sidebar-new-btn primary" title="Upload a PCAP to analyze">
        <span className="sidebar-new-plus">⬆</span> Upload PCAP
        <input type="file" accept=".pcap,.pcapng,.cap" onChange={handleFileChange} style={{ display: 'none' }} />
      </label>

      <button className="sidebar-new-btn" onClick={onNewSession}>
        <span className="sidebar-new-plus">+</span> New Session
      </button>

      <div className="sidebar-scroll">
        {savedSessions.length > 0 ? (
          <>
            <div className="sidebar-section-label">Past Sessions</div>
            {savedSessions.map(s => {
              const active = s.pcapName === activePcapName;
              const confirming = confirmId === s.jobId;
              return (
                <div
                  key={s.jobId || s.pcapName}
                  className={`session-item${active ? ' active' : ''}`}
                  title={s.pcapName}
                  onClick={() => !loading && !confirming && onLoadSession(s)}
                >
                  <div className="session-info">
                    <div className="session-name">{s.pcapName}</div>
                    <div className="session-date">{timeAgo(s.timestamp)}</div>
                  </div>

                  {confirming ? (
                    <div className="session-confirm">
                      <button className="session-confirm-yes" onClick={(e) => confirmDelete(e, s.jobId)} title="Delete">✓</button>
                      <button className="session-confirm-no" onClick={cancelDelete} title="Keep">✕</button>
                    </div>
                  ) : (
                    <button
                      className="session-delete"
                      onClick={(e) => handleDelete(e, s.jobId)}
                      title="Delete session"
                    >
                      <TrashIcon />
                    </button>
                  )}
                </div>
              );
            })}
          </>
        ) : (
          <div className="sidebar-empty">No sessions yet. Upload a PCAP to get started.</div>
        )}
      </div>
    </div>
  );
}
