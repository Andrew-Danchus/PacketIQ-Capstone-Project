import React from 'react';

export default function Sidebar({
  savedSessions,
  activePcapName,
  pcapList,
  loading,
  onNewSession,
  onLoadSession,
  onAnalyzePath,
}) {
  return (
    <div className="sidebar">
      <div className="sidebar-logo">PacketIQ</div>
      <div className="history-item active">Current Session</div>
      <div className="history-item" onClick={onNewSession}>+ New Session</div>

      {savedSessions.length > 0 && (
        <>
          <div className="sidebar-section-label">Past Sessions</div>
          {savedSessions.map(s => (
            <div
              key={s.jobId || s.pcapName}
              className={`session-item${s.pcapName === activePcapName ? ' active' : ''}`}
              title={s.pcapName}
              onClick={() => !loading && onLoadSession(s)}
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
            <div key={name} className="pcap-item" title={name} onClick={() => !loading && onAnalyzePath(name)}>
              {name}
            </div>
          ))}
        </>
      )}
    </div>
  );
}
