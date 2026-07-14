import React from 'react';

const STEPS = [
  { n: 1, title: 'Drop a capture', text: 'PCAP, PCAPNG, or CAP — drag it anywhere in this window' },
  { n: 2, title: 'Zeek + detections run', text: 'Connections, DNS, HTTP, TLS extracted; threats flagged automatically' },
  { n: 3, title: 'Investigate with AI', text: 'Browse the tabs and ask the copilot about anything you see' },
];

export default function WelcomeView({ onFileSelected }) {
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) onFileSelected(file);
    e.target.value = '';
  };

  return (
    <div className="welcome-empty">
      <div className="welcome-logo">PacketIQ</div>
      <p className="welcome-tagline">AI-powered network packet analysis</p>

      <label className="welcome-dropzone">
        <input
          type="file"
          accept=".pcap,.pcapng,.cap"
          onChange={handleFileChange}
          style={{ display: 'none' }}
        />
        <div className="welcome-dropzone-icon">⇪</div>
        <div className="welcome-dropzone-title">Drop a PCAP here</div>
        <div className="welcome-dropzone-sub">or <span className="welcome-browse">browse files</span> · paste a capture · pick one from the sidebar</div>
      </label>

      <div className="welcome-steps">
        {STEPS.map(s => (
          <div key={s.n} className="welcome-step">
            <div className="welcome-step-num">{s.n}</div>
            <div>
              <div className="welcome-step-title">{s.title}</div>
              <div className="welcome-step-text">{s.text}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
