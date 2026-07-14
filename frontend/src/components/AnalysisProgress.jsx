import React from 'react';

// Ordered pipeline stages with analyst-friendly labels.
const STAGES = [
  { key: 'zeek', label: 'Parsing packets', detail: 'Zeek extracts connections, DNS, HTTP, and TLS' },
  { key: 'detection', label: 'Detecting threats', detail: 'Port scans, DDoS, brute force' },
  { key: 'ingest', label: 'Storing events', detail: 'Loading logs into the database' },
  { key: 'rag_index', label: 'Indexing for AI', detail: 'Embedding records so the copilot can search them' },
  { key: 'summary', label: 'Summarizing', detail: 'Computing traffic statistics' },
];

export default function AnalysisProgress({ fileName, stage, error, onDismiss }) {
  const activeIndex = STAGES.findIndex(s => s.key === stage);

  return (
    <div className="progress-wrap">
      <div className="progress-card">
        <div className="progress-title">
          {error ? 'Analysis failed' : 'Analyzing capture'}
        </div>
        <div className="progress-file">{fileName}</div>

        {error ? (
          <>
            <div className="progress-error">{error}</div>
            <button className="filter-apply" onClick={onDismiss}>Dismiss</button>
          </>
        ) : (
          <div className="progress-steps">
            {STAGES.map((s, i) => {
              const state = activeIndex === -1
                ? (i === 0 ? 'pending' : 'pending')
                : i < activeIndex ? 'done' : i === activeIndex ? 'active' : 'pending';
              return (
                <div key={s.key} className={`progress-step ${state}`}>
                  <span className="progress-step-icon">
                    {state === 'done' ? '✓' : state === 'active' ? <span className="progress-spinner" /> : '○'}
                  </span>
                  <span className="progress-step-text">
                    <span className="progress-step-label">{s.label}</span>
                    <span className="progress-step-detail">{s.detail}</span>
                  </span>
                </div>
              );
            })}
            {activeIndex === -1 && (
              <div className="progress-queued"><span className="progress-spinner" /> Queued — waiting for the pipeline…</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
