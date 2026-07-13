import React from 'react';

const SEVERITY_COLOR = { high: '#f85149', medium: '#e3b341', low: '#3fb950' };
const SEVERITY_BG    = { high: 'rgba(248,81,73,0.12)', medium: 'rgba(227,179,65,0.12)', low: 'rgba(63,185,80,0.12)' };

function formatBytes(b) {
  if (!b) return '0 B';
  const k = 1024, s = ['B','KB','MB','GB'], i = Math.floor(Math.log(b) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(1)} ${s[i]}`;
}

const SUMMARY_ICONS = {
  portScan: (
    <svg className="det-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="6" strokeDasharray="3 2" />
      <circle cx="12" cy="12" r="10" strokeDasharray="3 2" />
      <line x1="12" y1="12" x2="19" y2="5" strokeWidth="2" />
    </svg>
  ),
  ddos: (
    <svg className="det-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <line x1="4" y1="4" x2="11" y2="11" /><line x1="20" y1="4" x2="13" y2="11" />
      <line x1="4" y1="20" x2="11" y2="13" /><line x1="20" y1="20" x2="13" y2="13" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  ),
  bruteForce: (
    <svg className="det-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" />
      <circle cx="12" cy="16" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  ),
};

export default function DetectionsView({ detections }) {
  const portScans  = detections?.port_scans  || [];
  const ddos       = detections?.ddos        || [];
  const bruteForce = detections?.brute_force || [];
  const allAlerts  = [...portScans, ...ddos, ...bruteForce];
  const totalAlerts = allAlerts.length;

  return (
    <div className="view-scroll">
      <div className="view-content">

        <div className="view-header">
          <h2>Threat Detections</h2>
          <span className={`total-badge ${totalAlerts > 0 ? 'has-alerts' : 'clean'}`}>
            {totalAlerts > 0 ? `${totalAlerts} Alert${totalAlerts !== 1 ? 's' : ''}` : 'All Clear'}
          </span>
        </div>

        <div className="det-summary-row">
          {[
            { count: portScans.length,  label: 'Port Scans',  severity: 'medium', icon: SUMMARY_ICONS.portScan },
            { count: ddos.length,       label: 'DDoS',        severity: 'high',   icon: SUMMARY_ICONS.ddos },
            { count: bruteForce.length, label: 'Brute Force', severity: 'high',   icon: SUMMARY_ICONS.bruteForce },
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
  );
}
