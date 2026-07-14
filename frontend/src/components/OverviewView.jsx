import React, { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import * as api from '../api';

const STATE_COLORS = {
  SF: '#3fb950', S0: '#f85149', REJ: '#f85149', RSTO: '#e3b341',
  RSTR: '#e3b341', RSTOS0: '#f85149', RSTRH: '#e3b341', OTH: '#8b949e',
};
const STATE_LABELS = {
  SF: 'Normal close', S0: 'No reply', REJ: 'Rejected', RSTO: 'Reset by orig.',
  RSTR: 'Reset by resp.', RSTOS0: 'Reset before reply', OTH: 'Mid-stream',
};

function BarChart({ items, getLabel, getCount, color, getBarColor, onRowClick, rowTitle }) {
  const max = Math.max(...items.map(getCount), 1);
  return items.map((item, i) => (
    <div
      key={i}
      className={`bar-row${onRowClick ? ' clickable' : ''}`}
      onClick={onRowClick ? () => onRowClick(item) : undefined}
      title={onRowClick ? rowTitle : undefined}
    >
      <span className="bar-label">{getLabel(item)}</span>
      <div className="bar-track">
        <div
          className="bar-fill"
          style={{
            width: `${(getCount(item) / max) * 100}%`,
            background: getBarColor ? getBarColor(item) : color,
          }}
        />
      </div>
      <span className="bar-value">{getCount(item).toLocaleString()}</span>
    </div>
  ));
}

function GeoIpSection({ jobId }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let live = true;
    api.getGeoip(jobId, 100)
      .then(d => live && setData(d))
      .catch(() => live && setError(true));
    return () => { live = false; };
  }, [jobId]);

  if (error || !data) return null;

  const external = data.peers.filter(p => p.scope === 'public');
  if (external.length === 0) return null;

  const dbActive = data.status.city_db || data.status.asn_db;

  return (
    <div className="ov-section">
      <div className="ov-section-title">
        External Hosts
        <span className="ov-section-sub">{data.external_count} public IPs</span>
      </div>
      {!dbActive && (
        <div className="ov-geo-note">
          Showing external IPs. Add MaxMind GeoLite2 databases to see country and network (ASN) details.
        </div>
      )}
      <div className="ov-list">
        {external.slice(0, 15).map((p, i) => (
          <div key={i} className="ov-list-item ov-geo-row">
            <span className="ov-list-label col-ip">{p.ip}</span>
            <span className="ov-geo-meta">
              {p.country && <span className="ov-geo-country">{p.country}</span>}
              {p.org && <span className="ov-geo-org">AS{p.asn} {p.org}</span>}
            </span>
            <span className="ov-list-count">{p.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function OverviewView({
  jobId, stats, pcapName, timings, aiSummary, aiLoading,
  onOpenConnections, onOpenProtocols,
}) {
  if (!stats) return null;

  return (
    <div className="view-scroll">
      <div className="view-content">

        <div className="view-header">
          <div>
            <h2>Traffic Overview</h2>
            {pcapName && <div className="ov-pcap-name">{pcapName}</div>}
            {timings?.total != null && (
              <div className="ov-processing-timer">
                Processed in {timings.total}s
                {timings.zeek != null && ` (Zeek ${timings.zeek}s, indexing ${timings.rag_index ?? 0}s)`}
              </div>
            )}
          </div>
        </div>

        {/* Stat cards — Connections and DNS jump to their detail views */}
        <div className="ov-stats-row">
          {[
            { value: stats.total_connections.toLocaleString(), label: 'Connections', color: '#58a6ff',
              onClick: onOpenConnections ? () => onOpenConnections({}) : null, hint: 'Browse all connections' },
            { value: stats.unique_src_ips,                     label: 'Source IPs',  color: '#bc8cff' },
            { value: stats.unique_dst_ips,                     label: 'Dest. IPs',   color: '#e3b341' },
            { value: stats.total_dns.toLocaleString(),         label: 'DNS Events',  color: '#3fb950',
              onClick: onOpenProtocols || null, hint: 'Inspect DNS queries' },
            ...(stats.total_weird > 0 ? [{ value: stats.total_weird, label: 'Weird Events', color: '#f85149' }] : []),
          ].map(({ value, label, color, onClick, hint }) => (
            <div
              key={label}
              className={`ov-stat-card${onClick ? ' clickable' : ''}`}
              style={{ borderTopColor: color }}
              onClick={onClick || undefined}
              title={onClick ? hint : undefined}
            >
              <div className="ov-stat-value" style={{ color }}>{value}</div>
              <div className="ov-stat-label">{label}</div>
            </div>
          ))}
        </div>

        {stats.top_services.length > 0 && (
          <div className="ov-section">
            <div className="ov-section-title">Top Services</div>
            <BarChart
              items={stats.top_services}
              getLabel={s => s.name}
              getCount={s => s.count}
              color="#58a6ff"
            />
          </div>
        )}

        {stats.top_ports.length > 0 && (
          <div className="ov-section">
            <div className="ov-section-title">Top Destination Ports</div>
            <BarChart
              items={stats.top_ports}
              getLabel={p => (
                <>
                  <span className="bar-port">:{p.port}</span>
                  {p.service !== 'unknown' && <span className="bar-service">{p.service}</span>}
                </>
              )}
              getCount={p => p.count}
              color="#bc8cff"
              onRowClick={onOpenConnections ? p => onOpenConnections({ dst_port: p.port }) : undefined}
              rowTitle="View these connections"
            />
          </div>
        )}

        {stats.connection_states.length > 0 && (
          <div className="ov-section">
            <div className="ov-section-title">Connection States</div>
            <BarChart
              items={stats.connection_states}
              getLabel={s => (
                <>
                  <span className="bar-state" style={{ color: STATE_COLORS[s.state] || '#8b949e' }}>{s.state}</span>
                  {STATE_LABELS[s.state] && <span className="bar-state-desc">{STATE_LABELS[s.state]}</span>}
                </>
              )}
              getCount={s => s.count}
              getBarColor={s => STATE_COLORS[s.state] || '#8b949e'}
              onRowClick={onOpenConnections ? s => onOpenConnections({ conn_state: s.state }) : undefined}
              rowTitle="View connections in this state"
            />
          </div>
        )}

        {(stats.dns_queries.length > 0 || stats.weird_events.length > 0) && (
          <div className="ov-two-col">
            {stats.dns_queries.length > 0 && (
              <div className="ov-section ov-col">
                <div className="ov-section-title">Top DNS Queries</div>
                <div className="ov-list">
                  {stats.dns_queries.map((q, i) => (
                    <div key={i} className="ov-list-item">
                      <span className="ov-list-label">{q.query}</span>
                      <span className="ov-list-count">{q.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {stats.weird_events.length > 0 && (
              <div className="ov-section ov-col">
                <div className="ov-section-title">Weird Events</div>
                <div className="ov-list">
                  {stats.weird_events.map((w, i) => (
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

        {jobId && <GeoIpSection jobId={jobId} />}

        <div className="ov-section">
          <div className="ov-section-title">AI Analysis & Next Steps</div>
          <div className="ov-ai-box">
            {aiLoading && !aiSummary
              ? <div className="system-text loading-text">Consulting PacketIQ AI<span className="dots" /></div>
              : <div className="ov-ai-content markdown"><ReactMarkdown>{aiSummary}</ReactMarkdown></div>
            }
          </div>
        </div>

      </div>
    </div>
  );
}
