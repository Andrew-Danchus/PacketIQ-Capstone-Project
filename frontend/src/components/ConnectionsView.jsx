import React, { useState, useCallback, useEffect } from 'react';
import * as api from '../api';
import PagedTable from './PagedTable';

const EMPTY = { src_ip: '', dst_ip: '', dst_port: '', conn_state: '' };

function describeFilters(f) {
  const parts = [];
  if (f.src_ip) parts.push(`source ${f.src_ip}`);
  if (f.dst_ip) parts.push(`destination ${f.dst_ip}`);
  if (f.dst_port) parts.push(`port ${f.dst_port}`);
  if (f.conn_state) parts.push(`state ${f.conn_state}`);
  return parts.length ? `They have the connections table filtered to ${parts.join(', ')}.` : '';
}

const STATE_COLORS = {
  SF: '#3fb950', S0: '#f85149', REJ: '#f85149', RSTO: '#e3b341',
  RSTR: '#e3b341', RSTOS0: '#f85149', RSTRH: '#e3b341', S1: '#58a6ff', OTH: '#8b949e',
};

// Plain-English explanations for Zeek's cryptic connection states.
const STATE_INFO = {
  SF: 'Normal — connection established and closed cleanly',
  S0: 'No reply — SYN sent, nothing came back',
  S1: 'Established but never terminated',
  REJ: 'Rejected — connection attempt refused',
  RSTO: 'Reset by the originator',
  RSTR: 'Reset by the responder',
  RSTOS0: 'SYN then reset by originator, no reply seen',
  RSTRH: 'Responder sent SYN-ACK then reset',
  OTH: 'Midstream — no handshake observed',
};

function formatBytes(b) {
  if (!b) return '0';
  const k = 1024, s = ['B', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(b) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(1)}${s[i]}`;
}

const COLUMNS = [
  { key: 'ts', label: 'Time', render: v => (v ? new Date(v).toLocaleTimeString() : '—'), className: 'col-time' },
  { key: 'src_ip', label: 'Source', render: (v, r) => `${v ?? '—'}:${r.src_port ?? '—'}`, className: 'col-ip' },
  { key: 'dst_ip', label: 'Destination', render: (v, r) => `${v ?? '—'}:${r.dst_port ?? '—'}`, className: 'col-ip' },
  { key: 'proto', label: 'Proto', className: 'col-narrow' },
  { key: 'service', label: 'Service', render: v => v || '—' },
  { key: 'duration', label: 'Duration', render: v => (v != null ? `${Number(v).toFixed(2)}s` : '—'), className: 'col-narrow' },
  { key: 'orig_bytes', label: 'Sent', render: formatBytes, className: 'col-narrow' },
  { key: 'resp_bytes', label: 'Recv', render: formatBytes, className: 'col-narrow' },
  {
    key: 'conn_state', label: 'State', className: 'col-narrow',
    render: v => (
      <span
        style={{ color: STATE_COLORS[v] || '#8b949e', fontWeight: 600, cursor: 'help' }}
        title={STATE_INFO[v] || ''}
      >
        {v || '—'}
      </span>
    ),
  },
];

export default function ConnectionsView({ jobId, preset, onContextChange, onAskAbout }) {
  const [draft, setDraft] = useState(EMPTY);
  const [query, setQuery] = useState(EMPTY);
  const [nlQuery, setNlQuery] = useState('');
  const [nlLoading, setNlLoading] = useState(false);
  const [nlError, setNlError] = useState('');

  const fetchPage = useCallback(
    ({ limit, offset }) => api.getConnections(jobId, { ...query, limit, offset }),
    [jobId, query],
  );

  // Filters handed in from elsewhere (a detection's "View connections",
  // a clicked Overview port, …) — applied whenever a new preset arrives.
  useEffect(() => {
    if (!preset?.nonce) return;
    const merged = {
      ...EMPTY,
      ...(preset.src_ip ? { src_ip: preset.src_ip } : {}),
      ...(preset.dst_ip ? { dst_ip: preset.dst_ip } : {}),
      ...(preset.dst_port != null ? { dst_port: String(preset.dst_port) } : {}),
      ...(preset.conn_state ? { conn_state: preset.conn_state } : {}),
    };
    setDraft(merged);
    setQuery(merged);
    setNlQuery('');
    setNlError('');
  }, [preset?.nonce]); // eslint-disable-line

  // Keep the copilot informed of the active filter so questions have context.
  useEffect(() => { onContextChange?.(describeFilters(query)); }, [query]); // eslint-disable-line
  useEffect(() => () => onContextChange?.(''), []); // eslint-disable-line

  const hasFilters = Object.values(query).some(Boolean);

  const apply = () => setQuery(draft);
  const reset = () => { setDraft(EMPTY); setQuery(EMPTY); setNlQuery(''); setNlError(''); };
  const onKey = e => e.key === 'Enter' && apply();
  const set = (k, v) => setDraft(prev => ({ ...prev, [k]: v }));

  // Natural-language search → structured filters (resolved server-side by the LLM).
  const runNlSearch = async () => {
    const q = nlQuery.trim();
    if (!q || nlLoading) return;
    setNlLoading(true);
    setNlError('');
    try {
      const { filters, dropped_ips } = await api.searchConnections(jobId, q, { limit: 1 });
      if (!filters || Object.keys(filters).length === 0) {
        const extra = dropped_ips?.length
          ? ` (ignored ${dropped_ips.join(', ')} — not seen in this capture)`
          : '';
        setNlError(`Couldn't turn that into a filter — try naming an IP, port, or state.${extra}`);
      } else {
        const merged = { ...EMPTY, ...filters, dst_port: filters.dst_port != null ? String(filters.dst_port) : '' };
        setDraft(merged);
        setQuery(merged);
        if (dropped_ips?.length) {
          setNlError(`Ignored ${dropped_ips.join(', ')} — not present in this capture.`);
        }
      }
    } catch (err) {
      setNlError(err.message);
    } finally {
      setNlLoading(false);
    }
  };

  return (
    <div className="view-scroll">
      <div className="view-content">
        <div className="view-header"><h2>Connections</h2></div>

        <div className="nl-search">
          <span className="nl-search-icon">✨</span>
          <input
            className="filter-grow"
            placeholder='Ask in plain English — e.g. "failed SSH connections from 192.168.1.70"'
            value={nlQuery}
            onChange={e => setNlQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && runNlSearch()}
          />
          <button className="filter-apply" onClick={runNlSearch} disabled={nlLoading}>
            {nlLoading ? 'Parsing…' : 'AI Search'}
          </button>
        </div>
        {nlError && <div className="nl-search-error">{nlError}</div>}

        <div className="filter-bar">
          <input placeholder="Source IP" value={draft.src_ip} onChange={e => set('src_ip', e.target.value)} onKeyDown={onKey} />
          <input placeholder="Dest IP" value={draft.dst_ip} onChange={e => set('dst_ip', e.target.value)} onKeyDown={onKey} />
          <input placeholder="Dest port" value={draft.dst_port} onChange={e => set('dst_port', e.target.value)} onKeyDown={onKey} className="filter-narrow" />
          <select value={draft.conn_state} onChange={e => set('conn_state', e.target.value)}>
            <option value="">Any state</option>
            {['SF', 'S0', 'S1', 'REJ', 'RSTO', 'RSTR', 'RSTOS0', 'OTH'].map(s => (
              <option key={s} value={s}>
                {s}{STATE_INFO[s] ? ` · ${STATE_INFO[s].split(' — ')[0]}` : ''}
              </option>
            ))}
          </select>
          <button className="filter-apply" onClick={apply}>Filter</button>
          <button className="filter-reset" onClick={reset}>Reset</button>
          {hasFilters && onAskAbout && (
            <button
              className="ask-ai-chip inline"
              onClick={() => onAskAbout('Are these connections I have filtered normal or suspicious? What stands out?')}
            >
              ✨ Ask AI about these
            </button>
          )}
        </div>

        <PagedTable
          fetchPage={fetchPage}
          rowsKey="connections"
          columns={COLUMNS}
          deps={[jobId, query]}
          emptyText="No connections match these filters."
        />
      </div>
    </div>
  );
}
