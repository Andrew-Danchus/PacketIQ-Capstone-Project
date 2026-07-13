import React, { useState, useCallback } from 'react';
import * as api from '../api';
import PagedTable from './PagedTable';

const STATE_COLORS = {
  SF: '#3fb950', S0: '#f85149', REJ: '#f85149', RSTO: '#e3b341',
  RSTR: '#e3b341', RSTOS0: '#f85149', RSTRH: '#e3b341', S1: '#58a6ff', OTH: '#8b949e',
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
    render: v => <span style={{ color: STATE_COLORS[v] || '#8b949e', fontWeight: 600 }}>{v || '—'}</span>,
  },
];

export default function ConnectionsView({ jobId }) {
  const [draft, setDraft] = useState({ src_ip: '', dst_ip: '', dst_port: '', conn_state: '' });
  const [query, setQuery] = useState(draft);

  const fetchPage = useCallback(
    ({ limit, offset }) => api.getConnections(jobId, { ...query, limit, offset }),
    [jobId, query],
  );

  const apply = () => setQuery(draft);
  const reset = () => { const empty = { src_ip: '', dst_ip: '', dst_port: '', conn_state: '' }; setDraft(empty); setQuery(empty); };
  const onKey = e => e.key === 'Enter' && apply();
  const set = (k, v) => setDraft(prev => ({ ...prev, [k]: v }));

  return (
    <div className="view-scroll">
      <div className="view-content">
        <div className="view-header"><h2>Connections</h2></div>

        <div className="filter-bar">
          <input placeholder="Source IP" value={draft.src_ip} onChange={e => set('src_ip', e.target.value)} onKeyDown={onKey} />
          <input placeholder="Dest IP" value={draft.dst_ip} onChange={e => set('dst_ip', e.target.value)} onKeyDown={onKey} />
          <input placeholder="Dest port" value={draft.dst_port} onChange={e => set('dst_port', e.target.value)} onKeyDown={onKey} className="filter-narrow" />
          <select value={draft.conn_state} onChange={e => set('conn_state', e.target.value)}>
            <option value="">Any state</option>
            {['SF', 'S0', 'S1', 'REJ', 'RSTO', 'RSTR', 'RSTOS0', 'OTH'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className="filter-apply" onClick={apply}>Filter</button>
          <button className="filter-reset" onClick={reset}>Reset</button>
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
