import React, { useState, useCallback } from 'react';
import * as api from '../api';
import PagedTable from './PagedTable';

const time = v => (v ? new Date(v).toLocaleTimeString() : '—');

// TLS versions considered weak/legacy — highlighted red.
const WEAK_TLS = /^(SSLv|TLSv10|TLSv11)/i;

const PROTOCOLS = {
  dns: {
    label: 'DNS',
    rowsKey: 'dns',
    placeholder: 'Search domain or answer…',
    empty: 'No DNS events in this capture.',
    columns: [
      { key: 'ts', label: 'Time', render: time, className: 'col-time' },
      { key: 'src_ip', label: 'Client', className: 'col-ip' },
      { key: 'query', label: 'Query', render: v => v || '—' },
      { key: 'qtype', label: 'Type', className: 'col-narrow' },
      { key: 'rcode', label: 'RCode', className: 'col-narrow' },
      { key: 'answers', label: 'Answers', render: v => v || '—' },
    ],
  },
  http: {
    label: 'HTTP',
    rowsKey: 'http',
    placeholder: 'Search host, URI, or user-agent…',
    empty: 'No HTTP events in this capture.',
    columns: [
      { key: 'ts', label: 'Time', render: time, className: 'col-time' },
      { key: 'src_ip', label: 'Client', className: 'col-ip' },
      { key: 'method', label: 'Method', className: 'col-narrow' },
      { key: 'host', label: 'Host', render: v => v || '—' },
      { key: 'uri', label: 'URI', render: v => v || '—' },
      {
        key: 'status_code', label: 'Status', className: 'col-narrow',
        render: v => <span style={{ color: v >= 400 ? '#f85149' : v >= 300 ? '#e3b341' : '#3fb950' }}>{v ?? '—'}</span>,
      },
      { key: 'user_agent', label: 'User-Agent', render: v => v || '—' },
    ],
  },
  tls: {
    label: 'TLS',
    rowsKey: 'tls',
    placeholder: 'Search SNI, version, or cipher…',
    empty: 'No TLS events in this capture.',
    columns: [
      { key: 'ts', label: 'Time', render: time, className: 'col-time' },
      { key: 'src_ip', label: 'Client', className: 'col-ip' },
      { key: 'dst_ip', label: 'Server', className: 'col-ip' },
      { key: 'server_name', label: 'SNI', render: v => v || '—' },
      {
        key: 'version', label: 'Version', className: 'col-narrow',
        render: v => (v ? <span style={{ color: WEAK_TLS.test(v) ? '#f85149' : 'inherit', fontWeight: WEAK_TLS.test(v) ? 600 : 400 }}>{v}</span> : '—'),
      },
      { key: 'cipher', label: 'Cipher', render: v => v || '—' },
    ],
  },
};

function ProtocolTable({ jobId, protocol }) {
  const [draft, setDraft] = useState('');
  const [search, setSearch] = useState('');
  const cfg = PROTOCOLS[protocol];

  const fetchPage = useCallback(
    ({ limit, offset }) => api.getProtocolEvents(jobId, protocol, { search, limit, offset }),
    [jobId, protocol, search],
  );

  return (
    <>
      <div className="filter-bar">
        <input
          placeholder={cfg.placeholder}
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && setSearch(draft)}
          className="filter-grow"
        />
        <button className="filter-apply" onClick={() => setSearch(draft)}>Search</button>
        <button className="filter-reset" onClick={() => { setDraft(''); setSearch(''); }}>Clear</button>
      </div>

      <PagedTable
        fetchPage={fetchPage}
        rowsKey={cfg.rowsKey}
        columns={cfg.columns}
        deps={[jobId, protocol, search]}
        emptyText={cfg.empty}
      />
    </>
  );
}

export default function ProtocolsView({ jobId }) {
  const [protocol, setProtocol] = useState('dns');

  return (
    <div className="view-scroll">
      <div className="view-content">
        <div className="view-header"><h2>Protocol Detail</h2></div>

        <div className="sub-tabs">
          {Object.entries(PROTOCOLS).map(([key, cfg]) => (
            <button
              key={key}
              className={`sub-tab${protocol === key ? ' active' : ''}`}
              onClick={() => setProtocol(key)}
            >
              {cfg.label}
            </button>
          ))}
        </div>

        <ProtocolTable jobId={jobId} protocol={protocol} />
      </div>
    </div>
  );
}
