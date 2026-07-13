import React, { useState, useEffect, useCallback } from 'react';

const PAGE_SIZE = 100;

// Generic paged table. `fetchPage({ limit, offset })` must resolve to
// { total, <rowsKey>: [...] }. `columns` is [{ key, label, render?, className? }].
export default function PagedTable({ fetchPage, rowsKey, columns, deps = [], emptyText = 'No records.' }) {
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(async (nextOffset) => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchPage({ limit: PAGE_SIZE, offset: nextOffset });
      setRows(data[rowsKey] || []);
      setTotal(data.total || 0);
      setOffset(nextOffset);
    } catch (err) {
      setError(err.message);
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [fetchPage, rowsKey]);

  // Reload from the first page whenever the query (deps) changes.
  useEffect(() => { load(0); }, deps); // eslint-disable-line react-hooks/exhaustive-deps

  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE_SIZE, total);
  const canPrev = offset > 0;
  const canNext = offset + PAGE_SIZE < total;

  return (
    <div className="table-wrap">
      <div className="table-toolbar">
        <span className="table-count">
          {loading ? 'Loading…' : `${from.toLocaleString()}–${to.toLocaleString()} of ${total.toLocaleString()}`}
        </span>
        <div className="table-pager">
          <button disabled={!canPrev || loading} onClick={() => load(offset - PAGE_SIZE)}>‹ Prev</button>
          <button disabled={!canNext || loading} onClick={() => load(offset + PAGE_SIZE)}>Next ›</button>
        </div>
      </div>

      {error ? (
        <div className="table-empty">Error: {error}</div>
      ) : rows.length === 0 && !loading ? (
        <div className="table-empty">{emptyText}</div>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>{columns.map(c => <th key={c.key} className={c.className}>{c.label}</th>)}</tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={i}>
                  {columns.map(c => (
                    <td key={c.key} className={c.className}>
                      {c.render ? c.render(row[c.key], row) : (row[c.key] ?? '—')}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
