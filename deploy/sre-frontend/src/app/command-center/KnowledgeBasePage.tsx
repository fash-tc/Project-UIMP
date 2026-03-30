'use client';

import { useState, useEffect, useCallback } from 'react';
import { SREFeedbackEntry, RunbookExclusion, RunbookEntry, PaginatedResponse } from '@/lib/types';
import {
  fetchAllSREFeedback,
  updateSREFeedback,
  deleteSREFeedback,
  bulkDeleteSREFeedback,
  fetchAllRunbookExclusions,
  deleteRunbookExclusion,
  deleteRunbookEntry,
  severityColor,
  timeAgo,
} from '@/lib/keep-api';

const RUNBOOK_BASE = '/api/runbook';

type SubTab = 'feedback' | 'runbooks' | 'exclusions';

export default function KnowledgeBasePage() {
  const [activeTab, setActiveTab] = useState<SubTab>('feedback');

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4 border-b border-border pb-3">
        <h2 className="text-lg font-semibold text-text-bright">Knowledge Base</h2>
        <div className="flex gap-1 ml-4">
          {[
            { key: 'feedback' as SubTab, label: 'SRE Feedback' },
            { key: 'runbooks' as SubTab, label: 'Runbook Entries' },
            { key: 'exclusions' as SubTab, label: 'Exclusion Rules' },
          ].map(tab => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                activeTab === tab.key
                  ? 'bg-accent/10 text-accent border border-accent/30'
                  : 'text-muted hover:text-text border border-transparent'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'feedback' && <FeedbackTab />}
      {activeTab === 'runbooks' && <RunbookTab />}
      {activeTab === 'exclusions' && <ExclusionsTab />}
    </div>
  );
}

/* ── SRE Feedback Tab ── */

function FeedbackTab() {
  const [data, setData] = useState<PaginatedResponse<SREFeedbackEntry>>({ items: [], total: 0, page: 1, limit: 50 });
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [ratingFilter, setRatingFilter] = useState('');
  const [sort, setSort] = useState('date');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editComment, setEditComment] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    fetchAllSREFeedback({ page, limit: 50, search, rating: ratingFilter, sort })
      .then(setData)
      .finally(() => setLoading(false));
  }, [page, search, ratingFilter, sort]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [search, ratingFilter, sort]);

  const toggleSelect = (id: number) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selected.size === data.items.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(data.items.map(i => i.id)));
    }
  };

  async function handleBulkDelete() {
    if (!confirm(`Delete ${selected.size} feedback entries?`)) return;
    const ok = await bulkDeleteSREFeedback(Array.from(selected));
    if (ok) { setSelected(new Set()); load(); }
  }

  async function handleDelete(id: number) {
    if (!confirm('Delete this feedback entry?')) return;
    const ok = await deleteSREFeedback(id);
    if (ok) load();
  }

  async function handleEditSave(id: number) {
    const ok = await updateSREFeedback(id, { comment: editComment });
    if (ok) { setEditingId(null); load(); }
  }

  const totalPages = Math.max(1, Math.ceil(data.total / 50));

  const ratingBadge = (r: string) => {
    if (r === 'positive') return <span className="px-1.5 py-0.5 rounded text-[10px] bg-green/10 border border-green/30 text-green">Accurate</span>;
    if (r === 'correction') return <span className="px-1.5 py-0.5 rounded text-[10px] bg-orange/10 border border-orange/30 text-orange">Correction</span>;
    return <span className="px-1.5 py-0.5 rounded text-[10px] bg-red/10 border border-red/30 text-red">Needs Fix</span>;
  };

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="text"
          placeholder="Search by alert name or comment..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-surface border border-border rounded-md px-3 py-1.5 text-sm text-text placeholder-muted focus:outline-none focus:border-accent w-72"
        />
        <select value={ratingFilter} onChange={e => setRatingFilter(e.target.value)}
          className="bg-surface border border-border rounded-md px-3 py-1.5 text-sm text-text">
          <option value="">All Ratings</option>
          <option value="positive">Accurate</option>
          <option value="negative">Needs Fix</option>
          <option value="correction">Correction</option>
        </select>
        <select value={sort} onChange={e => setSort(e.target.value)}
          className="bg-surface border border-border rounded-md px-3 py-1.5 text-sm text-text">
          <option value="date">Newest First</option>
          <option value="score">Highest Voted</option>
        </select>
        {selected.size > 0 && (
          <button onClick={handleBulkDelete}
            className="px-3 py-1.5 rounded-md border border-red/50 text-red text-xs font-medium hover:bg-red/10 transition-colors">
            Delete Selected ({selected.size})
          </button>
        )}
        <span className="text-xs text-muted ml-auto">{data.total} entries</span>
      </div>

      {/* Table */}
      <div className="stat-card overflow-hidden">
        <div className="overflow-x-auto -mx-5">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="table-header w-8">
                  <input type="checkbox" checked={selected.size === data.items.length && data.items.length > 0}
                    onChange={toggleSelectAll} className="rounded" />
                </th>
                <th className="table-header">Alert Name</th>
                <th className="table-header">User</th>
                <th className="table-header">Rating</th>
                <th className="table-header">Corrections</th>
                <th className="table-header">Comment</th>
                <th className="table-header">Votes</th>
                <th className="table-header">Date</th>
                <th className="table-header w-16">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} className="table-cell text-center text-muted py-8 animate-pulse">Loading...</td></tr>
              ) : data.items.length === 0 ? (
                <tr><td colSpan={9} className="table-cell text-center text-muted py-8">No feedback entries found</td></tr>
              ) : data.items.map(entry => (
                <tr key={entry.id} className="border-b border-border/50 hover:bg-surface-hover transition-colors">
                  <td className="table-cell">
                    <input type="checkbox" checked={selected.has(entry.id)}
                      onChange={() => toggleSelect(entry.id)} className="rounded" />
                  </td>
                  <td className="table-cell">
                    <button onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                      className="text-xs text-text-bright hover:text-accent transition-colors text-left">
                      {entry.alert_name?.substring(0, 40)}{(entry.alert_name?.length ?? 0) > 40 ? '...' : ''}
                    </button>
                  </td>
                  <td className="table-cell text-xs text-muted">{entry.user}</td>
                  <td className="table-cell">{ratingBadge(entry.rating)}</td>
                  <td className="table-cell text-xs text-muted">
                    {entry.corrected_severity && <span className={severityColor(entry.corrected_severity)}>sev: {entry.corrected_severity}</span>}
                    {entry.corrected_severity && entry.corrected_noise != null && ' | '}
                    {entry.corrected_noise != null && <span>noise: {entry.corrected_noise}/10</span>}
                    {!entry.corrected_severity && entry.corrected_noise == null && '—'}
                  </td>
                  <td className="table-cell text-xs text-muted max-w-[200px] truncate">
                    {editingId === entry.id ? (
                      <div className="flex gap-1">
                        <input value={editComment} onChange={e => setEditComment(e.target.value)}
                          className="bg-surface border border-border rounded px-1.5 py-0.5 text-xs w-full" />
                        <button onClick={() => handleEditSave(entry.id)}
                          className="text-green text-[10px] whitespace-nowrap">Save</button>
                        <button onClick={() => setEditingId(null)}
                          className="text-muted text-[10px]">Cancel</button>
                      </div>
                    ) : (
                      entry.comment?.substring(0, 60) || '—'
                    )}
                  </td>
                  <td className="table-cell">
                    <span className={`text-xs font-mono ${
                      entry.vote_score > 0 ? 'text-green' : entry.vote_score < 0 ? 'text-red' : 'text-muted'
                    }`}>
                      {entry.vote_score > 0 ? `+${entry.vote_score}` : entry.vote_score}
                    </span>
                  </td>
                  <td className="table-cell text-xs text-muted">{timeAgo(entry.created_at)}</td>
                  <td className="table-cell">
                    <div className="flex gap-1">
                      <button onClick={() => { setEditingId(entry.id); setEditComment(entry.comment || ''); }}
                        className="text-muted/50 hover:text-accent transition-colors" title="Edit">
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>
                      <button onClick={() => handleDelete(entry.id)}
                        className="text-muted/50 hover:text-red transition-colors" title="Delete">
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Expanded detail */}
      {expandedId && (() => {
        const entry = data.items.find(e => e.id === expandedId);
        if (!entry) return null;
        return (
          <div className="stat-card border-accent/20">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-medium text-accent">{entry.alert_name}</h4>
              <a href={`/portal/alerts/${entry.alert_fingerprint}`} target="_blank" rel="noopener noreferrer"
                className="text-[10px] text-accent hover:text-accent-hover">View Alert &rarr;</a>
            </div>
            <div className="text-xs text-text whitespace-pre-wrap">{entry.comment || 'No comment'}</div>
            <div className="text-[10px] text-muted mt-2">
              by {entry.user} | {entry.created_at?.substring(0, 16).replace('T', ' ')} | Fingerprint: {entry.alert_fingerprint?.substring(0, 16)}...
            </div>
          </div>
        );
      })()}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
            className="px-2 py-1 rounded border border-border text-xs text-muted hover:text-text disabled:opacity-30">Prev</button>
          <span className="text-xs text-muted">Page {page} of {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
            className="px-2 py-1 rounded border border-border text-xs text-muted hover:text-text disabled:opacity-30">Next</button>
        </div>
      )}
    </div>
  );
}

/* ── Runbook Entries Tab ── */

function RunbookTab() {
  const [entries, setEntries] = useState<RunbookEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const qs = new URLSearchParams();
    qs.set('page', String(page));
    qs.set('limit', '50');
    if (search) qs.set('search', search);
    fetch(`${RUNBOOK_BASE}/entries?${qs.toString()}`)
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          // Old API returns array
          setEntries(data);
          setTotal(data.length);
        } else {
          // New paginated API
          setEntries(data.items || []);
          setTotal(data.total || 0);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [page, search]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [search]);

  const toggleSelect = (id: number) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  async function handleDelete(id: number) {
    if (!confirm('Delete this runbook entry permanently?')) return;
    const ok = await deleteRunbookEntry(id);
    if (ok) load();
  }

  async function handleBulkDelete() {
    if (!confirm(`Delete ${selected.size} runbook entries?`)) return;
    const results = await Promise.all(Array.from(selected).map(id => deleteRunbookEntry(id)));
    if (results.some(ok => ok)) { setSelected(new Set()); load(); }
  }

  const totalPages = Math.max(1, Math.ceil(total / 50));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="text"
          placeholder="Search by alert name, hostname, or remediation..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-surface border border-border rounded-md px-3 py-1.5 text-sm text-text placeholder-muted focus:outline-none focus:border-accent w-80"
        />
        {selected.size > 0 && (
          <button onClick={handleBulkDelete}
            className="px-3 py-1.5 rounded-md border border-red/50 text-red text-xs font-medium hover:bg-red/10 transition-colors">
            Delete Selected ({selected.size})
          </button>
        )}
        <span className="text-xs text-muted ml-auto">{total} entries</span>
      </div>

      <div className="stat-card overflow-hidden">
        <div className="overflow-x-auto -mx-5">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="table-header w-8">
                  <input type="checkbox" checked={selected.size === entries.length && entries.length > 0}
                    onChange={() => {
                      if (selected.size === entries.length) setSelected(new Set());
                      else setSelected(new Set(entries.map(e => e.id).filter((id): id is number => id != null)));
                    }} className="rounded" />
                </th>
                <th className="table-header">Alert Name</th>
                <th className="table-header">Hostname</th>
                <th className="table-header">Service</th>
                <th className="table-header">Remediation</th>
                <th className="table-header">Author</th>
                <th className="table-header">Date</th>
                <th className="table-header w-12">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="table-cell text-center text-muted py-8 animate-pulse">Loading...</td></tr>
              ) : entries.length === 0 ? (
                <tr><td colSpan={8} className="table-cell text-center text-muted py-8">No runbook entries found</td></tr>
              ) : entries.map(entry => (
                <tr key={entry.id} className="border-b border-border/50 hover:bg-surface-hover transition-colors">
                  <td className="table-cell">
                    {entry.id != null && <input type="checkbox" checked={selected.has(entry.id)}
                      onChange={() => toggleSelect(entry.id!)} className="rounded" />}
                  </td>
                  <td className="table-cell text-xs text-text-bright max-w-[200px] truncate">
                    <button onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id ?? null)}
                      className="hover:text-accent transition-colors text-left">
                      {entry.alert_name?.substring(0, 45)}{(entry.alert_name?.length ?? 0) > 45 ? '...' : ''}
                    </button>
                  </td>
                  <td className="table-cell text-xs text-muted font-mono">{entry.hostname || '—'}</td>
                  <td className="table-cell text-xs text-muted">{entry.service || '—'}</td>
                  <td className="table-cell text-xs text-muted max-w-[250px] truncate">{entry.remediation?.substring(0, 80)}</td>
                  <td className="table-cell text-xs text-muted">{entry.sre_user || '—'}</td>
                  <td className="table-cell text-xs text-muted">{entry.created_at ? timeAgo(entry.created_at) : '—'}</td>
                  <td className="table-cell">
                    <button onClick={() => entry.id != null && handleDelete(entry.id)}
                      className="text-muted/50 hover:text-red transition-colors" title="Delete">
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {expandedId && (() => {
        const entry = entries.find(e => e.id === expandedId);
        if (!entry) return null;
        return (
          <div className="stat-card border-accent/20">
            <h4 className="text-xs font-medium text-accent mb-2">{entry.alert_name}</h4>
            <div className="text-xs text-text whitespace-pre-wrap">{entry.remediation}</div>
            <div className="text-[10px] text-muted mt-2">
              by {entry.sre_user || 'unknown'} | {entry.created_at?.substring(0, 16).replace('T', ' ')}
              {entry.hostname && ` | Host: ${entry.hostname}`}
              {entry.service && ` | Service: ${entry.service}`}
            </div>
          </div>
        );
      })()}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
            className="px-2 py-1 rounded border border-border text-xs text-muted hover:text-text disabled:opacity-30">Prev</button>
          <span className="text-xs text-muted">Page {page} of {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
            className="px-2 py-1 rounded border border-border text-xs text-muted hover:text-text disabled:opacity-30">Next</button>
        </div>
      )}
    </div>
  );
}

/* ── Exclusion Rules Tab ── */

function ExclusionsTab() {
  const [data, setData] = useState<PaginatedResponse<RunbookExclusion>>({ items: [], total: 0, page: 1, limit: 50 });
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);

  const load = useCallback(() => {
    setLoading(true);
    fetchAllRunbookExclusions({ page, limit: 50, search })
      .then(setData)
      .finally(() => setLoading(false));
  }, [page, search]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPage(1); }, [search]);

  async function handleRemove(id: number) {
    if (!confirm('Remove this exclusion? The runbook will appear for this alert type again.')) return;
    const ok = await deleteRunbookExclusion(id);
    if (ok) load();
  }

  const totalPages = Math.max(1, Math.ceil(data.total / 50));

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="text"
          placeholder="Search by alert name..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-surface border border-border rounded-md px-3 py-1.5 text-sm text-text placeholder-muted focus:outline-none focus:border-accent w-72"
        />
        <span className="text-xs text-muted ml-auto">{data.total} exclusions</span>
      </div>

      <div className="stat-card overflow-hidden">
        <div className="overflow-x-auto -mx-5">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="table-header">Alert Name</th>
                <th className="table-header">Runbook Entry ID</th>
                <th className="table-header">Excluded By</th>
                <th className="table-header">Date</th>
                <th className="table-header w-16">Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5} className="table-cell text-center text-muted py-8 animate-pulse">Loading...</td></tr>
              ) : data.items.length === 0 ? (
                <tr><td colSpan={5} className="table-cell text-center text-muted py-8">No exclusion rules</td></tr>
              ) : data.items.map(excl => (
                <tr key={excl.id} className="border-b border-border/50 hover:bg-surface-hover transition-colors">
                  <td className="table-cell text-xs text-text-bright">{excl.alert_name}</td>
                  <td className="table-cell text-xs text-muted font-mono">#{excl.runbook_entry_id}</td>
                  <td className="table-cell text-xs text-muted">{excl.excluded_by}</td>
                  <td className="table-cell text-xs text-muted">{timeAgo(excl.created_at)}</td>
                  <td className="table-cell">
                    <button onClick={() => handleRemove(excl.id)}
                      className="text-xs text-muted hover:text-accent transition-colors">
                      Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1}
            className="px-2 py-1 rounded border border-border text-xs text-muted hover:text-text disabled:opacity-30">Prev</button>
          <span className="text-xs text-muted">Page {page} of {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages}
            className="px-2 py-1 rounded border border-border text-xs text-muted hover:text-text disabled:opacity-30">Next</button>
        </div>
      )}
    </div>
  );
}
