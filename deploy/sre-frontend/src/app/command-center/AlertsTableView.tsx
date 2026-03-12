'use client';

import { useState, useMemo, useEffect } from 'react';
import { Alert } from '@/lib/types';
import {
  parseAIEnrichment,
  severityBg,
  timeAgo,
  alertStartTime,
  getSourceLabel,
} from '@/lib/keep-api';

type SortField = 'severity' | 'name' | 'host' | 'noise' | 'time';
type SortDir = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, warning: 2, low: 3, info: 4, unknown: 5,
};

export interface AlertsTableViewProps {
  alerts: Alert[];
  loading: boolean;
  onAlertClick: (alert: Alert) => void;
}

export default function AlertsTableView({ alerts, loading, onAlertClick }: AlertsTableViewProps) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('active');
  const [sortField, setSortField] = useState<SortField>('time');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [pageSize, setPageSize] = useState(25);
  const [currentPage, setCurrentPage] = useState(0);

  const enrichedAlerts = useMemo(() => {
    return alerts.map(a => ({
      alert: a,
      enrichment: parseAIEnrichment(a.note),
    }));
  }, [alerts]);

  const filtered = useMemo(() => {
    return enrichedAlerts
      .filter(({ alert, enrichment }) => {
        // Status filter
        if (statusFilter === 'active' && (alert.status === 'resolved' || alert.status === 'ok')) return false;
        if (statusFilter === 'resolved' && alert.status !== 'resolved' && alert.status !== 'ok') return false;

        // Severity filter
        if (sevFilter !== 'all') {
          const sev = enrichment?.assessed_severity ?? 'unknown';
          if (sev !== sevFilter) return false;
        }

        // Search
        if (search) {
          const q = search.toLowerCase();
          const name = (alert.name || '').toLowerCase();
          const host = (alert.hostName || alert.hostname || '').toLowerCase();
          const summary = (enrichment?.summary || '').toLowerCase();
          if (!name.includes(q) && !host.includes(q) && !summary.includes(q)) return false;
        }

        return true;
      })
      .sort((a, b) => {
        let cmp = 0;
        switch (sortField) {
          case 'severity': {
            const sa = SEVERITY_ORDER[a.enrichment?.assessed_severity ?? 'unknown'] ?? 5;
            const sb = SEVERITY_ORDER[b.enrichment?.assessed_severity ?? 'unknown'] ?? 5;
            cmp = sa - sb;
            break;
          }
          case 'name':
            cmp = (a.alert.name || '').localeCompare(b.alert.name || '');
            break;
          case 'host': {
            const ha = a.alert.hostName || a.alert.hostname || '';
            const hb = b.alert.hostName || b.alert.hostname || '';
            cmp = ha.localeCompare(hb);
            break;
          }
          case 'noise':
            cmp = (a.enrichment?.noise_score ?? 5) - (b.enrichment?.noise_score ?? 5);
            break;
          case 'time':
            cmp = (alertStartTime(a.alert) || '').localeCompare(alertStartTime(b.alert) || '');
            break;
        }
        return sortDir === 'desc' ? -cmp : cmp;
      });
  }, [enrichedAlerts, search, sevFilter, statusFilter, sortField, sortDir]);

  const totalPages = pageSize === 0 ? 1 : Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(currentPage, totalPages - 1);
  const paginatedAlerts = pageSize === 0
    ? filtered
    : filtered.slice(safePage * pageSize, (safePage + 1) * pageSize);

  // Reset to page 0 when filters or page size change
  useEffect(() => { setCurrentPage(0); }, [search, sevFilter, statusFilter, pageSize]);

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  }

  const sortIndicator = (field: SortField) =>
    sortField === field ? (sortDir === 'asc' ? ' \u25B2' : ' \u25BC') : '';

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted animate-pulse">Loading alerts...</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <input
          type="text"
          placeholder="Search alerts..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-surface border border-border rounded-md px-3 py-1.5 text-sm text-text placeholder-muted focus:outline-none focus:border-accent w-64"
        />
        <select
          value={sevFilter}
          onChange={e => setSevFilter(e.target.value)}
          className="bg-surface border border-border rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="warning">Warning</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
          className="bg-surface border border-border rounded-md px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
        >
          <option value="active">Active</option>
          <option value="resolved">Resolved</option>
          <option value="all">All</option>
        </select>
        <span className="text-xs text-muted ml-auto">{filtered.length} alerts</span>
      </div>

      {/* Table */}
      <div className="stat-card overflow-hidden">
        <div className="overflow-x-auto -mx-5">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="table-header cursor-pointer select-none" onClick={() => toggleSort('severity')}>
                  Severity{sortIndicator('severity')}
                </th>
                <th className="table-header cursor-pointer select-none" onClick={() => toggleSort('name')}>
                  Alert{sortIndicator('name')}
                </th>
                <th className="table-header cursor-pointer select-none" onClick={() => toggleSort('host')}>
                  Host{sortIndicator('host')}
                </th>
                <th className="table-header">Source</th>
                <th className="table-header cursor-pointer select-none" onClick={() => toggleSort('noise')}>
                  Noise{sortIndicator('noise')}
                </th>
                <th className="table-header">AI Summary</th>
                <th className="table-header cursor-pointer select-none" onClick={() => toggleSort('time')}>
                  Time{sortIndicator('time')}
                </th>
              </tr>
            </thead>
            <tbody>
              {paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="table-cell text-center text-muted py-8">
                    No matching alerts
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map(({ alert, enrichment }) => {
                  const sev = enrichment?.assessed_severity ?? 'unknown';
                  const host = alert.hostName || alert.hostname || '';
                  const source = getSourceLabel(alert);

                  return (
                    <tr
                      key={alert.fingerprint || alert.id}
                      className="border-b border-border/50 hover:bg-surface-hover transition-colors cursor-pointer"
                      onClick={() => onAlertClick(alert)}
                    >
                      <td className="table-cell">
                        <span className={`badge ${severityBg(sev)}`}>{sev}</span>
                      </td>
                      <td className="table-cell">
                        <span className="text-text-bright hover:text-accent transition-colors">
                          {(alert.name || 'Unknown').substring(0, 50)}
                          {(alert.name?.length ?? 0) > 50 ? '...' : ''}
                        </span>
                        {alert.description && alert.description !== alert.name && (
                          <div className="text-xs text-muted mt-0.5 truncate max-w-xs font-mono">
                            {alert.description.substring(0, 80)}
                            {(alert.description?.length ?? 0) > 80 ? '...' : ''}
                          </div>
                        )}
                      </td>
                      <td className="table-cell text-xs text-muted font-mono">{host}</td>
                      <td className="table-cell text-xs text-muted">{source}</td>
                      <td className="table-cell">
                        {enrichment ? (
                          <div className="flex items-center gap-2">
                            <div className="w-10 bg-border rounded-full h-1.5">
                              <div
                                className={`h-1.5 rounded-full ${enrichment.noise_score >= 7 ? 'bg-muted' : enrichment.noise_score >= 4 ? 'bg-yellow' : 'bg-green'}`}
                                style={{ width: `${enrichment.noise_score * 10}%` }}
                              />
                            </div>
                            <span className="text-xs text-muted font-mono">{enrichment.noise_score}</span>
                          </div>
                        ) : (
                          <span className="text-xs text-muted">--</span>
                        )}
                      </td>
                      <td className="table-cell text-xs text-muted max-w-xs truncate">
                        {enrichment?.summary || '--'}
                      </td>
                      <td className="table-cell text-xs text-muted whitespace-nowrap">
                        {timeAgo(alertStartTime(alert))}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
          <div className="flex items-center gap-3">
            <span className="text-xs text-muted">
              {pageSize === 0
                ? `Showing all ${filtered.length} alerts`
                : filtered.length > 0
                  ? `Showing ${safePage * pageSize + 1}\u2013${Math.min((safePage + 1) * pageSize, filtered.length)} of ${filtered.length}`
                  : 'No alerts'}
            </span>
            <select
              value={pageSize}
              onChange={e => setPageSize(Number(e.target.value))}
              className="bg-surface border border-border rounded px-2 py-1 text-xs text-muted focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value={25}>25 per page</option>
              <option value={50}>50 per page</option>
              <option value={100}>100 per page</option>
              <option value={0}>All</option>
            </select>
          </div>
          {pageSize > 0 && totalPages > 1 && (
            <div className="flex items-center gap-1">
              <button
                onClick={() => setCurrentPage(p => Math.max(0, p - 1))}
                disabled={safePage === 0}
                className="px-2 py-1 text-xs text-muted hover:text-text hover:bg-surface-hover rounded transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
              >
                &lsaquo; Prev
              </button>
              {paginationRange(safePage, totalPages).map((p, i) =>
                p === -1 ? (
                  <span key={`ellipsis-${i}`} className="px-1 text-xs text-muted">&hellip;</span>
                ) : (
                  <button
                    key={p}
                    onClick={() => setCurrentPage(p)}
                    className={`w-7 h-7 rounded text-xs font-medium transition-colors ${
                      p === safePage
                        ? 'bg-accent text-bg'
                        : 'text-muted hover:text-text hover:bg-surface-hover'
                    }`}
                  >
                    {p + 1}
                  </button>
                )
              )}
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={safePage >= totalPages - 1}
                className="px-2 py-1 text-xs text-muted hover:text-text hover:bg-surface-hover rounded transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
              >
                Next &rsaquo;
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function paginationRange(current: number, total: number): number[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i);
  const pages: number[] = [];
  pages.push(0);
  if (current > 2) pages.push(-1);
  for (let i = Math.max(1, current - 1); i <= Math.min(total - 2, current + 1); i++) {
    pages.push(i);
  }
  if (current < total - 3) pages.push(-1);
  pages.push(total - 1);
  return pages;
}
