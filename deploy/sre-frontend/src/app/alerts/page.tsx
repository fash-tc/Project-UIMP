'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { Alert } from '@/lib/types';
import {
  fetchAlerts,
  parseAIEnrichment,
  severityColor,
  severityBg,
  timeAgo,
} from '@/lib/keep-api';

type SortField = 'severity' | 'name' | 'host' | 'noise' | 'time';
type SortDir = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, warning: 2, low: 3, info: 4, unknown: 5,
};

export default function AlertExplorer() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('active');
  const [sortField, setSortField] = useState<SortField>('time');
  const [sortDir, setSortDir] = useState<SortDir>('desc');

  const load = useCallback(async () => {
    try {
      const data = await fetchAlerts(250);
      setAlerts(data);
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

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
            cmp = (a.alert.lastReceived || '').localeCompare(b.alert.lastReceived || '');
            break;
        }
        return sortDir === 'desc' ? -cmp : cmp;
      });
  }, [enrichedAlerts, search, sevFilter, statusFilter, sortField, sortDir]);

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('desc');
    }
  }

  const sortIndicator = (field: SortField) =>
    sortField === field ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted animate-pulse">Loading alerts...</div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-bright">Alert Explorer</h1>

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
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="table-cell text-center text-muted py-8">
                    No matching alerts
                  </td>
                </tr>
              ) : (
                filtered.map(({ alert, enrichment }) => {
                  const sev = enrichment?.assessed_severity ?? 'unknown';
                  const host = alert.hostName || alert.hostname || '';
                  const source = Array.isArray(alert.source)
                    ? alert.source.join(', ')
                    : String(alert.source || '');

                  return (
                    <tr
                      key={alert.fingerprint || alert.id}
                      className="border-b border-border/50 hover:bg-surface-hover transition-colors"
                    >
                      <td className="table-cell">
                        <span className={`badge ${severityBg(sev)}`}>{sev}</span>
                      </td>
                      <td className="table-cell">
                        <a
                          href={`/portal/alerts/${alert.fingerprint}`}
                          className="text-text-bright hover:text-accent transition-colors"
                        >
                          {(alert.name || 'Unknown').substring(0, 50)}
                          {(alert.name?.length ?? 0) > 50 ? '...' : ''}
                        </a>
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
                        {timeAgo(alert.lastReceived)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
