'use client';

import { useState, useMemo, useEffect } from 'react';
import { Alert, AlertState } from '@/lib/types';
import {
  parseAIEnrichment,
  severityBg,
  severityColor,
  timeAgo,
  alertStartTime,
  getSourceLabel,
  overrideSeverity,
  forceEnrich,
  fetchAlertRules,
  AlertRule,
  matchHighlightRules,
  colorWithAlpha,
} from '@/lib/keep-api';

const ZABBIX_URLS: Record<string, string> = {
  'domains-shared': 'https://zabbix.prod-domains-shared.bra2.tucows.systems',
  'ascio': 'https://zabbix.ascio.com',
  'hostedemail': 'https://zabbix.a.tucows.com',
  'enom': 'https://zabbix.enom.net',
  'iaas': 'https://zabbix.tucows.cloud',
};

type SortField = 'severity' | 'name' | 'host' | 'noise' | 'time' | 'received';
type SortDir = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, warning: 2, low: 3, info: 4, unknown: 5,
};

export interface AlertsTableViewProps {
  alerts: Alert[];
  alertStates?: Map<string, AlertState>;
  customGroupByFingerprint?: Map<string, string>;
  selectedFingerprints: Set<string>;
  loading: boolean;
  onAlertClick: (alert: Alert) => void;
  onToggleSelectAlert: (fingerprint: string) => void;
  onSetSelectedAlerts: (fingerprints: string[], selected: boolean) => void;
}

export default function AlertsTableView({
  alerts,
  alertStates,
  customGroupByFingerprint,
  selectedFingerprints,
  loading,
  onAlertClick,
  onToggleSelectAlert,
  onSetSelectedAlerts,
}: AlertsTableViewProps) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('active');
  const [sortField, setSortField] = useState<SortField>('time');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [pageSize, setPageSize] = useState(25);
  const [currentPage, setCurrentPage] = useState(0);
  const [severityDropdown, setSeverityDropdown] = useState<string | null>(null);
  const [highlightRules, setHighlightRules] = useState<AlertRule[]>([]);
  const isResolvedView = statusFilter === 'resolved';

  useEffect(() => {
    fetchAlertRules('highlight').then(setHighlightRules);
  }, []);

  useEffect(() => {
    if (statusFilter === 'resolved') {
      setSortField('time');
      setSortDir('desc');
    } else if (sortField === 'received') {
      setSortField('time');
      setSortDir('desc');
    }
  }, [statusFilter, sortField]);

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
            cmp = (
              statusFilter === 'resolved' ? (a.alert.lastReceived || '') : (alertStartTime(a.alert) || '')
            ).localeCompare(
              statusFilter === 'resolved' ? (b.alert.lastReceived || '') : (alertStartTime(b.alert) || '')
            );
            break;
          case 'received':
            cmp = (a.alert.lastReceived || '').localeCompare(b.alert.lastReceived || '');
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
  const visibleFingerprints = paginatedAlerts.map(({ alert }) => alert.fingerprint);
  const allVisibleSelected = visibleFingerprints.length > 0 && visibleFingerprints.every(fp => selectedFingerprints.has(fp));

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
                <th className="table-header w-10">
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={(e) => onSetSelectedAlerts(visibleFingerprints, e.target.checked)}
                  />
                </th>
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
                {isResolvedView ? (
                  <>
                    <th className="table-header cursor-pointer select-none" onClick={() => toggleSort('time')}>
                      Last Received{sortIndicator('time')}
                    </th>
                    <th className="table-header">AI Summary</th>
                  </>
                ) : (
                  <>
                    <th className="table-header">AI Summary</th>
                    <th className="table-header cursor-pointer select-none" onClick={() => toggleSort('time')}>
                      Time{sortIndicator('time')}
                    </th>
                  </>
                )}
              </tr>
            </thead>
            <tbody>
              {paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="table-cell text-center text-muted py-8">
                    No matching alerts
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map(({ alert, enrichment }) => {
                  const sev = enrichment?.assessed_severity ?? 'unknown';
                  const host = alert.hostName || alert.hostname || '';
                  const source = getSourceLabel(alert);

                  const alertState = alertStates?.get(alert.fingerprint);
                  const displaySeverity = alertState?.severity_override || sev;
                  const hl = matchHighlightRules(alert, highlightRules);

                  return (
                    <tr
                      key={alert.fingerprint || alert.id}
                      className={`border-b border-border/50 hover:bg-surface-hover transition-colors cursor-pointer ${selectedFingerprints.has(alert.fingerprint) ? 'bg-accent/5' : ''}`}
                      style={hl ? (
                        hl.style === 'box'
                          ? {
                              borderLeft: `3px solid ${hl.color}`,
                              backgroundColor: colorWithAlpha(hl.color, 0.12),
                              boxShadow: `inset 0 0 0 1px ${colorWithAlpha(hl.color, 0.28)}`,
                            }
                          : { borderLeft: `3px solid ${hl.color}` }
                      ) : undefined}
                      onClick={() => onAlertClick(alert)}
                    >
                      <td className="table-cell">
                        <input
                          type="checkbox"
                          checked={selectedFingerprints.has(alert.fingerprint)}
                          onChange={(e) => {
                            e.stopPropagation();
                            onToggleSelectAlert(alert.fingerprint);
                          }}
                          onClick={(e) => e.stopPropagation()}
                        />
                      </td>
                      <td className="table-cell">
                        <div className="relative">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSeverityDropdown(severityDropdown === alert.fingerprint ? null : alert.fingerprint);
                            }}
                            className={`text-xs px-1.5 py-0.5 rounded border ${severityBg(displaySeverity)} ${severityColor(displaySeverity)} cursor-pointer hover:ring-1 hover:ring-accent/50 transition-all`}
                            title={alertState?.severity_override ? 'Overridden severity' : 'Click to override severity'}
                          >
                            {displaySeverity}
                            {alertState?.severity_override && <span className="ml-0.5 opacity-60">•</span>}
                          </button>
                          {severityDropdown === alert.fingerprint && (
                            <div className="absolute z-50 top-full mt-1 left-0 bg-surface border border-border rounded-md shadow-lg py-1 min-w-[100px]">
                              {['critical', 'high', 'warning', 'info'].map(s => (
                                <button
                                  key={s}
                                  onClick={async (e) => {
                                    e.stopPropagation();
                                    await overrideSeverity(alert.fingerprint, s);
                                    setSeverityDropdown(null);
                                  }}
                                  className={`block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors ${severityColor(s)}`}
                                >
                                  {s}
                                </button>
                              ))}
                              {alertState?.severity_override && (
                                <button
                                  onClick={async (e) => {
                                    e.stopPropagation();
                                    await overrideSeverity(alert.fingerprint, 'none');
                                    setSeverityDropdown(null);
                                  }}
                                  className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-muted border-t border-border"
                                >
                                  Reset to AI
                                </button>
                              )}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="table-cell">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-text-bright hover:text-accent transition-colors">
                            {(alert.name || 'Unknown').substring(0, 50)}
                            {(alert.name?.length ?? 0) > 50 ? '...' : ''}
                          </span>
                          {hl?.label && (
                            <span
                              className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium whitespace-nowrap"
                              style={{ backgroundColor: `${hl.color}20`, color: hl.color, border: `1px solid ${hl.color}40` }}
                            >
                              {hl.label}
                            </span>
                          )}
                          {customGroupByFingerprint?.get(alert.fingerprint) && (
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium whitespace-nowrap bg-accent/10 border border-accent/30 text-accent">
                              {customGroupByFingerprint.get(alert.fingerprint)}
                            </span>
                          )}
                          {alertStates?.get(alert.fingerprint)?.incident_jira_key && (
                            <a
                              href={alertStates.get(alert.fingerprint)!.incident_jira_url || '#'}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              title={`Incident created by ${alertStates.get(alert.fingerprint)!.incident_created_by || 'unknown'}${alertStates.get(alert.fingerprint)!.incident_created_at ? ', ' + timeAgo(alertStates.get(alert.fingerprint)!.incident_created_at!) : ''}`}
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-purple/10 border border-purple/30 text-purple whitespace-nowrap hover:bg-purple/20 transition-all duration-200"
                            >
                              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" />
                                <path strokeLinecap="round" strokeLinejoin="round" d="M10.172 13.828a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.102 1.101" />
                              </svg>
                              {alertStates.get(alert.fingerprint)!.incident_jira_key}
                            </a>
                          )}
                          {alertStates?.get(alert.fingerprint)?.escalated_to && (
                            <span
                              title={`Escalated by ${alertStates.get(alert.fingerprint)!.escalated_by || 'unknown'}${alertStates.get(alert.fingerprint)!.escalated_at ? ', ' + timeAgo(alertStates.get(alert.fingerprint)!.escalated_at!) : ''}`}
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-amber/10 border border-amber/30 text-amber whitespace-nowrap transition-all duration-200"
                            >
                              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M5 10l7-7m0 0l7 7m-7-7v18" />
                              </svg>
                              {alertStates.get(alert.fingerprint)!.escalated_to}
                            </span>
                          )}
                          {alert.triggerId && alert.zabbixInstance && ZABBIX_URLS[alert.zabbixInstance] && (
                            <a
                              href={`${ZABBIX_URLS[alert.zabbixInstance]}/zabbix.php?action=problem.view&filter_triggerids[]=${alert.triggerId}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center text-muted/50 hover:text-blue-400 transition-colors ml-1"
                              title="View in Zabbix"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                              </svg>
                            </a>
                          )}
                        </div>
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
                      {isResolvedView ? (
                        <>
                          <td className="table-cell text-xs text-muted whitespace-nowrap">
                            {timeAgo(alert.lastReceived)}
                          </td>
                          <td className="table-cell text-xs text-muted max-w-[14rem] truncate">
                            {enrichment?.summary || (
                              !alert.note ? (
                                <button
                                  onClick={async (e) => {
                                    e.stopPropagation();
                                    await forceEnrich(alert.fingerprint);
                                  }}
                                  className="text-xs text-muted animate-pulse hover:text-accent transition-colors cursor-pointer"
                                  title="Click to force enrichment"
                                >
                                  Enriching...
                                </button>
                              ) : '--'
                            )}
                          </td>
                        </>
                      ) : (
                        <>
                          <td className="table-cell text-xs text-muted max-w-xs truncate">
                            {enrichment?.summary || (
                              !alert.note ? (
                                <button
                                  onClick={async (e) => {
                                    e.stopPropagation();
                                    await forceEnrich(alert.fingerprint);
                                  }}
                                  className="text-xs text-muted animate-pulse hover:text-accent transition-colors cursor-pointer"
                                  title="Click to force enrichment"
                                >
                                  Enriching...
                                </button>
                              ) : '--'
                            )}
                          </td>
                          <td className="table-cell text-xs text-muted whitespace-nowrap">
                            {timeAgo(alertStartTime(alert))}
                          </td>
                        </>
                      )}
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
