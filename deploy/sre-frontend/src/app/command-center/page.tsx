'use client';

import { Fragment, useEffect, useState, useCallback, useMemo } from 'react';
import { Alert, AlertStats, AIEnrichment, SREFeedback, RunbookEntry, AlertState } from '@/lib/types';
import {
  fetchAlerts,
  parseAIEnrichment,
  parseSREFeedback,
  submitFeedback,
  computeStats,
  severityColor,
  severityBg,
  timeAgo,
  alertStartTime,
  fetchRunbookMatches,
  submitRunbookEntry,
  resolveAlert,
  silenceAlert,
  createJiraIncident,
  fetchAlertStates,
  toggleInvestigating,
  acknowledgeAlerts,
  unacknowledgeAlerts,
  markAlertsUpdated,
  getSourceLabel,
} from '@/lib/keep-api';
import { getClientUsername } from '@/lib/auth';
import { detectRegistryFromAlert, buildRegistryMailto } from '@/lib/registry-contacts';

/* ── Alert Grouping ── */

interface AlertGroup {
  key: string;
  label: string;
  alerts: Alert[];
  highestSeverity: string;
}

function extractAlertBase(alertName: string, hostname: string): string {
  if (!alertName) return 'Unknown';
  if (hostname) {
    const lower = alertName.toLowerCase();
    const hostLower = hostname.toLowerCase();
    for (const sep of [' on ', ' for ', ' at ', ' - ', ': ']) {
      const idx = lower.indexOf(sep + hostLower);
      if (idx !== -1) return alertName.substring(0, idx).trim();
    }
    if (lower.endsWith(hostLower)) {
      return alertName.substring(0, alertName.length - hostname.length).replace(/[\s\-:]+$/, '').trim();
    }
  }
  return alertName;
}

function getParentDomain(hostname: string): string {
  if (!hostname) return '';
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  return parts.slice(1).join('.');
}

function buildAlertGroups(alerts: Alert[], sortKey: string = 'severity', sortDir: 'asc' | 'desc' = 'desc'): AlertGroup[] {
  const sevOrder: Record<string, number> = { critical: 0, high: 1, warning: 2, low: 3, info: 4, unknown: 5 };
  const sevNames = ['critical', 'high', 'warning', 'low', 'info', 'unknown'];

  // Pass 1: group by alertBase + parentDomain
  const domainMap = new Map<string, AlertGroup>();
  for (const alert of alerts) {
    const host = alert.hostName || alert.hostname || '';
    const base = extractAlertBase(alert.name || '', host);
    const parent = getParentDomain(host);
    const key = `${base}::${parent}`;

    if (!domainMap.has(key)) {
      const label = parent ? `${base} — ${parent}` : base;
      domainMap.set(key, { key, label, alerts: [], highestSeverity: 'unknown' });
    }
    domainMap.get(key)!.alerts.push(alert);
  }

  // Pass 2: singles from pass 1 that share alertBase get merged into name-only groups
  const multiGroups: AlertGroup[] = [];
  const singles: { base: string; alert: Alert }[] = [];

  Array.from(domainMap.values()).forEach(g => {
    if (g.alerts.length >= 2) {
      multiGroups.push(g);
    } else {
      const host = g.alerts[0].hostName || g.alerts[0].hostname || '';
      singles.push({ base: extractAlertBase(g.alerts[0].name || '', host), alert: g.alerts[0] });
    }
  });

  const nameMap = new Map<string, AlertGroup>();
  for (const { base, alert } of singles) {
    if (!nameMap.has(base)) {
      nameMap.set(base, { key: `name::${base}`, label: base, alerts: [], highestSeverity: 'unknown' });
    }
    nameMap.get(base)!.alerts.push(alert);
  }

  // Name-only groups with 2+ alerts become real groups; true singles stay as-is
  Array.from(nameMap.values()).forEach(g => multiGroups.push(g));

  // Compute highest severity per group and best time
  const result = multiGroups.map(g => {
    let best = 5;
    for (const a of g.alerts) {
      const sev = parseAIEnrichment(a.note)?.assessed_severity ?? 'unknown';
      best = Math.min(best, sevOrder[sev] ?? 5);
    }
    g.highestSeverity = sevNames[best];
    return g;
  });

  // Sort groups respecting the user's chosen sort key and direction
  const dir = sortDir === 'asc' ? 1 : -1;
  result.sort((a, b) => {
    switch (sortKey) {
      case 'time': {
        const ta = Math.max(...a.alerts.map(al => new Date(alertStartTime(al)).getTime() || 0));
        const tb = Math.max(...b.alerts.map(al => new Date(alertStartTime(al)).getTime() || 0));
        return (ta - tb) * dir;
      }
      case 'severity': {
        const sa = sevOrder[a.highestSeverity] ?? 5;
        const sb = sevOrder[b.highestSeverity] ?? 5;
        if (sa !== sb) return (sa - sb) * dir;
        return b.alerts.length - a.alerts.length;
      }
      case 'alert':
        return a.label.localeCompare(b.label) * dir;
      case 'host': {
        const ha = a.alerts[0]?.hostName || a.alerts[0]?.hostname || '';
        const hb = b.alerts[0]?.hostName || b.alerts[0]?.hostname || '';
        return ha.localeCompare(hb) * dir;
      }
      default: {
        // Default: multi-alert groups first, then severity
        const aMulti = a.alerts.length >= 2 ? 0 : 1;
        const bMulti = b.alerts.length >= 2 ? 0 : 1;
        if (aMulti !== bMulti) return aMulti - bMulti;
        const sa = sevOrder[a.highestSeverity] ?? 5;
        const sb = sevOrder[b.highestSeverity] ?? 5;
        if (sa !== sb) return sa - sb;
        return b.alerts.length - a.alerts.length;
      }
    }
  });

  return result;
}

export default function CommandCenter() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  // stats derived via useMemo below
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [sortKey, setSortKey] = useState<'severity' | 'alert' | 'host' | 'source' | 'summary' | 'time'>('time');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [pageSize, setPageSize] = useState(10);
  const [currentPage, setCurrentPage] = useState(0);
  const [groupView, setGroupView] = useState(true);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [alertStates, setAlertStates] = useState<Map<string, AlertState>>(new Map());
  const [dashboardTab, setDashboardTab] = useState<'firing' | 'acknowledged'>('firing');

  const load = useCallback(async () => {
    try {
      const [data, states] = await Promise.all([fetchAlerts(100), fetchAlertStates()]);

      // Build states map
      let stateMap = new Map<string, AlertState>();
      for (const s of states) stateMap.set(s.alert_fingerprint, s);

      // Re-fire detection: check acked alerts for new firingStartTime
      const refired: string[] = [];
      for (const alert of data) {
        const st = stateMap.get(alert.fingerprint);
        if (st?.acknowledged_by && st.ack_firing_start) {
          const cur = alert.firingStartTime || alert.startedAt || '';
          if (cur && cur !== st.ack_firing_start) refired.push(alert.fingerprint);
        }
      }
      if (refired.length > 0) {
        await markAlertsUpdated(refired);
        const fresh = await fetchAlertStates();
        stateMap = new Map<string, AlertState>();
        for (const s of fresh) stateMap.set(s.alert_fingerprint, s);
      }

      setAlerts(data);
      setAlertStates(stateMap);
      setLastUpdated(new Date());
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, refreshInterval * 1000);
    return () => clearInterval(interval);
  }, [load, refreshInterval]);

  const activeAlerts = alerts.filter(a => a.status !== 'resolved' && a.status !== 'ok');

  // Split into firing vs acknowledged
  const firingAlerts = activeAlerts.filter(a => !alertStates.get(a.fingerprint)?.acknowledged_by);
  const ackedAlerts = activeAlerts.filter(a => !!alertStates.get(a.fingerprint)?.acknowledged_by);
  const tabAlerts = dashboardTab === 'firing' ? firingAlerts : ackedAlerts;

  // Stats from firing alerts only
  const stats = useMemo(() => computeStats(firingAlerts), [firingAlerts]);

  const filteredAlerts = useMemo(() => {
    return tabAlerts.filter(a => {
      if (sevFilter) {
        const enrichment = parseAIEnrichment(a.note);
        const sev = enrichment?.assessed_severity ?? 'unknown';
        if (sevFilter === 'low') {
          if (sev !== 'low' && sev !== 'info') return false;
        } else {
          if (sev !== sevFilter) return false;
        }
      }
      return true;
    });
  }, [tabAlerts, sevFilter]);

  const sevOrder: Record<string, number> = { critical: 0, high: 1, warning: 2, low: 3, info: 4, unknown: 5 };

  const sortedAlerts = useMemo(() => {
    const arr = [...filteredAlerts];
    const dir = sortDir === 'asc' ? 1 : -1;
    arr.sort((a, b) => {
      switch (sortKey) {
        case 'severity': {
          const sa = sevOrder[parseAIEnrichment(a.note)?.assessed_severity ?? 'unknown'] ?? 5;
          const sb = sevOrder[parseAIEnrichment(b.note)?.assessed_severity ?? 'unknown'] ?? 5;
          return (sa - sb) * dir;
        }
        case 'alert':
          return (a.name || '').localeCompare(b.name || '') * dir;
        case 'host': {
          const ha = a.hostName || a.hostname || '';
          const hb = b.hostName || b.hostname || '';
          return ha.localeCompare(hb) * dir;
        }
        case 'source':
          return getSourceLabel(a).localeCompare(getSourceLabel(b)) * dir;
        case 'summary': {
          const sumA = parseAIEnrichment(a.note)?.summary || '';
          const sumB = parseAIEnrichment(b.note)?.summary || '';
          return sumA.localeCompare(sumB) * dir;
        }
        case 'time': {
          const ta = new Date(alertStartTime(a)).getTime() || 0;
          const tb = new Date(alertStartTime(b)).getTime() || 0;
          return (ta - tb) * dir;
        }
        default:
          return 0;
      }
    });
    return arr;
  }, [filteredAlerts, sortKey, sortDir]);

  const alertGroups = useMemo(() => groupView ? buildAlertGroups(sortedAlerts, sortKey, sortDir) : [], [sortedAlerts, groupView, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sortedAlerts.length / pageSize));
  const safePage = Math.min(currentPage, totalPages - 1);
  const displayAlerts = sortedAlerts.slice(safePage * pageSize, (safePage + 1) * pageSize);
  const hasFilter = sevFilter !== null;

  // Reset to page 0 when filters or page size change
  useEffect(() => { setCurrentPage(0); }, [sevFilter, pageSize]);

  function handleSort(key: typeof sortKey) {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir(key === 'time' ? 'desc' : 'asc');
    }
  }

  function toggleRow(id: string) {
    setExpandedRows(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleInvestigate(alert: Alert) {
    await toggleInvestigating(alert.fingerprint, alert.name || '');
    load();
  }

  async function handleAcknowledge(alert: Alert) {
    const names: Record<string, string> = { [alert.fingerprint]: alert.name || '' };
    const starts: Record<string, string> = { [alert.fingerprint]: alertStartTime(alert) };
    await acknowledgeAlerts([alert.fingerprint], names, starts);
    load();
  }

  async function handleUnacknowledge(alert: Alert) {
    await unacknowledgeAlerts([alert.fingerprint]);
    load();
  }

  async function handleGroupAcknowledge(group: AlertGroup) {
    const fps = group.alerts.map(a => a.fingerprint);
    const names: Record<string, string> = {};
    const starts: Record<string, string> = {};
    for (const a of group.alerts) {
      names[a.fingerprint] = a.name || '';
      starts[a.fingerprint] = alertStartTime(a);
    }
    await acknowledgeAlerts(fps, names, starts);
    load();
  }

  function toggleGroup(key: string) {
    setExpandedGroups(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function handleAlertRefresh() {
    load();
    // Update the selectedAlert if it's still open
    if (selectedAlert) {
      const fresh = alerts.find(a => a.fingerprint === selectedAlert.fingerprint);
      if (fresh) setSelectedAlert(fresh);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted animate-pulse">Loading alerts...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-text-bright">Command Center</h1>
        <div className="flex items-center gap-3">
          <RefreshControl
            refreshInterval={refreshInterval}
            onRefreshIntervalChange={setRefreshInterval}
            onRefresh={() => { setRefreshing(true); load().finally(() => setTimeout(() => setRefreshing(false), 500)); }}
            refreshing={refreshing}
          />
          <span className="text-xs text-muted">
            {lastUpdated && `Updated ${lastUpdated.toLocaleTimeString()}`}
          </span>
        </div>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-red text-sm">
          {error}
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Active Alerts" value={stats.total} color="text-text-bright" />
        <StatCard label="Critical" value={stats.critical} color="text-red"
          filterKey="critical" activeFilter={sevFilter} onFilter={setSevFilter} />
        <StatCard label="High" value={stats.high} color="text-orange"
          filterKey="high" activeFilter={sevFilter} onFilter={setSevFilter} />
        <StatCard label="Warning" value={stats.warning} color="text-yellow"
          filterKey="warning" activeFilter={sevFilter} onFilter={setSevFilter} />
      </div>

      {/* Firing / Acknowledged Tab Bar */}
      <div className="flex items-center gap-1 bg-surface border border-border rounded-lg p-1">
        <button
          onClick={() => setDashboardTab('firing')}
          className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
            dashboardTab === 'firing'
              ? 'bg-accent text-white'
              : 'text-muted hover:text-text-bright'
          }`}
        >
          Firing ({firingAlerts.length})
        </button>
        <button
          onClick={() => setDashboardTab('acknowledged')}
          className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
            dashboardTab === 'acknowledged'
              ? 'bg-accent text-white'
              : 'text-muted hover:text-text-bright'
          }`}
        >
          Acknowledged ({ackedAlerts.length})
        </button>
      </div>

      {/* Active filter indicator */}
      {hasFilter && (
        <div className="flex items-center gap-2 text-sm">
          <span className="text-muted">Filtering by:</span>
          {sevFilter && (
            <button
              onClick={() => setSevFilter(null)}
              className={`badge ${severityBg(sevFilter)} cursor-pointer`}
            >
              {sevFilter} &times;
            </button>
          )}
          <button
            onClick={() => setSevFilter(null)}
            className="text-xs text-muted hover:text-text transition-colors ml-2"
          >
            Clear
          </button>
        </div>
      )}

      {/* Recent Alerts Table */}
      <div className="stat-card overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-medium text-muted">
            {hasFilter ? `Filtered Alerts (${filteredAlerts.length})` : 'Recent Active Alerts'}
          </h3>
          <div className="flex items-center gap-3">
            <button
              onClick={() => { setGroupView(v => !v); setExpandedGroups(new Set()); }}
              className={`text-xs px-2.5 py-1 rounded border transition-colors inline-flex items-center gap-1.5 ${
                groupView
                  ? 'border-accent/40 bg-accent/10 text-accent'
                  : 'border-border text-muted hover:text-text hover:bg-surface-hover'
              }`}
              title="Group similar alerts by name and host pattern"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              Group similar
            </button>
            <a href="/portal/alerts" className="text-xs text-accent hover:text-accent-hover transition-colors">
              View all &rarr;
            </a>
          </div>
        </div>
        <div className="overflow-x-auto -mx-5">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                {([
                  ['severity', 'Severity'],
                  ['alert', 'Alert'],
                  ['host', 'Host'],
                  ['source', 'Source'],
                  ['summary', 'AI Summary'],
                  ['time', 'Time'],
                ] as const).map(([key, label]) => (
                  <th
                    key={key}
                    className="table-header cursor-pointer select-none hover:text-text-bright transition-colors"
                    onClick={() => handleSort(key)}
                  >
                    <span className="inline-flex items-center gap-1">
                      {label}
                      {sortKey === key ? (
                        <span className="text-accent">{sortDir === 'asc' ? '\u25B2' : '\u25BC'}</span>
                      ) : (
                        <span className="text-muted/40">{'\u25BC'}</span>
                      )}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {groupView ? (
                alertGroups.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="table-cell text-center text-muted py-8">
                      {hasFilter ? 'No alerts match the selected filters' : 'No active alerts'}
                    </td>
                  </tr>
                ) : (
                  alertGroups.map(group => group.alerts.length >= 2 ? (
                    <Fragment key={group.key}>
                      <tr
                        className="border-b border-border/50 hover:bg-surface-hover cursor-pointer transition-colors bg-bg/30"
                        onClick={() => toggleGroup(group.key)}
                      >
                        <td colSpan={6} className="px-5 py-2.5">
                          <div className="flex items-center gap-3">
                            <span className="text-muted text-xs w-4 text-center">{expandedGroups.has(group.key) ? '\u25BE' : '\u25B8'}</span>
                            <span className={`badge ${severityBg(group.highestSeverity)}`}>
                              {group.highestSeverity}
                            </span>
                            <span className="text-text-bright font-medium text-sm">{group.label}</span>
                            <span className="bg-accent/10 text-accent text-[10px] px-2 py-0.5 rounded-full font-medium">
                              {group.alerts.length} alerts
                            </span>
                            <span className="text-muted text-xs ml-auto flex items-center gap-2">
                              {timeAgo(alertStartTime(group.alerts.reduce((latest, a) => {
                                const t = new Date(alertStartTime(a)).getTime() || 0;
                                const l = new Date(alertStartTime(latest)).getTime() || 0;
                                return t > l ? a : latest;
                              })))}
                              {dashboardTab === 'firing' && (
                                <button
                                  onClick={(e) => { e.stopPropagation(); handleGroupAcknowledge(group); }}
                                  className="text-[10px] px-2 py-0.5 rounded border border-border text-muted hover:text-green hover:border-green/50 transition-colors"
                                >
                                  Ack Group
                                </button>
                              )}
                            </span>
                          </div>
                        </td>
                      </tr>
                      {expandedGroups.has(group.key) && group.alerts.map(alert => {
                        const rowId = alert.fingerprint || alert.id;
                        return (
                          <AlertRow
                            key={rowId}
                            alert={alert}
                            expanded={expandedRows.has(rowId)}
                            onToggleExpand={() => toggleRow(rowId)}
                            onOpenDetail={() => setSelectedAlert(alert)}
                            indented
                            alertState={alertStates.get(alert.fingerprint)}
                            onInvestigate={() => handleInvestigate(alert)}
                            onAcknowledge={dashboardTab === 'firing' ? () => handleAcknowledge(alert) : undefined}
                            onUnacknowledge={dashboardTab === 'acknowledged' ? () => handleUnacknowledge(alert) : undefined}
                            showAckInfo={dashboardTab === 'acknowledged'}
                          />
                        );
                      })}
                    </Fragment>
                  ) : (
                    <AlertRow
                      key={group.alerts[0].fingerprint || group.alerts[0].id}
                      alert={group.alerts[0]}
                      expanded={expandedRows.has(group.alerts[0].fingerprint || group.alerts[0].id)}
                      onToggleExpand={() => toggleRow(group.alerts[0].fingerprint || group.alerts[0].id)}
                      onOpenDetail={() => setSelectedAlert(group.alerts[0])}
                      alertState={alertStates.get(group.alerts[0].fingerprint)}
                      onInvestigate={() => handleInvestigate(group.alerts[0])}
                      onAcknowledge={dashboardTab === 'firing' ? () => handleAcknowledge(group.alerts[0]) : undefined}
                      onUnacknowledge={dashboardTab === 'acknowledged' ? () => handleUnacknowledge(group.alerts[0]) : undefined}
                      showAckInfo={dashboardTab === 'acknowledged'}
                    />
                  ))
                )
              ) : (
                displayAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="table-cell text-center text-muted py-8">
                      {hasFilter ? 'No alerts match the selected filters' : 'No active alerts'}
                    </td>
                  </tr>
                ) : (
                  displayAlerts.map((alert) => {
                    const rowId = alert.fingerprint || alert.id;
                    return (
                      <AlertRow
                        key={rowId}
                        alert={alert}
                        expanded={expandedRows.has(rowId)}
                        onToggleExpand={() => toggleRow(rowId)}
                        onOpenDetail={() => setSelectedAlert(alert)}
                        alertState={alertStates.get(alert.fingerprint)}
                        onInvestigate={() => handleInvestigate(alert)}
                        onAcknowledge={dashboardTab === 'firing' ? () => handleAcknowledge(alert) : undefined}
                        onUnacknowledge={dashboardTab === 'acknowledged' ? () => handleUnacknowledge(alert) : undefined}
                        showAckInfo={dashboardTab === 'acknowledged'}
                      />
                    );
                  })
                )
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination / Group summary */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-border">
          {groupView ? (
            <span className="text-xs text-muted">
              {(() => {
                const multi = alertGroups.filter(g => g.alerts.length >= 2);
                const singles = alertGroups.filter(g => g.alerts.length === 1);
                const parts: string[] = [];
                if (multi.length > 0) parts.push(`${multi.length} group${multi.length > 1 ? 's' : ''} (${multi.reduce((s, g) => s + g.alerts.length, 0)} alerts)`);
                if (singles.length > 0) parts.push(`${singles.length} ungrouped`);
                return parts.join(', ') || 'No alerts';
              })()}
            </span>
          ) : (
            <>
              <div className="flex items-center gap-3">
                <span className="text-xs text-muted">
                  {sortedAlerts.length > 0
                    ? `Showing ${safePage * pageSize + 1}\u2013${Math.min((safePage + 1) * pageSize, sortedAlerts.length)} of ${sortedAlerts.length}`
                    : 'No alerts'}
                </span>
                <select
                  value={pageSize}
                  onChange={e => setPageSize(Number(e.target.value))}
                  className="bg-surface border border-border rounded px-2 py-1 text-xs text-muted focus:outline-none focus:ring-1 focus:ring-accent"
                >
                  <option value={10}>10 per page</option>
                  <option value={25}>25 per page</option>
                  <option value={50}>50 per page</option>
                  <option value={100}>100 per page</option>
                </select>
              </div>
              {totalPages > 1 && (
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
            </>
          )}
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onRefresh={handleAlertRefresh}
          alertState={alertStates.get(selectedAlert.fingerprint)}
          onInvestigate={() => handleInvestigate(selectedAlert)}
          onAcknowledge={() => handleAcknowledge(selectedAlert)}
        />
      )}
    </div>
  );
}

/** Generate page number buttons: [0, 1, -1, 4, 5] where -1 = ellipsis */
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

function StatCard({ label, value, color, subtext, filterKey, activeFilter, onFilter }: {
  label: string; value: number; color: string; subtext?: string;
  filterKey?: string; activeFilter?: string | null; onFilter?: (f: string | null) => void;
}) {
  const isActive = filterKey && activeFilter === filterKey;
  const clickable = filterKey && onFilter;
  return (
    <div
      className={`stat-card transition-all ${clickable ? 'cursor-pointer hover:ring-1 hover:ring-accent/30' : ''} ${
        isActive ? 'ring-2 ring-accent' : ''
      }`}
      onClick={() => clickable && onFilter(isActive ? null : filterKey)}
    >
      <div className="text-xs text-muted uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-3xl font-bold ${color}`}>{value}</div>
      {subtext && <div className="text-xs text-muted font-normal mt-1">{subtext}</div>}
    </div>
  );
}

function RefreshControl({ refreshInterval, onRefreshIntervalChange, onRefresh, refreshing }: {
  refreshInterval: number;
  onRefreshIntervalChange: (v: number) => void;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  return (
    <div className="flex items-center border border-border rounded overflow-hidden">
      <button
        onClick={onRefresh}
        className="px-2 py-1.5 text-muted hover:text-accent hover:bg-surface-hover transition-colors border-r border-border"
        title="Refresh now"
      >
        <svg
          className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin-once' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h5M20 20v-5h-5M4.49 15A8 8 0 0019.5 9M19.51 9A8 8 0 004.5 15" />
        </svg>
      </button>
      <select
        value={refreshInterval}
        onChange={e => onRefreshIntervalChange(Number(e.target.value))}
        className="bg-surface px-2 py-1 text-xs text-muted focus:outline-none"
      >
        <option value={5}>5s</option>
        <option value={10}>10s</option>
        <option value={30}>30s</option>
        <option value={60}>1m</option>
        <option value={120}>2m</option>
        <option value={300}>5m</option>
        <option value={600}>10m</option>
      </select>
    </div>
  );
}

function AlertRow({ alert, expanded, onToggleExpand, onOpenDetail, indented, alertState, onInvestigate, onAcknowledge, onUnacknowledge, showAckInfo }: {
  alert: Alert;
  expanded: boolean;
  onToggleExpand: () => void;
  onOpenDetail: () => void;
  indented?: boolean;
  alertState?: AlertState;
  onInvestigate?: () => void;
  onAcknowledge?: () => void;
  onUnacknowledge?: () => void;
  showAckInfo?: boolean;
}) {
  const enrichment = parseAIEnrichment(alert.note);
  const sev = enrichment?.assessed_severity ?? 'unknown';
  const host = alert.hostName || alert.hostname || '';
  const source = getSourceLabel(alert);
  const summary = enrichment?.summary || '';
  const description = alert.description && alert.description !== alert.name ? alert.description : '';

  const truncatedSummary = summary.length > 80 ? summary.substring(0, 80) + '...' : summary;
  const truncatedDesc = description.length > 80 ? description.substring(0, 80) + '...' : description;
  const hasExpandableContent = summary.length > 80 || description.length > 80;

  return (
    <tr className={`border-b border-border/50 hover:bg-surface-hover transition-colors ${indented ? 'bg-bg/20' : ''}`}>
      <td className={`table-cell ${indented ? 'pl-10' : ''}`}>
        <span className={`badge ${severityBg(sev)}`}>
          {sev}
        </span>
      </td>
      <td className="table-cell">
        <div className="flex items-center gap-1.5 flex-wrap">
          <button
            onClick={onOpenDetail}
            className="text-left text-text-bright hover:text-accent transition-colors"
          >
            {alert.name?.substring(0, 60) || 'Unknown'}
            {(alert.name?.length ?? 0) > 60 ? '...' : ''}
          </button>
          {alertState?.investigating_user && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-blue/10 border border-blue/30 text-blue whitespace-nowrap">
              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              {alertState.investigating_user}
            </span>
          )}
          {alertState?.is_updated === 1 && (
            <span className="px-1.5 py-0.5 rounded text-[10px] bg-orange/10 border border-orange/30 text-orange font-medium whitespace-nowrap">
              Updated
            </span>
          )}
          {showAckInfo && alertState?.acknowledged_by && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-green/10 border border-green/30 text-green whitespace-nowrap">
              Acked by {alertState.acknowledged_by} {alertState.acknowledged_at ? timeAgo(alertState.acknowledged_at) : ''}
            </span>
          )}
        </div>
        {description && (
          <div className="text-xs text-muted mt-0.5 font-mono">
            {expanded ? description : truncatedDesc}
          </div>
        )}
      </td>
      <td className="table-cell text-muted text-xs font-mono">{host}</td>
      <td className="table-cell text-xs text-muted">{source}</td>
      <td className="table-cell text-xs text-muted max-w-xs">
        <div className={expanded ? '' : 'truncate'}>
          {expanded ? summary : truncatedSummary}
        </div>
        {hasExpandableContent && (
          <button
            onClick={(e) => { e.stopPropagation(); onToggleExpand(); }}
            className="text-accent hover:text-accent-hover text-[10px] mt-0.5 transition-colors"
          >
            {expanded ? 'Show less' : 'Show more'}
          </button>
        )}
        {!summary && <span>--</span>}
      </td>
      <td className="table-cell text-xs text-muted whitespace-nowrap">
        <div className="flex items-center gap-2">
          <span>{timeAgo(alertStartTime(alert))}</span>
          <div className="flex items-center gap-1 ml-auto">
            {onInvestigate && (
              <button
                onClick={(e) => { e.stopPropagation(); onInvestigate(); }}
                title={alertState?.investigating_user ? `Investigating by ${alertState.investigating_user}` : 'Mark as investigating'}
                className={`p-1 rounded transition-colors ${
                  alertState?.investigating_user
                    ? 'text-blue hover:text-blue/70'
                    : 'text-muted/40 hover:text-blue'
                }`}
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </button>
            )}
            {onAcknowledge && (
              <button
                onClick={(e) => { e.stopPropagation(); onAcknowledge(); }}
                title="Acknowledge"
                className="p-1 rounded text-muted/40 hover:text-green transition-colors"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </button>
            )}
            {onUnacknowledge && (
              <button
                onClick={(e) => { e.stopPropagation(); onUnacknowledge(); }}
                title="Unacknowledge"
                className="p-1 rounded text-muted/40 hover:text-orange transition-colors"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>
        </div>
      </td>
    </tr>
  );
}

/* ── Alert Detail Modal ── */

function AlertDetailModal({ alert, onClose, onRefresh, alertState, onInvestigate, onAcknowledge }: {
  alert: Alert;
  onClose: () => void;
  onRefresh: () => void;
  alertState?: AlertState;
  onInvestigate?: () => void;
  onAcknowledge?: () => void;
}) {
  const enrichment = parseAIEnrichment(alert.note);
  const host = alert.hostName || alert.hostname || 'Unknown';
  const source = getSourceLabel(alert);

  // Close on Escape
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [onClose]);

  // Prevent background scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-bg/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Panel */}
      <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto mt-[5vh] mx-4 bg-surface border border-border rounded-xl shadow-2xl">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 z-10 w-8 h-8 flex items-center justify-center rounded-md text-muted hover:text-text hover:bg-surface-hover transition-colors"
        >
          &times;
        </button>

        <div className="p-6 space-y-5">
          {/* Header */}
          <div>
            <h2 className="text-lg font-bold text-text-bright pr-8">{alert.name}</h2>
            <div className="flex flex-wrap gap-3 mt-2 text-xs text-muted">
              <span>Host: <span className="text-text font-mono">{host}</span></span>
              <span>Source: <span className="text-text">{source}</span></span>
              <span>Status: <span className="text-text">{alert.status}</span></span>
              <span>Started: <span className="text-text">{timeAgo(alertStartTime(alert))}</span></span>
              {alert.fingerprint && (
                <span>FP: <span className="text-text font-mono">{alert.fingerprint.substring(0, 16)}...</span></span>
              )}
            </div>
          </div>

          {/* Actions */}
          <AlertActions alert={alert} enrichment={enrichment} onAlertChanged={onRefresh} alertState={alertState} onInvestigate={onInvestigate} onAcknowledge={onAcknowledge} />

          {/* Description / Metric Values */}
          {alert.description && alert.description !== alert.name && (
            <div className="bg-bg/60 border border-border rounded-lg px-4 py-3">
              <h3 className="text-xs font-medium text-muted mb-1">Alert Details</h3>
              <p className="text-sm text-text-bright font-mono">{alert.description}</p>
            </div>
          )}

          {/* AI Analysis */}
          {enrichment ? (
            <div className="space-y-4">
              <h3 className="text-base font-semibold text-accent">AI Analysis</h3>

              {/* Summary + Metrics */}
              <div className="bg-bg/40 border border-accent/20 rounded-lg px-4 py-3">
                <div className="text-sm text-text-bright mb-3">{enrichment.summary}</div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <ModalMetricBox
                    label="Assessed Severity"
                    value={enrichment.assessed_severity}
                    className={severityColor(enrichment.assessed_severity)}
                  />
                  <ModalMetricBox
                    label="Original Severity"
                    value={alert.severity || 'unknown'}
                    className="text-muted"
                  />
                  <ModalMetricBox
                    label="Noise Score"
                    value={`${enrichment.noise_score}/10`}
                    className={enrichment.noise_score >= 7 ? 'text-muted' : enrichment.noise_score >= 4 ? 'text-yellow' : 'text-green'}
                  />
                  <ModalMetricBox
                    label="Dedup"
                    value={enrichment.dedup_assessment || 'N/A'}
                    className={enrichment.dedup_assessment === 'DUPLICATE' ? 'text-orange' : enrichment.dedup_assessment === 'CORRELATED' ? 'text-yellow' : 'text-green'}
                  />
                </div>
              </div>

              {/* Detail Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <ModalDetailCard title="Likely Cause" content={enrichment.likely_cause} icon="?" />
                <ModalDetailCard title="Remediation" content={enrichment.remediation} icon="!" />
                <ModalDetailCard title="Impact Scope" content={enrichment.impact_scope} icon="~" />
                <ModalDetailCard title="Noise Reason" content={enrichment.noise_reason} icon="#" />
              </div>

              {enrichment.dedup_reason && (
                <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
                  <h4 className="text-xs font-medium text-muted mb-1">Deduplication Reason</h4>
                  <div className="text-sm text-text">{enrichment.dedup_reason}</div>
                </div>
              )}

              {/* Noise Assessment Bar */}
              <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
                <h4 className="text-xs font-medium text-muted mb-2">Noise Assessment</h4>
                <div className="flex items-center gap-4">
                  <div className="flex-1">
                    <div className="w-full bg-border rounded-full h-2.5">
                      <div
                        className={`h-2.5 rounded-full transition-all ${
                          enrichment.noise_score >= 7 ? 'bg-muted' :
                          enrichment.noise_score >= 4 ? 'bg-yellow' : 'bg-green'
                        }`}
                        style={{ width: `${enrichment.noise_score * 10}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] text-muted mt-1">
                      <span>Actionable</span>
                      <span>Likely Noise</span>
                    </div>
                  </div>
                  <div className={`text-xl font-bold font-mono ${
                    enrichment.noise_score >= 7 ? 'text-muted' :
                    enrichment.noise_score >= 4 ? 'text-yellow' : 'text-green'
                  }`}>
                    {enrichment.noise_score}/10
                  </div>
                </div>
              </div>

              {enrichment.llm_model && (
                <div className="text-xs text-muted">
                  Analyzed by: {enrichment.llm_model}
                </div>
              )}
            </div>
          ) : (
            <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
              <div className="text-muted text-sm">
                AI enrichment not yet available. The enricher processes alerts every 60 seconds.
              </div>
            </div>
          )}

          {/* SRE Feedback */}
          {enrichment && (
            <ModalFeedbackPanel
              fingerprint={alert.fingerprint}
              currentNote={alert.note}
              existingFeedback={parseSREFeedback(alert.note)}
              enrichment={enrichment}
              onFeedbackSubmitted={onRefresh}
            />
          )}

          {/* Runbook & Remediation */}
          <RunbookPanel alert={alert} />

          {/* Tags */}
          {alert.tags && Array.isArray(alert.tags) && alert.tags.length > 0 && (
            <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
              <h4 className="text-xs font-medium text-muted mb-2">Tags</h4>
              <div className="flex flex-wrap gap-2">
                {alert.tags.map((tag, i) => (
                  <span key={i} className="badge bg-accent/10 border-accent/30 text-accent">
                    {tag.tag || tag.name}: {tag.value}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Open full page link */}
          <div className="flex justify-between items-center pt-2 border-t border-border">
            <a
              href={`/portal/alerts/${alert.fingerprint}`}
              className="text-xs text-accent hover:text-accent-hover transition-colors"
            >
              Open full page &rarr;
            </a>
            <button
              onClick={onClose}
              className="px-4 py-1.5 text-xs rounded-md border border-border text-muted hover:text-text hover:bg-surface-hover transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ModalMetricBox({ label, value, className }: { label: string; value: string; className?: string }) {
  return (
    <div>
      <div className="text-[10px] text-muted uppercase tracking-wider mb-0.5">{label}</div>
      <div className={`text-sm font-semibold uppercase ${className || ''}`}>{value}</div>
    </div>
  );
}

function ModalDetailCard({ title, content, icon }: { title: string; content: string; icon: string }) {
  if (!content) return null;
  return (
    <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
      <div className="flex items-start gap-2">
        <div className="w-6 h-6 rounded bg-accent/10 border border-accent/30 flex items-center justify-center text-accent font-mono text-xs flex-shrink-0">
          {icon}
        </div>
        <div className="min-w-0">
          <h4 className="text-xs font-medium text-muted mb-0.5">{title}</h4>
          <div className="text-sm text-text">{content}</div>
        </div>
      </div>
    </div>
  );
}

function ModalFeedbackPanel({
  fingerprint,
  currentNote,
  existingFeedback,
  enrichment,
  onFeedbackSubmitted,
}: {
  fingerprint: string;
  currentNote: string | undefined | null;
  existingFeedback: SREFeedback | null;
  enrichment: { assessed_severity: string; noise_score: number };
  onFeedbackSubmitted?: () => void;
}) {
  const [rating, setRating] = useState<'positive' | 'negative' | null>(
    existingFeedback?.rating === 'positive' ? 'positive' :
    existingFeedback?.rating ? 'negative' : null
  );
  const [correctedSeverity, setCorrectedSeverity] = useState(existingFeedback?.corrected_severity ?? '');
  const [correctedNoise, setCorrectedNoise] = useState(existingFeedback?.corrected_noise?.toString() ?? '');
  const [comment, setComment] = useState(existingFeedback?.comment ?? '');
  const [sreUser] = useState(() => existingFeedback?.sre_user || getClientUsername() || '');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(!!existingFeedback);
  const [editing, setEditing] = useState(false);
  const [justSubmitted, setJustSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState(false);

  async function handleSubmit() {
    if (!rating) return;
    setSubmitting(true);
    setSubmitError(false);

    const feedback: SREFeedback = {
      rating: rating === 'negative' && !correctedSeverity && !correctedNoise ? 'negative' :
              rating === 'negative' ? 'correction' : 'positive',
      corrected_severity: correctedSeverity || undefined,
      corrected_noise: correctedNoise ? parseInt(correctedNoise, 10) : undefined,
      comment: comment.slice(0, 500) || undefined,
      sre_user: sreUser || undefined,
    };

    const ok = await submitFeedback(fingerprint, currentNote, feedback);
    setSubmitting(false);
    if (ok) {
      setSubmitted(true);
      setEditing(false);
      setJustSubmitted(true);
      if (onFeedbackSubmitted) {
        setTimeout(onFeedbackSubmitted, 500);
      }
    } else {
      setSubmitError(true);
    }
  }

  return (
    <div className="bg-bg/40 border border-accent/20 rounded-lg px-4 py-3">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-semibold text-accent">SRE Feedback</h4>
        <span className="text-[10px] text-muted">Help improve AI analysis</span>
      </div>

      {justSubmitted && (
        <div className="bg-green/10 border border-green/30 rounded-lg px-3 py-2 mb-3">
          <div className="flex items-start gap-2">
            <span className="text-green text-sm leading-none">{'\u2713'}</span>
            <div>
              <div className="text-xs font-medium text-green">Feedback submitted</div>
              <div className="text-[10px] text-muted mt-0.5">
                Will be ingested on next enricher cycle (~60s).
              </div>
            </div>
          </div>
        </div>
      )}

      {submitError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-3 py-2 mb-3">
          <div className="text-xs text-red">Failed to submit. Please try again.</div>
        </div>
      )}

      {submitted && !editing ? (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm">
            <span className={`text-base ${rating === 'positive' ? 'text-green' : 'text-red'}`}>
              {rating === 'positive' ? '\u2713' : '\u2717'}
            </span>
            <span className="text-text text-xs">
              {rating === 'positive' ? 'Confirmed accurate' : 'Needs correction'}
            </span>
            {sreUser && <span className="text-muted text-[10px]">by {sreUser}</span>}
          </div>
          {(correctedSeverity || correctedNoise) && (
            <div className="flex gap-3 text-[10px] text-muted">
              {correctedSeverity && (
                <span>Severity: <span className={`font-medium ${severityColor(correctedSeverity)}`}>{correctedSeverity}</span></span>
              )}
              {correctedNoise && (
                <span>Noise: <span className="font-medium text-text">{correctedNoise}/10</span></span>
              )}
            </div>
          )}
          {comment && (
            <div className="text-xs text-text bg-bg rounded-md p-2 border border-border">{comment}</div>
          )}
          <button
            onClick={() => { setEditing(true); setJustSubmitted(false); }}
            className="text-[10px] text-accent hover:text-accent-hover transition-colors"
          >
            Update feedback
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          <div>
            <div className="text-[10px] text-muted mb-1.5">Is this analysis accurate?</div>
            <div className="flex gap-2">
              <button
                onClick={() => setRating('positive')}
                className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
                  rating === 'positive'
                    ? 'border-green bg-green/10 text-green'
                    : 'border-border text-muted hover:border-green/50 hover:text-green'
                }`}
              >
                &#x2713; Accurate
              </button>
              <button
                onClick={() => setRating('negative')}
                className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
                  rating === 'negative'
                    ? 'border-red bg-red/10 text-red'
                    : 'border-border text-muted hover:border-red/50 hover:text-red'
                }`}
              >
                &#x2717; Needs correction
              </button>
            </div>
          </div>

          {rating === 'negative' && (
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] text-muted block mb-1">Correct severity</label>
                <select
                  value={correctedSeverity}
                  onChange={(e) => setCorrectedSeverity(e.target.value)}
                  className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
                >
                  <option value="">No change ({enrichment.assessed_severity})</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="warning">Warning</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted block mb-1">Correct noise score</label>
                <select
                  value={correctedNoise}
                  onChange={(e) => setCorrectedNoise(e.target.value)}
                  className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
                >
                  <option value="">No change ({enrichment.noise_score}/10)</option>
                  {[1,2,3,4,5,6,7,8,9,10].map(n => (
                    <option key={n} value={n}>{n}/10 {n <= 3 ? '(actionable)' : n >= 7 ? '(noise)' : ''}</option>
                  ))}
                </select>
              </div>
            </div>
          )}

          {rating && (
            <div>
              <label className="text-[10px] text-muted block mb-1">
                {rating === 'positive' ? 'Notes (optional)' : 'What should the AI learn?'}
              </label>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                maxLength={500}
                rows={2}
                placeholder={rating === 'positive'
                  ? 'Additional context...'
                  : 'e.g. "Known maintenance window, noise should be higher"'
                }
                className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-y"
              />
            </div>
          )}

          {rating && (
            <div className="flex items-end gap-2">
              {sreUser && <span className="text-[10px] text-muted py-1.5">as {sreUser}</span>}
              <button
                onClick={handleSubmit}
                disabled={submitting || !rating}
                className="px-4 py-1.5 rounded-md bg-accent text-bg font-medium text-xs hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? 'Submitting...' : 'Submit'}
              </button>
              {editing && (
                <button
                  onClick={() => setEditing(false)}
                  className="px-3 py-1.5 rounded-md border border-border text-muted text-xs hover:text-text transition-colors"
                >
                  Cancel
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AlertActions({ alert, enrichment, onAlertChanged, alertState, onInvestigate, onAcknowledge }: {
  alert: Alert;
  enrichment: AIEnrichment | null;
  onAlertChanged: () => void;
  alertState?: AlertState;
  onInvestigate?: () => void;
  onAcknowledge?: () => void;
}) {
  const [resolving, setResolving] = useState(false);
  const [resolved, setResolved] = useState(false);
  const [showSilenceMenu, setShowSilenceMenu] = useState(false);
  const [silencing, setSilencing] = useState(false);
  const [silenced, setSilenced] = useState<string | null>(null);
  const [silenceError, setSilenceError] = useState(false);
  const [showIncidentForm, setShowIncidentForm] = useState(false);
  const [incidentResult, setIncidentResult] = useState<{ key: string; url: string } | null>(null);

  const host = alert.hostName || alert.hostname || '';
  const registryMatch = detectRegistryFromAlert(alert.name, host, alert.description);
  const registryMailto = registryMatch && registryMatch.operator.contacts[0]
    ? buildRegistryMailto(registryMatch.operator, registryMatch.operator.contacts[0], {
        alertName: alert.name,
        description: alert.description,
        startTime: alertStartTime(alert),
      })
    : null;

  async function handleResolve() {
    if (!confirm('Resolve this alert? It will be marked as resolved in Keep.')) return;
    setResolving(true);
    const ok = await resolveAlert(alert.fingerprint);
    setResolving(false);
    if (ok) {
      setResolved(true);
      onAlertChanged();
    }
  }

  async function handleSilence(seconds: number) {
    setSilencing(true);
    setShowSilenceMenu(false);
    setSilenceError(false);
    const ok = await silenceAlert(alert.name, seconds, host || undefined);
    setSilencing(false);
    if (ok) {
      const label = seconds >= 86400 ? '24h' : seconds >= 28800 ? '8h' : seconds >= 14400 ? '4h' : seconds >= 3600 ? '1h' : '30m';
      setSilenced(label);
    } else {
      setSilenceError(true);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {/* Resolve */}
        <button
          onClick={handleResolve}
          disabled={resolving || resolved}
          className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
            resolved
              ? 'border-green/40 bg-green/10 text-green cursor-default'
              : 'border-border text-muted hover:border-green/50 hover:text-green hover:bg-green/5'
          } disabled:opacity-60`}
        >
          {resolved ? '\u2713 Resolved' : resolving ? 'Resolving...' : 'Resolve'}
        </button>

        {/* Silence */}
        <div className="relative">
          <button
            onClick={() => setShowSilenceMenu(!showSilenceMenu)}
            disabled={silencing || !!silenced}
            className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
              silenced
                ? 'border-yellow/40 bg-yellow/10 text-yellow cursor-default'
                : 'border-border text-muted hover:border-yellow/50 hover:text-yellow hover:bg-yellow/5'
            } disabled:opacity-60`}
          >
            {silenced ? `Silenced (${silenced})` : silencing ? 'Silencing...' : 'Silence'}
          </button>
          {showSilenceMenu && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setShowSilenceMenu(false)} />
              <div className="absolute top-full left-0 mt-1 bg-surface border border-border rounded-lg shadow-xl z-20 py-1 min-w-[140px]">
                {[
                  { label: '30 minutes', seconds: 1800 },
                  { label: '1 hour', seconds: 3600 },
                  { label: '4 hours', seconds: 14400 },
                  { label: '8 hours', seconds: 28800 },
                  { label: '24 hours', seconds: 86400 },
                ].map(opt => (
                  <button
                    key={opt.seconds}
                    onClick={() => handleSilence(opt.seconds)}
                    className="w-full text-left px-3 py-1.5 text-xs text-text hover:bg-surface-hover transition-colors"
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Create Incident */}
        {incidentResult ? (
          <a
            href={incidentResult.url}
            target="_blank"
            rel="noopener noreferrer"
            className="px-3 py-1.5 rounded-md border border-accent/40 bg-accent/10 text-accent text-xs font-medium hover:bg-accent/20 transition-colors"
          >
            {incidentResult.key} &uarr;
          </a>
        ) : (
          <button
            onClick={() => setShowIncidentForm(!showIncidentForm)}
            className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
              showIncidentForm
                ? 'border-accent/40 bg-accent/10 text-accent'
                : 'border-border text-muted hover:border-accent/50 hover:text-accent hover:bg-accent/5'
            }`}
          >
            Create Incident
          </button>
        )}

        {/* Contact Registry */}
        {registryMailto && (
          <a
            href={registryMailto}
            className="px-3 py-1.5 rounded-md border border-blue/30 text-blue text-xs font-medium hover:bg-blue/10 hover:border-blue/50 transition-all inline-flex items-center gap-1"
            title={`Email ${registryMatch!.operator.name}`}
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            Contact {registryMatch!.operator.name.length > 20
              ? registryMatch!.operator.name.substring(0, 20) + '...'
              : registryMatch!.operator.name}
          </a>
        )}

        {/* Investigate Toggle */}
        {onInvestigate && (
          <button
            onClick={onInvestigate}
            className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all inline-flex items-center gap-1 ${
              alertState?.investigating_user
                ? 'border-blue/40 bg-blue/10 text-blue'
                : 'border-border text-muted hover:border-blue/50 hover:text-blue hover:bg-blue/5'
            }`}
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            {alertState?.investigating_user ? `Investigating (${alertState.investigating_user})` : 'Investigate'}
          </button>
        )}

        {/* Acknowledge */}
        {onAcknowledge && !alertState?.acknowledged_by && (
          <button
            onClick={onAcknowledge}
            className="px-3 py-1.5 rounded-md border border-border text-muted text-xs font-medium hover:border-green/50 hover:text-green hover:bg-green/5 transition-all inline-flex items-center gap-1"
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            Acknowledge
          </button>
        )}
        {alertState?.acknowledged_by && (
          <span className="px-3 py-1.5 rounded-md border border-green/40 bg-green/10 text-green text-xs font-medium inline-flex items-center gap-1">
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            Acked by {alertState.acknowledged_by}
          </span>
        )}
      </div>

      {silenceError && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">
          Failed to create silence rule. Check Keep maintenance API.
        </div>
      )}

      {/* Incident Form */}
      {showIncidentForm && !incidentResult && (
        <IncidentForm
          alert={alert}
          enrichment={enrichment}
          onCreated={(key, url) => {
            setIncidentResult({ key, url });
            setShowIncidentForm(false);
          }}
          onCancel={() => setShowIncidentForm(false)}
        />
      )}
    </div>
  );
}

const SEVERITY_CLASS_MAP: Record<string, string> = {
  critical: '11227',
  high: '11228',
  warning: '11229',
  low: '11230',
  info: '11230',
};

function detectService(alertName: string, hostname: string): string {
  const text = `${alertName} ${hostname}`.toLowerCase();
  if (text.includes('ascio')) return '11231';
  if (text.includes('enom')) return '11232';
  if (text.includes('opensrs')) return '11233';
  if (text.includes('hover')) return '11234';
  if (text.includes('hosted') && text.includes('email')) return '11235';
  if (text.includes('exacthosting')) return '11236';
  if (text.includes('trs')) return '11239';
  return '11237';
}

function IncidentForm({ alert, enrichment, onCreated, onCancel }: {
  alert: Alert;
  enrichment: AIEnrichment | null;
  onCreated: (key: string, url: string) => void;
  onCancel: () => void;
}) {
  const host = alert.hostName || alert.hostname || '';
  const sev = enrichment?.assessed_severity || 'unknown';

  const defaultDesc = [
    enrichment?.summary,
    enrichment?.likely_cause ? `Likely Cause: ${enrichment.likely_cause}` : null,
    enrichment?.impact_scope ? `Impact: ${enrichment.impact_scope}` : null,
    `Host: ${host}`,
    `Source: ${getSourceLabel(alert)}`,
    alert.description && alert.description !== alert.name ? `Details: ${alert.description}` : null,
  ].filter(Boolean).join('\n\n');

  const [summary, setSummary] = useState(host ? `${host} | ${alert.name}` : alert.name || 'Unknown Alert');
  const [description, setDescription] = useState(defaultDesc);
  const [classId, setClassId] = useState('11230');
  const [serviceId, setServiceId] = useState(detectService(alert.name, host));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [pastedImages, setPastedImages] = useState<{ data: string; filename: string; preview: string }[]>([]);

  function handlePaste(e: React.ClipboardEvent) {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (let i = 0; i < items.length; i++) {
      if (items[i].type.startsWith('image/')) {
        e.preventDefault();
        const file = items[i].getAsFile();
        if (!file) continue;
        const reader = new FileReader();
        reader.onload = () => {
          const dataUrl = reader.result as string;
          const base64 = dataUrl.split(',')[1];
          const ext = file.type.split('/')[1] || 'png';
          const filename = `screenshot_${Date.now()}.${ext}`;
          setPastedImages(prev => [...prev, { data: base64, filename, preview: dataUrl }]);
        };
        reader.readAsDataURL(file);
        break;
      }
    }
  }

  function removeImage(idx: number) {
    setPastedImages(prev => prev.filter((_, i) => i !== idx));
  }

  async function handleSubmit() {
    if (!summary.trim()) return;
    setSubmitting(true);
    setError('');

    const result = await createJiraIncident({
      summary: summary.trim(),
      description: description.trim(),
      classId,
      operationalServiceId: serviceId || undefined,
      alertLink: `http://10.177.154.196/portal/alerts/${alert.fingerprint}`,
      attachments: pastedImages.map(({ data, filename }) => ({ data, filename })),
    });

    setSubmitting(false);
    if (result.ok && result.issueKey) {
      onCreated(result.issueKey, result.issueUrl || '');
    } else {
      setError(result.error || 'Failed to create incident');
    }
  }

  return (
    <div className="bg-bg/60 border border-accent/20 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-accent">Create Jira Incident (OCCIR)</h4>
        <button onClick={onCancel} className="text-muted hover:text-text text-xs transition-colors">Cancel</button>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">{error}</div>
      )}

      <div>
        <label className="text-[10px] text-muted block mb-1">Summary</label>
        <input
          value={summary}
          onChange={(e) => setSummary(e.target.value)}
          className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
        />
      </div>

      <div>
        <label className="text-[10px] text-muted block mb-1">Description <span className="text-muted/60">(paste screenshots here)</span></label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          onPaste={handlePaste}
          rows={4}
          className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none resize-y"
        />
        {pastedImages.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-2">
            {pastedImages.map((img, idx) => (
              <div key={idx} className="relative group">
                <img
                  src={img.preview}
                  alt={img.filename}
                  className="h-16 w-auto rounded border border-border object-cover"
                />
                <button
                  onClick={() => removeImage(idx)}
                  className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-red text-bg rounded-full text-[10px] leading-none flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  x
                </button>
                <div className="text-[9px] text-muted truncate max-w-[80px] mt-0.5">{img.filename}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-[10px] text-muted block mb-1">Class</label>
          <select
            value={classId}
            onChange={(e) => setClassId(e.target.value)}
            className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
          >
            <option value="11230">Class IV - Informational</option>
            <option value="11229">Class III - Minor</option>
            <option value="11228">Class II - Major</option>
            <option value="11227">Class I - Critical</option>
          </select>
        </div>
        <div>
          <label className="text-[10px] text-muted block mb-1">Operational Service</label>
          <select
            value={serviceId}
            onChange={(e) => setServiceId(e.target.value)}
            className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
          >
            <option value="11231">Ascio</option>
            <option value="11232">Enom</option>
            <option value="11233">OpenSRS</option>
            <option value="11234">Hover</option>
            <option value="11235">Hosted Email</option>
            <option value="11236">ExactHosting</option>
            <option value="11237">Infrastructure</option>
            <option value="11239">TRS</option>
          </select>
        </div>
      </div>

      <div className="flex justify-end gap-2">
        <button
          onClick={onCancel}
          className="px-3 py-1.5 rounded-md border border-border text-muted text-xs hover:text-text transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={handleSubmit}
          disabled={submitting || !summary.trim()}
          className="px-4 py-1.5 rounded-md bg-accent text-bg font-medium text-xs hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? (pastedImages.length > 0 ? 'Creating & uploading...' : 'Creating...') : 'Create Incident'}
        </button>
      </div>
    </div>
  );
}

function RunbookPanel({ alert }: { alert: Alert }) {
  const [matches, setMatches] = useState<RunbookEntry[]>([]);
  const [loadingMatches, setLoadingMatches] = useState(true);
  const [remediation, setRemediation] = useState('');
  const [sreUser] = useState(() => getClientUsername() || '');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState(false);

  const host = alert.hostName || alert.hostname || '';

  useEffect(() => {
    setLoadingMatches(true);
    fetchRunbookMatches(alert.name, host || undefined)
      .then(setMatches)
      .finally(() => setLoadingMatches(false));
  }, [alert.name, host]);

  async function handleSubmit() {
    if (!remediation.trim()) return;
    setSubmitting(true);
    setSubmitError(false);

    const enrichment = parseAIEnrichment(alert.note);
    const ok = await submitRunbookEntry({
      alert_name: alert.name,
      alert_fingerprint: alert.fingerprint,
      hostname: host || undefined,
      severity: enrichment?.assessed_severity || alert.severity,
      remediation: remediation.trim(),
      sre_user: sreUser || undefined,
    });

    setSubmitting(false);
    if (ok) {
      setSubmitted(true);
      setRemediation('');
      fetchRunbookMatches(alert.name, host || undefined).then(setMatches);
    } else {
      setSubmitError(true);
    }
  }

  return (
    <div className="bg-bg/40 border border-accent/20 rounded-lg px-4 py-3">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-semibold text-accent">Runbook &amp; Remediation</h4>
        <span className="text-[10px] text-muted">Build institutional knowledge</span>
      </div>

      {loadingMatches ? (
        <div className="text-xs text-muted animate-pulse mb-3">Loading runbook entries...</div>
      ) : matches.length > 0 ? (
        <div className="space-y-2 mb-4">
          <div className="text-[10px] text-muted uppercase tracking-wider">
            Past remediations for similar alerts ({matches.length})
          </div>
          {matches.map((entry) => (
            <div key={entry.id} className="bg-bg rounded-md p-2.5 border border-border">
              <div className="flex items-center gap-2 text-[10px] text-muted mb-1">
                <span>{entry.created_at?.substring(0, 10)}</span>
                {entry.sre_user && <span>by {entry.sre_user}</span>}
                {entry.hostname && <span className="font-mono">{entry.hostname}</span>}
                {entry.score != null && <span className="text-accent">relevance: {entry.score}</span>}
              </div>
              <div className="text-[10px] text-muted mb-0.5 truncate">
                Alert: {entry.alert_name?.substring(0, 80)}
              </div>
              <div className="text-xs text-text whitespace-pre-wrap">{entry.remediation}</div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-xs text-muted mb-3">
          No past remediations found for similar alerts. Be the first to document one.
        </div>
      )}

      {submitted && (
        <div className="bg-green/10 border border-green/30 rounded-lg px-3 py-2 mb-3">
          <div className="text-xs text-green">Remediation saved to runbook. It will be used to improve future AI analysis.</div>
        </div>
      )}

      {submitError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-3 py-2 mb-3">
          <div className="text-xs text-red">Failed to save. Please try again.</div>
        </div>
      )}

      <div className="space-y-2">
        <label className="text-[10px] text-muted block">
          What was the remediation? (Steps taken or needed to resolve this alert)
        </label>
        <textarea
          value={remediation}
          onChange={(e) => { setRemediation(e.target.value); setSubmitted(false); }}
          maxLength={5000}
          rows={3}
          placeholder="e.g. Restarted the bind9 service on prod-dns01. Root cause was recursive query loop from partner traffic spike. Applied rate limiting rule."
          className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-y"
        />
        <div className="flex items-end gap-2">
          {sreUser && <span className="text-[10px] text-muted py-1.5">as {sreUser}</span>}
          <button
            onClick={handleSubmit}
            disabled={submitting || !remediation.trim()}
            className="ml-auto px-4 py-1.5 rounded-md bg-accent text-bg font-medium text-xs hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitting ? 'Saving...' : 'Save to Runbook'}
          </button>
        </div>
      </div>
    </div>
  );
}
