'use client';

import { Fragment, useState, useMemo, useEffect } from 'react';
import { Alert, AlertStats, AlertState } from '@/lib/types';
import {
  parseAIEnrichment,
  computeStats,
  severityColor,
  severityBg,
  timeAgo,
  alertStartTime,
  getSourceLabel,
} from '@/lib/keep-api';

/* ── Alert Grouping (duplicated from page-level helpers) ── */

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

  Array.from(nameMap.values()).forEach(g => multiGroups.push(g));

  const result = multiGroups.map(g => {
    let best = 5;
    for (const a of g.alerts) {
      const sev = parseAIEnrichment(a.note)?.assessed_severity ?? 'unknown';
      best = Math.min(best, sevOrder[sev] ?? 5);
    }
    g.highestSeverity = sevNames[best];
    return g;
  });

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

/* ── Sub-components ── */

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

/* ── Main DashboardView ── */

export interface DashboardViewProps {
  alerts: Alert[];
  alertStates: Map<string, AlertState>;
  loading: boolean;
  onAlertClick: (alert: Alert) => void;
  onInvestigate: (alert: Alert) => void;
  onAcknowledge: (alert: Alert) => void;
  onUnacknowledge: (alert: Alert) => void;
  onGroupAcknowledge: (fingerprints: string[], names: Record<string, string>, starts: Record<string, string>) => void;
  onRefresh: () => void;
}

export default function DashboardView({
  alerts,
  alertStates,
  loading,
  onAlertClick,
  onInvestigate,
  onAcknowledge,
  onUnacknowledge,
  onGroupAcknowledge,
}: DashboardViewProps) {
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [sortKey, setSortKey] = useState<'severity' | 'alert' | 'host' | 'source' | 'summary' | 'time'>('time');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [pageSize, setPageSize] = useState(10);
  const [currentPage, setCurrentPage] = useState(0);
  const [groupView, setGroupView] = useState(true);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [dashboardTab, setDashboardTab] = useState<'firing' | 'acknowledged'>('firing');

  const activeAlerts = alerts.filter(a => a.status !== 'resolved' && a.status !== 'ok');
  const firingAlerts = activeAlerts.filter(a => !alertStates.get(a.fingerprint)?.acknowledged_by);
  const ackedAlerts = activeAlerts.filter(a => !!alertStates.get(a.fingerprint)?.acknowledged_by);
  const tabAlerts = dashboardTab === 'firing' ? firingAlerts : ackedAlerts;

  const stats = useMemo(() => computeStats(firingAlerts), [firingAlerts]);

  const sevOrder: Record<string, number> = { critical: 0, high: 1, warning: 2, low: 3, info: 4, unknown: 5 };

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

  function toggleGroup(key: string) {
    setExpandedGroups(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function handleGroupAck(group: AlertGroup) {
    const fps = group.alerts.map(a => a.fingerprint);
    const names: Record<string, string> = {};
    const starts: Record<string, string> = {};
    for (const a of group.alerts) {
      names[a.fingerprint] = a.name || '';
      starts[a.fingerprint] = alertStartTime(a);
    }
    onGroupAcknowledge(fps, names, starts);
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
                                  onClick={(e) => { e.stopPropagation(); handleGroupAck(group); }}
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
                            onOpenDetail={() => onAlertClick(alert)}
                            indented
                            alertState={alertStates.get(alert.fingerprint)}
                            onInvestigate={() => onInvestigate(alert)}
                            onAcknowledge={dashboardTab === 'firing' ? () => onAcknowledge(alert) : undefined}
                            onUnacknowledge={dashboardTab === 'acknowledged' ? () => onUnacknowledge(alert) : undefined}
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
                      onOpenDetail={() => onAlertClick(group.alerts[0])}
                      alertState={alertStates.get(group.alerts[0].fingerprint)}
                      onInvestigate={() => onInvestigate(group.alerts[0])}
                      onAcknowledge={dashboardTab === 'firing' ? () => onAcknowledge(group.alerts[0]) : undefined}
                      onUnacknowledge={dashboardTab === 'acknowledged' ? () => onUnacknowledge(group.alerts[0]) : undefined}
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
                        onOpenDetail={() => onAlertClick(alert)}
                        alertState={alertStates.get(alert.fingerprint)}
                        onInvestigate={() => onInvestigate(alert)}
                        onAcknowledge={dashboardTab === 'firing' ? () => onAcknowledge(alert) : undefined}
                        onUnacknowledge={dashboardTab === 'acknowledged' ? () => onUnacknowledge(alert) : undefined}
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
    </div>
  );
}
