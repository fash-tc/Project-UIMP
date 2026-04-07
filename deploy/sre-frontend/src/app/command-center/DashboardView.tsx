'use client';

import { Fragment, useState, useMemo, useEffect } from 'react';
import { Alert, AlertStats, AlertState, CustomAlertGroup } from '@/lib/types';
import {
  parseAIEnrichment,
  computeStats,
  severityColor,
  severityBg,
  timeAgo,
  alertStartTime,
  getSourceLabel,
  overrideSeverity,
  overrideSeverityBulk,
  forceEnrich,
  isAlertSilenced,
  SilenceRule,
  fetchAlertRules,
  AlertRule,
  matchHighlightRules,
  colorWithAlpha,
} from '@/lib/keep-api';
import SituationCard from './SituationCard';
import IncidentWizard from './IncidentWizard';
import { AlertRulesManager } from '../alert-rules/AlertRulesManager';
import StatuspageTab from './StatuspageTab';

const ZABBIX_URLS: Record<string, string> = {
  'domains-shared': 'https://zabbix.prod-domains-shared.bra2.tucows.systems',
  'ascio': 'https://zabbix.ascio.com',
  'hostedemail': 'https://zabbix.a.tucows.com',
  'enom': 'https://zabbix.enom.net',
  'iaas': 'https://zabbix.tucows.cloud',
};

/* â”€â”€ Alert Grouping (duplicated from page-level helpers) â”€â”€ */

interface AlertGroup {
  key: string;
  label: string;
  alerts: Alert[];
  highestSeverity: string;
  groupType?: 'custom' | 'inferred';
  customGroupId?: number;
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
  // Normalize: strip trailing digits from each part so dns1/dns2 -> dns, host01/host02 -> host
  const parent = parts.slice(1).join('.');
  return parent;
}

/** Normalize a domain by stripping trailing digits from each segment.
 *  e.g. "dns1.tucows.net" -> "dns.tucows.net", "host02.prod.aws" -> "host.prod.aws" */
function normalizeDomain(domain: string): string {
  if (!domain) return '';
  return domain.split('.').map(p => p.replace(/\d+$/, '')).join('.');
}

function buildAlertGroups(alerts: Alert[], sortKey: string = 'severity', sortDir: 'asc' | 'desc' = 'desc', alertStatesMap?: Map<string, AlertState>): AlertGroup[] {
  const sevOrder: Record<string, number> = { critical: 0, high: 1, warning: 2, low: 3, info: 4, unknown: 5 };
  const sevNames = ['critical', 'high', 'warning', 'low', 'info', 'unknown'];

  const domainMap = new Map<string, AlertGroup>();
  for (const alert of alerts) {
    const host = alert.hostName || alert.hostname || '';
    const base = extractAlertBase(alert.name || '', host);
    const parent = getParentDomain(host);
    // Use normalized domain for grouping key so dns1.tucows.net and dns2.tucows.net merge
    const normalizedParent = normalizeDomain(parent);
    const key = `${base}::${normalizedParent}`;

    if (!domainMap.has(key)) {
      // Use the normalized domain as display label (with wildcard hint if different from raw)
      const displayParent = normalizedParent !== parent && parent
        ? parent.split('.').map(p => p.replace(/\d+$/, '') ? p.replace(/\d+$/, '*') : p).join('.')
        : parent;
      const label = displayParent ? `${base} â€” ${displayParent}` : base;
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
      // Severity override takes precedence over AI enrichment
      const override = alertStatesMap?.get(a.fingerprint)?.severity_override;
      const sev = override || parseAIEnrichment(a.note)?.assessed_severity || 'unknown';
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

/* â”€â”€ Sub-components â”€â”€ */

function getHighestSeverity(alerts: Alert[], alertStatesMap?: Map<string, AlertState>): string {
  const sevOrder: Record<string, number> = { critical: 0, high: 1, warning: 2, low: 3, info: 4, unknown: 5 };
  const sevNames = ['critical', 'high', 'warning', 'low', 'info', 'unknown'];
  let best = 5;
  for (const alert of alerts) {
    const override = alertStatesMap?.get(alert.fingerprint)?.severity_override;
    const sev = override || parseAIEnrichment(alert.note)?.assessed_severity || 'unknown';
    best = Math.min(best, sevOrder[sev] ?? 5);
  }
  return sevNames[best];
}

function buildDisplayAlertGroups(
  alerts: Alert[],
  customGroups: CustomAlertGroup[],
  sortKey: string,
  sortDir: 'asc' | 'desc',
  alertStatesMap?: Map<string, AlertState>,
): AlertGroup[] {
  const alertByFingerprint = new Map(alerts.map(alert => [alert.fingerprint, alert] as const));
  const claimed = new Set<string>();
  const persistedGroups: AlertGroup[] = customGroups.map(group => {
    const groupAlerts = group.fingerprints
      .map(fingerprint => alertByFingerprint.get(fingerprint))
      .filter((alert): alert is Alert => Boolean(alert));
    groupAlerts.forEach(alert => claimed.add(alert.fingerprint));
    return {
      key: `custom::${group.id}`,
      label: group.name,
      alerts: groupAlerts,
      highestSeverity: getHighestSeverity(groupAlerts, alertStatesMap),
      groupType: 'custom' as const,
      customGroupId: group.id,
    };
  }).filter(group => group.alerts.length > 0);

  const inferredGroups = buildAlertGroups(
    alerts.filter(alert => !claimed.has(alert.fingerprint)),
    sortKey,
    sortDir,
    alertStatesMap,
  ).map(group => ({
    ...group,
    groupType: 'inferred' as const,
  }));

  return [...persistedGroups, ...inferredGroups];
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

function AlertRow({ alert, expanded, onToggleExpand, onOpenDetail, indented, alertState, onInvestigate, onAcknowledge, onUnacknowledge, showAckInfo, highlightColor, highlightLabel, highlightStyle, customGroupName, isSelected, onToggleSelect }: {
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
  highlightColor?: string;
  highlightLabel?: string;
  highlightStyle?: 'side' | 'box';
  customGroupName?: string;
  isSelected?: boolean;
  onToggleSelect?: () => void;
}) {
  const [severityDropdown, setSeverityDropdown] = useState<boolean>(false);
  const enrichment = parseAIEnrichment(alert.note);
  const displaySeverity = alertState?.severity_override || enrichment?.assessed_severity || alert.severity || 'unknown';
  const sev = displaySeverity;
  const host = alert.hostName || alert.hostname || '';
  const source = getSourceLabel(alert);
  const summary = enrichment?.summary || '';
  const description = alert.description && alert.description !== alert.name ? alert.description : '';

  const truncatedSummary = summary.length > 80 ? summary.substring(0, 80) + '...' : summary;
  const truncatedDesc = description.length > 80 ? description.substring(0, 80) + '...' : description;
  const hasExpandableContent = summary.length > 80 || description.length > 80;

  return (
    <tr
      className={`border-b border-border/50 hover:bg-surface-hover transition-colors ${indented ? 'bg-bg/20' : ''} ${isSelected ? 'bg-accent/5' : ''}`}
      style={highlightColor ? (
        highlightStyle === 'box'
          ? {
              borderLeft: `3px solid ${highlightColor}`,
              backgroundColor: colorWithAlpha(highlightColor, 0.12),
              boxShadow: `inset 0 0 0 1px ${colorWithAlpha(highlightColor, 0.28)}`,
            }
          : { borderLeft: `3px solid ${highlightColor}` }
      ) : undefined}
    >
      <td className={`table-cell ${indented ? 'pl-6' : ''}`}>
        <input
          type="checkbox"
          checked={Boolean(isSelected)}
          onChange={(e) => {
            e.stopPropagation();
            onToggleSelect?.();
          }}
          onClick={(e) => e.stopPropagation()}
        />
      </td>
      <td className={`table-cell ${indented ? 'pl-10' : ''}`}>
        <div className="relative">
          <button
            onClick={(e) => {
              e.stopPropagation();
              setSeverityDropdown(v => !v);
            }}
            className={`text-xs px-1.5 py-0.5 rounded border ${severityBg(sev)} ${severityColor(sev)} cursor-pointer hover:ring-1 hover:ring-accent/50 transition-all`}
            title={alertState?.severity_override ? `Overridden severity` : 'Click to override severity'}
          >
            {sev}
            {alertState?.severity_override && <span className="ml-0.5 opacity-60">â€¢</span>}
          </button>
          {severityDropdown && (
            <div className="absolute z-50 top-full mt-1 left-0 bg-surface border border-border rounded-md shadow-lg py-1 min-w-[100px]">
              {['critical', 'high', 'warning', 'info'].map(s => (
                <button
                  key={s}
                  onClick={async (e) => {
                    e.stopPropagation();
                    await overrideSeverity(alert.fingerprint, s);
                    setSeverityDropdown(false);
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
                    setSeverityDropdown(false);
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
          <button
            onClick={onOpenDetail}
            className="text-left text-text-bright hover:text-accent transition-colors"
          >
            {alert.name?.substring(0, 60) || 'Unknown'}
            {(alert.name?.length ?? 0) > 60 ? '...' : ''}
          </button>
          {highlightLabel && (
            <span
              className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium whitespace-nowrap"
              style={{ backgroundColor: `${highlightColor}20`, color: highlightColor, border: `1px solid ${highlightColor}40` }}
            >
              {highlightLabel}
            </span>
          )}
          {customGroupName && (
            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium whitespace-nowrap bg-accent/10 border border-accent/30 text-accent">
              {customGroupName}
            </span>
          )}
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
          {alertState?.incident_jira_key && (
            <a
              href={alertState.incident_jira_url || '#'}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              title={`Incident created by ${alertState.incident_created_by || 'unknown'}${alertState.incident_created_at ? ', ' + timeAgo(alertState.incident_created_at) : ''}`}
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-purple/10 border border-purple/30 text-purple whitespace-nowrap hover:bg-purple/20 transition-all duration-200"
            >
              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M10.172 13.828a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.102 1.101" />
              </svg>
              {alertState.incident_jira_key}
            </a>
          )}
          {alertState?.escalated_to && (
            <span
              title={`Escalated by ${alertState.escalated_by || 'unknown'}${alertState.escalated_at ? ', ' + timeAgo(alertState.escalated_at) : ''}`}
              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-amber/10 border border-amber/30 text-amber whitespace-nowrap transition-all duration-200"
            >
              <svg className="w-2.5 h-2.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 10l7-7m0 0l7 7m-7-7v18" />
              </svg>
              {alertState.escalated_to}
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
        {!alert.note && (
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
        )}
        {alert.note && !summary && <span>--</span>}
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

function CustomGroupControls({
  group,
  isOpen,
  selectedFingerprints,
  resolving,
  onToggle,
  onRename,
  onAddSelectedAlerts,
  onAcknowledge,
  onResolve,
  onSetSeverity,
  onSilenceGroup,
}: {
  group: AlertGroup;
  isOpen: boolean;
  selectedFingerprints: Set<string>;
  resolving: boolean;
  onToggle: (open: boolean) => void;
  onRename: () => void;
  onAddSelectedAlerts: () => Promise<void>;
  onAcknowledge: () => void;
  onResolve: () => Promise<void>;
  onSetSeverity: (severity: string) => Promise<void>;
  onSilenceGroup?: (alertNamePattern: string, durationSeconds: number, hostnamePattern?: string) => Promise<void>;
}) {
  const groupFingerprints = new Set(group.alerts.map(alert => alert.fingerprint));
  const addableCount = Array.from(selectedFingerprints).filter(fp => !groupFingerprints.has(fp)).length;
  const alertBase = group.label.split(' Ã¢â‚¬â€ ')[0] || group.label;
  const hostPart = group.label.split(' Ã¢â‚¬â€ ')[1] || undefined;
  const durations = [
    { label: '1 hour', seconds: 3600 },
    { label: '4 hours', seconds: 14400 },
    { label: '8 hours', seconds: 28800 },
    { label: '24 hours', seconds: 86400 },
    { label: '7 days', seconds: 604800 },
  ];

  return (
    <div className="relative">
      <button
        onClick={(e) => {
          e.stopPropagation();
          onToggle(!isOpen);
        }}
        className="text-[10px] px-2 py-0.5 rounded border border-border text-muted hover:text-text-bright hover:border-accent/50 transition-colors"
      >
        Group Controls
      </button>
      {isOpen && (
        <div
          className="absolute z-50 top-full mt-1 right-0 bg-surface border border-border rounded-md shadow-lg py-1 min-w-[220px]"
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={onRename}
            className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-text"
          >
            Rename Group
          </button>
          <button
            onClick={() => void onAddSelectedAlerts()}
            disabled={addableCount === 0}
            className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-text disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Add Selected Alerts{addableCount > 0 ? ` (${addableCount})` : ''}
          </button>
          <div className="border-t border-border my-1" />
          <button
            onClick={() => {
              onAcknowledge();
              onToggle(false);
            }}
            className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-green"
          >
            Acknowledge Group
          </button>
          <button
            onClick={() => void onResolve().then(() => onToggle(false))}
            disabled={resolving}
            className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-accent disabled:opacity-40"
          >
            {resolving ? 'Resolving...' : 'Resolve Group'}
          </button>
          <div className="border-t border-border my-1" />
          <div className="px-3 py-1 text-[10px] text-muted uppercase tracking-wide">Set Severity</div>
          {['critical', 'high', 'warning', 'info'].map(severity => (
            <button
              key={severity}
              onClick={() => void onSetSeverity(severity)}
              className={`block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors ${severityColor(severity)}`}
            >
              {severity}
            </button>
          ))}
          <button
            onClick={() => void onSetSeverity('none')}
            className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-muted"
          >
            Reset to AI
          </button>
          {onSilenceGroup && (
            <>
              <div className="border-t border-border my-1" />
              <div className="px-3 py-1 text-[10px] text-muted uppercase tracking-wide">Silence</div>
              {durations.map(opt => (
                <button
                  key={`custom-group-${group.key}-${opt.seconds}`}
                  onClick={() => void onSilenceGroup(alertBase, opt.seconds, hostPart).then(() => onToggle(false))}
                  className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-text"
                >
                  {opt.label}
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function CustomGroupControlsButton({
  onOpen,
}: {
  onOpen: () => void;
}) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        onOpen();
      }}
      className="text-[10px] px-2 py-0.5 rounded border border-border text-muted hover:text-text-bright hover:border-accent/50 transition-colors whitespace-nowrap"
    >
      Group Controls
    </button>
  );
}

function CustomGroupControlsModal({
  group,
  selectedFingerprints,
  resolving,
  onClose,
  onRename,
  onAddSelectedAlerts,
  onAcknowledge,
  onResolve,
  onSetSeverity,
  onSilenceGroup,
}: {
  group: AlertGroup;
  selectedFingerprints: Set<string>;
  resolving: boolean;
  onClose: () => void;
  onRename: () => void;
  onAddSelectedAlerts: () => Promise<boolean>;
  onAcknowledge: () => void;
  onResolve: () => Promise<void>;
  onSetSeverity: (severity: string) => Promise<void>;
  onSilenceGroup?: (alertNamePattern: string, durationSeconds: number, hostnamePattern?: string) => Promise<void>;
}) {
  const groupFingerprints = new Set(group.alerts.map(alert => alert.fingerprint));
  const addableCount = Array.from(selectedFingerprints).filter(fp => !groupFingerprints.has(fp)).length;
  const alertBase = group.label;
  const hostPart: string | undefined = undefined;
  const durations = [
    { label: '1 hour', seconds: 3600 },
    { label: '4 hours', seconds: 14400 },
    { label: '8 hours', seconds: 28800 },
    { label: '24 hours', seconds: 86400 },
    { label: '7 days', seconds: 604800 },
  ];

  return (
    <div className="fixed inset-0 z-[125] flex items-start justify-center">
      <div className="absolute inset-0 bg-bg/80 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md mt-[10vh] mx-4 bg-surface border border-border rounded-xl shadow-2xl overflow-hidden">
        <div className="flex items-start justify-between gap-4 px-5 py-4 border-b border-border">
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-[0.2em] text-muted mb-1">Custom Group Controls</div>
            <h3 className="text-base font-semibold text-text-bright truncate" title={group.label}>
              {group.label}
            </h3>
            <p className="text-xs text-muted mt-1">
              Manage this custom group outside the alert table so the row stays readable.
            </p>
          </div>
          <button onClick={onClose} className="text-muted hover:text-text text-sm whitespace-nowrap">Close</button>
        </div>
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="rounded-lg border border-border bg-bg/40 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wide text-muted">Alerts</div>
              <div className="text-sm text-text-bright mt-1">{group.alerts.length}</div>
            </div>
            <div className="rounded-lg border border-border bg-bg/40 px-3 py-2">
              <div className="text-[10px] uppercase tracking-wide text-muted">Addable Selected</div>
              <div className="text-sm text-text-bright mt-1">{addableCount}</div>
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-[10px] text-muted uppercase tracking-wide">Group</div>
            <button
              onClick={() => {
                onRename();
                onClose();
              }}
              className="block w-full text-left text-xs px-3 py-2 rounded-md border border-border hover:bg-surface-hover transition-colors text-text"
            >
              Rename Group
            </button>
            <button
              onClick={async () => {
                const added = await onAddSelectedAlerts();
                if (added) onClose();
              }}
              disabled={addableCount === 0}
              className="block w-full text-left text-xs px-3 py-2 rounded-md border border-border hover:bg-surface-hover transition-colors text-text disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Add Selected Alerts{addableCount > 0 ? ` (${addableCount})` : ''}
            </button>
          </div>

          <div className="space-y-2">
            <div className="text-[10px] text-muted uppercase tracking-wide">Actions</div>
            <button
              onClick={() => {
                onAcknowledge();
                onClose();
              }}
              className="block w-full text-left text-xs px-3 py-2 rounded-md border border-green/30 bg-green/5 hover:bg-green/10 transition-colors text-green"
            >
              Acknowledge Group
            </button>
            <button
              onClick={() => void onResolve().then(() => onClose())}
              disabled={resolving}
              className="block w-full text-left text-xs px-3 py-2 rounded-md border border-accent/30 bg-accent/5 hover:bg-accent/10 transition-colors text-accent disabled:opacity-40"
            >
              {resolving ? 'Resolving...' : 'Resolve Group'}
            </button>
          </div>

          <div className="space-y-2">
            <div className="text-[10px] text-muted uppercase tracking-wide">Set Severity</div>
            {['critical', 'high', 'warning', 'info'].map(severity => (
              <button
                key={severity}
                onClick={() => void onSetSeverity(severity).then(() => onClose())}
                className={`block w-full text-left text-xs px-3 py-2 rounded-md border border-border hover:bg-surface-hover transition-colors ${severityColor(severity)}`}
              >
                {severity}
              </button>
            ))}
            <button
              onClick={() => void onSetSeverity('none').then(() => onClose())}
              className="block w-full text-left text-xs px-3 py-2 rounded-md border border-border hover:bg-surface-hover transition-colors text-muted"
            >
              Reset to AI
            </button>
          </div>

          {onSilenceGroup && (
            <div className="space-y-2">
              <div className="text-[10px] text-muted uppercase tracking-wide">Silence</div>
              {durations.map(opt => (
                <button
                  key={`custom-group-${group.key}-${opt.seconds}`}
                  onClick={() => void onSilenceGroup(alertBase || group.label, opt.seconds, hostPart).then(() => onClose())}
                  className="block w-full text-left text-xs px-3 py-2 rounded-md border border-border hover:bg-surface-hover transition-colors text-text"
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function RenameCustomGroupModal({
  groupName,
  onChangeName,
  onClose,
  onSubmit,
}: {
  groupName: string;
  onChangeName: (value: string) => void;
  onClose: () => void;
  onSubmit: () => Promise<void>;
}) {
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit() {
    if (!groupName.trim()) return;
    setSubmitting(true);
    await onSubmit();
    setSubmitting(false);
  }

  return (
    <div className="fixed inset-0 z-[120] flex items-start justify-center">
      <div className="absolute inset-0 bg-bg/80 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md mt-[12vh] mx-4 bg-surface border border-border rounded-xl shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div>
            <h3 className="text-base font-semibold text-text-bright">Rename Custom Group</h3>
            <p className="text-xs text-muted mt-1">Update the shared name operators see for this temporary group.</p>
          </div>
          <button onClick={onClose} className="text-muted hover:text-text text-sm">Close</button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="text-[10px] text-muted block mb-1">Group Name</label>
            <input
              value={groupName}
              onChange={(e) => onChangeName(e.target.value)}
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
              placeholder="Enter a shared temporary group name"
            />
          </div>
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-md border border-border text-sm text-muted hover:text-text transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={() => void handleSubmit()}
              disabled={submitting || !groupName.trim()}
              className="px-4 py-2 rounded-md bg-accent text-bg text-sm font-medium hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Saving...' : 'Rename Group'}
            </button>
          </div>
        </div>
      </div>
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

/* â”€â”€ Main DashboardView â”€â”€ */

export interface DashboardViewProps {
  alerts: Alert[];
  alertStates: Map<string, AlertState>;
  customGroups: CustomAlertGroup[];
  selectedFingerprints: Set<string>;
  loading: boolean;
  onAlertClick: (alert: Alert) => void;
  onToggleSelectAlert: (fingerprint: string) => void;
  onSetSelectedAlerts: (fingerprints: string[], selected: boolean) => void;
  onInvestigate: (alert: Alert) => void;
  onAcknowledge: (alert: Alert) => void;
  onUnacknowledge: (alert: Alert) => void;
  onGroupAcknowledge: (fingerprints: string[], names: Record<string, string>, starts: Record<string, string>) => void;
  onGroupResolve: (fingerprints: string[]) => Promise<void>;
  onGroupUnresolve?: (fingerprints: string[]) => Promise<void>;
  onForceEnrich?: (fingerprint: string) => Promise<void>;
  onRenameCustomGroup?: (groupId: number, name: string) => Promise<{ ok: boolean; error?: string }>;
  onAddSelectedAlertsToCustomGroup?: (groupId: number, fingerprints: string[]) => Promise<{ ok: boolean; error?: string }>;
  onRefresh: () => void;
  sseUpdateTrigger?: number;
  silenceRules?: SilenceRule[];
  onSilenceGroup?: (alertNamePattern: string, durationSeconds: number, hostnamePattern?: string) => Promise<void>;
  onCancelSilence?: (ruleId: number) => Promise<void>;
}

function isSuppressedNote(note: string | undefined | null): boolean {
  if (!note) return false;
  return note.startsWith('NOISE:') || note.startsWith('ENRICHMENT (copied');
}

export default function DashboardView({
  alerts,
  alertStates,
  customGroups,
  selectedFingerprints,
  loading,
  onAlertClick,
  onToggleSelectAlert,
  onSetSelectedAlerts,
  onInvestigate,
  onAcknowledge,
  onUnacknowledge,
  onGroupAcknowledge,
  onGroupResolve,
  onGroupUnresolve,
  onForceEnrich,
  onRenameCustomGroup,
  onAddSelectedAlertsToCustomGroup,
  onRefresh,
  sseUpdateTrigger,
  silenceRules = [],
  onSilenceGroup,
  onCancelSilence,
}: DashboardViewProps) {
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [clusterFilter, setClusterFilter] = useState<string[] | null>(null);
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());
  const [sortKey, setSortKey] = useState<'severity' | 'alert' | 'host' | 'source' | 'summary' | 'time'>('time');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [pageSize, setPageSize] = useState(10);
  const [currentPage, setCurrentPage] = useState(0);
  const [groupView, setGroupView] = useState(true);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [dashboardTab, setDashboardTab] = useState<'firing' | 'acknowledged' | 'suppressed' | 'silenced' | 'rules' | 'statuspage'>('firing');
  const [statuspageIncidentCount, setStatuspageIncidentCount] = useState(0);
  const [silenceDropdown, setSilenceDropdown] = useState<string | null>(null);
  const [showIncidentWizard, setShowIncidentWizard] = useState(false);
  const [highlightRules, setHighlightRules] = useState<AlertRule[]>([]);

  useEffect(() => {
    fetchAlertRules('highlight').then(setHighlightRules);
  }, []);

  const activeAlerts = alerts.filter(a => a.status !== 'resolved' && a.status !== 'ok');
  const suppressedAlerts = activeAlerts.filter(a => isSuppressedNote(a.note));
  const nonSuppressedAlerts = activeAlerts.filter(a => !isSuppressedNote(a.note));
  // Separate silenced alerts (matched by active silence rules)
  const silencedAlerts = nonSuppressedAlerts.filter(a => {
    const host = a.hostName || a.hostname || '';
    return isAlertSilenced(a.name || '', host, silenceRules) !== null;
  });
  const silencedFingerprints = new Set(silencedAlerts.map(a => a.fingerprint));
  const nonSilencedAlerts = nonSuppressedAlerts.filter(a => !silencedFingerprints.has(a.fingerprint));
  const firingAlerts = nonSilencedAlerts.filter(a => !alertStates.get(a.fingerprint)?.acknowledged_by);
  const ackedAlerts = nonSilencedAlerts.filter(a => !!alertStates.get(a.fingerprint)?.acknowledged_by);
  const tabAlerts = dashboardTab === 'firing' ? firingAlerts
    : dashboardTab === 'acknowledged' ? ackedAlerts
    : dashboardTab === 'silenced' ? silencedAlerts
    : dashboardTab === 'statuspage' || dashboardTab === 'rules' ? []
    : suppressedAlerts;
  const isRulesTab = dashboardTab === 'rules';
  const isStatuspageTab = dashboardTab === 'statuspage';

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

  const alertGroups = useMemo(
    () => groupView ? buildDisplayAlertGroups(sortedAlerts, customGroups, sortKey, sortDir, alertStates) : [],
    [sortedAlerts, customGroups, groupView, sortKey, sortDir, alertStates],
  );

  const displayAlerts = clusterFilter
    ? filteredAlerts.filter(a => clusterFilter.includes(a.fingerprint))
    : sortedAlerts;

  const totalPages = Math.max(1, Math.ceil(displayAlerts.length / pageSize));
  const safePage = Math.min(currentPage, totalPages - 1);
  const pagedAlerts = displayAlerts.slice(safePage * pageSize, (safePage + 1) * pageSize);
  const hasFilter = sevFilter !== null || clusterFilter !== null;
  const customGroupByFingerprint = useMemo(() => {
    const map = new Map<string, string>();
    customGroups.forEach(group => group.fingerprints.forEach(fp => map.set(fp, group.name)));
    return map;
  }, [customGroups]);
  const visibleFingerprints = useMemo(
    () => (groupView ? alertGroups.flatMap(group => group.alerts.map(alert => alert.fingerprint)) : pagedAlerts.map(alert => alert.fingerprint)),
    [groupView, alertGroups, pagedAlerts],
  );
  const allVisibleSelected = visibleFingerprints.length > 0 && visibleFingerprints.every(fp => selectedFingerprints.has(fp));

  useEffect(() => { setCurrentPage(0); }, [sevFilter, clusterFilter, pageSize]);

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

  const [resolvingGroups, setResolvingGroups] = useState<Set<string>>(new Set());
  const [groupSevDropdown, setGroupSevDropdown] = useState<string | null>(null);
  const [groupControlsTarget, setGroupControlsTarget] = useState<AlertGroup | null>(null);
  const [renameTargetGroup, setRenameTargetGroup] = useState<AlertGroup | null>(null);
  const [renameGroupName, setRenameGroupName] = useState('');
  const [groupActionError, setGroupActionError] = useState<string | null>(null);

  async function handleGroupResolve(group: AlertGroup) {
    if (!confirm(`Resolve all ${group.alerts.length} alerts in "${group.label}"?`)) return;
    setResolvingGroups(prev => new Set(prev).add(group.key));
    await onGroupResolve(group.alerts.map(a => a.fingerprint));
    setResolvingGroups(prev => { const n = new Set(prev); n.delete(group.key); return n; });
  }

  function getSelectedFingerprintsOutsideGroup(group: AlertGroup): string[] {
    const groupFingerprints = new Set(group.alerts.map(alert => alert.fingerprint));
    return Array.from(selectedFingerprints).filter(fp => !groupFingerprints.has(fp));
  }

  async function handleRenameGroupSubmit() {
    if (!renameTargetGroup?.customGroupId || !onRenameCustomGroup) return;
    const result = await onRenameCustomGroup(renameTargetGroup.customGroupId, renameGroupName);
    if (!result.ok) {
      setGroupActionError(result.error || 'Failed to rename custom group.');
      return;
    }
    setGroupActionError(null);
    setRenameTargetGroup(null);
    setRenameGroupName('');
  }

  async function handleAddSelectedAlerts(group: AlertGroup): Promise<boolean> {
    if (!group.customGroupId || !onAddSelectedAlertsToCustomGroup) return false;
    const fingerprints = getSelectedFingerprintsOutsideGroup(group);
    if (fingerprints.length === 0) {
      setGroupActionError('Select one or more alerts outside this group first.');
      return false;
    }
    const result = await onAddSelectedAlertsToCustomGroup(group.customGroupId, fingerprints);
    if (!result.ok) {
      setGroupActionError(result.error || 'Failed to update custom group.');
      return false;
    }
    setGroupActionError(null);
    setGroupControlsTarget(null);
    onRefresh();
    return true;
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
      {/* Situation Summary Card */}
      <SituationCard
        sseUpdateTrigger={sseUpdateTrigger}
        firingCount={firingAlerts.length}
        onClusterClick={(fps) => setClusterFilter(fps.length > 0 ? fps : null)}
      />

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
        {(silencedAlerts.length > 0 || silenceRules.length > 0) && (
          <button
            onClick={() => setDashboardTab('silenced')}
            className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
              dashboardTab === 'silenced'
                ? 'bg-accent text-white'
                : 'text-muted hover:text-text-bright'
            }`}
          >
            Silenced ({silencedAlerts.length}{silenceRules.length > 0 ? ` Â· ${silenceRules.length} rule${silenceRules.length > 1 ? 's' : ''}` : ''})
          </button>
        )}
        {suppressedAlerts.length > 0 && (
          <button
            onClick={() => setDashboardTab('suppressed')}
            className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
              dashboardTab === 'suppressed'
                ? 'bg-accent text-white'
                : 'text-muted hover:text-text-bright'
            }`}
          >
            Suppressed ({suppressedAlerts.length})
          </button>
        )}
        <button
          onClick={() => setDashboardTab('statuspage')}
          className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
            dashboardTab === 'statuspage'
              ? 'bg-accent text-white'
              : 'text-muted hover:text-text-bright'
          }`}
        >
          <span className="inline-flex items-center gap-2">
            <span>Statuspage</span>
            {statuspageIncidentCount > 0 && (
              <span className="inline-flex min-w-[1.25rem] items-center justify-center rounded-full border border-accent/30 bg-accent/15 px-1.5 py-0.5 text-[10px] font-semibold leading-none text-accent">
                {statuspageIncidentCount}
              </span>
            )}
          </span>
        </button>
        <button
          onClick={() => setDashboardTab('rules')}
          className={`px-4 py-1.5 rounded-md text-xs font-medium transition-colors ${
            dashboardTab === 'rules'
              ? 'bg-accent text-white'
              : 'text-muted hover:text-text-bright'
          }`}
        >
          Alert Rules
        </button>
        {/* Create Incident (global) */}
        {!isRulesTab && !isStatuspageTab && (
          <button
            onClick={() => setShowIncidentWizard(!showIncidentWizard)}
            className={`ml-auto px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
              showIncidentWizard
                ? 'bg-orange/20 text-orange'
                : 'text-orange hover:bg-orange/10'
            }`}
          >
            Create Incident
          </button>
        )}
      </div>

      {/* Incident Wizard (global â€” not tied to a specific alert) */}
      {!isRulesTab && !isStatuspageTab && showIncidentWizard && (
        <IncidentWizard onClose={() => setShowIncidentWizard(false)} />
      )}

      {groupActionError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-red text-sm flex items-center justify-between gap-3">
          <span>{groupActionError}</span>
          <button onClick={() => setGroupActionError(null)} className="text-xs text-red/80 hover:text-red">Dismiss</button>
        </div>
      )}

      {renameTargetGroup && (
        <RenameCustomGroupModal
          groupName={renameGroupName}
          onChangeName={setRenameGroupName}
          onClose={() => {
            setRenameTargetGroup(null);
            setRenameGroupName('');
          }}
          onSubmit={handleRenameGroupSubmit}
        />
      )}

      {/* Active filter indicator */}
      {!isRulesTab && !isStatuspageTab && hasFilter && (
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
          {clusterFilter && (
            <button
              onClick={() => setClusterFilter(null)}
              className="text-xs px-2 py-1 bg-accent/20 text-accent rounded-full hover:bg-accent/30 transition-colors"
            >
              Showing cluster Â· Click to clear
            </button>
          )}
          <button
            onClick={() => { setSevFilter(null); setClusterFilter(null); }}
            className="text-xs text-muted hover:text-text transition-colors ml-2"
          >
            Clear
          </button>
        </div>
      )}

      {isRulesTab && <AlertRulesManager embedded />}
      <div className={isStatuspageTab ? '' : 'hidden'}>
        <StatuspageTab onIncidentCountChange={setStatuspageIncidentCount} />
      </div>

      {/* Recent Alerts Table */}
      {!isRulesTab && !isStatuspageTab && (
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
                <th className="table-header w-10">
                  <input
                    type="checkbox"
                    checked={allVisibleSelected}
                    onChange={(e) => onSetSelectedAlerts(visibleFingerprints, e.target.checked)}
                  />
                </th>
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
              {dashboardTab === 'silenced' ? (
                <>
                  {/* Active silence rules summary */}
                  {silenceRules.length > 0 && (
                    <tr>
                      <td colSpan={7} className="px-5 py-3 bg-yellow/5 border-b border-yellow/20">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-medium text-yellow">Active silence rules:</span>
                          {silenceRules.map(rule => (
                            <span key={rule.id} className="inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded bg-surface border border-border text-muted">
                              <span className="text-text-bright">{rule.alert_name_pattern}</span>
                              {rule.hostname_pattern && <span className="text-muted">on {rule.hostname_pattern}</span>}
                              <span className="text-muted/60">expires {timeAgo(rule.expires_at).replace(' ago', '').replace('just now', 'now')}</span>
                              {onCancelSilence && (
                                <button
                                  onClick={() => onCancelSilence(rule.id)}
                                  className="text-red/60 hover:text-red transition-colors ml-0.5"
                                  title="Cancel silence rule"
                                >
                                  &times;
                                </button>
                              )}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                  {silencedAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="table-cell text-center text-muted py-8">
                        No silenced alerts
                      </td>
                    </tr>
                  ) : (
                    silencedAlerts.map(alert => {
                      const host = alert.hostName || alert.hostname || '';
                      const source = getSourceLabel(alert);
                      const rule = isAlertSilenced(alert.name || '', host, silenceRules);
                      const enrichment = parseAIEnrichment(alert.note);
                      const summary = enrichment?.summary || '';
                      return (
                        <tr key={alert.fingerprint || alert.id} className="border-b border-border/50 hover:bg-surface-hover transition-colors">
                          <td className="table-cell">
                            <input
                              type="checkbox"
                              checked={selectedFingerprints.has(alert.fingerprint)}
                              onChange={() => onToggleSelectAlert(alert.fingerprint)}
                            />
                          </td>
                          <td className="table-cell">
                            <span className="badge bg-yellow/10 text-yellow border border-yellow/30">silenced</span>
                          </td>
                          <td className="table-cell">
                            <button
                              onClick={() => onAlertClick(alert)}
                              className="text-left text-text-bright hover:text-accent transition-colors"
                            >
                              {alert.name?.substring(0, 60) || 'Unknown'}
                            </button>
                            {rule && (
                              <div className="text-[10px] text-muted mt-0.5">
                                Rule: &quot;{rule.alert_name_pattern}&quot;{rule.hostname_pattern ? ` on ${rule.hostname_pattern}` : ''} by {rule.created_by}
                              </div>
                            )}
                          </td>
                          <td className="table-cell text-muted text-xs font-mono">{host}</td>
                          <td className="table-cell text-xs text-muted">{source}</td>
                          <td className="table-cell text-xs text-muted max-w-xs">
                            <div className="truncate">{summary || '--'}</div>
                          </td>
                          <td className="table-cell text-xs text-muted">{timeAgo(alertStartTime(alert))}</td>
                        </tr>
                      );
                    })
                  )}
                </>
              ) : dashboardTab === 'suppressed' ? (
                sortedAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="table-cell text-center text-muted py-8">
                      No suppressed alerts
                    </td>
                  </tr>
                ) : (
                  sortedAlerts.map(alert => {
                    const host = alert.hostName || alert.hostname || '';
                    const source = getSourceLabel(alert);
                    const note = alert.note || '';
                    const reason = note.startsWith('NOISE:')
                      ? note.split('\n')[0]
                      : note.startsWith('ENRICHMENT (copied')
                        ? note.split('):')[0] + ')'
                        : note.substring(0, 80);
                    return (
                      <tr key={alert.fingerprint || alert.id} className="border-b border-border/50 hover:bg-surface-hover transition-colors">
                        <td className="table-cell">
                          <input
                            type="checkbox"
                            checked={selectedFingerprints.has(alert.fingerprint)}
                            onChange={() => onToggleSelectAlert(alert.fingerprint)}
                          />
                        </td>
                        <td className="table-cell">
                          <span className="badge bg-surface text-muted border border-border">suppressed</span>
                        </td>
                        <td className="table-cell">
                          <button
                            onClick={() => onAlertClick(alert)}
                            className="text-left text-text-bright hover:text-accent transition-colors"
                          >
                            {alert.name?.substring(0, 60) || 'Unknown'}
                          </button>
                        </td>
                        <td className="table-cell text-muted text-xs font-mono">{host}</td>
                        <td className="table-cell text-xs text-muted">{source}</td>
                        <td className="table-cell text-xs text-yellow max-w-xs">
                          <div className="truncate">{reason}</div>
                        </td>
                        <td className="table-cell text-xs">
                          <div className="flex items-center gap-2">
                            <span className="text-muted">{timeAgo(alertStartTime(alert))}</span>
                            {onForceEnrich && (
                              <button
                                onClick={() => onForceEnrich(alert.fingerprint)}
                                className="text-[10px] px-2 py-0.5 rounded border border-accent/50 text-accent hover:bg-accent/10 transition-colors whitespace-nowrap"
                              >
                                Force Enrich
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )
              ) : groupView ? (
                alertGroups.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="table-cell text-center text-muted py-8">
                      {hasFilter ? 'No alerts match the selected filters' : 'No active alerts'}
                    </td>
                  </tr>
                ) : (
                  alertGroups.map(group => {
                    const groupHl = matchHighlightRules(group.alerts[0], highlightRules);
                    return group.alerts.length >= 2 ? (
                    <Fragment key={group.key}>
                      <tr
                        className="border-b border-border/50 hover:bg-surface-hover cursor-pointer transition-colors bg-bg/30"
                        style={groupHl ? { borderLeft: `3px solid ${groupHl.color}` } : undefined}
                        onClick={() => toggleGroup(group.key)}
                      >
                        <td className="px-4 py-2.5 align-top">
                          <input
                            type="checkbox"
                            checked={group.alerts.every(alert => selectedFingerprints.has(alert.fingerprint))}
                            onChange={(e) => {
                              e.stopPropagation();
                              onSetSelectedAlerts(group.alerts.map(alert => alert.fingerprint), e.target.checked);
                            }}
                            onClick={(e) => e.stopPropagation()}
                          />
                        </td>
                        <td colSpan={6} className="px-5 py-2.5">
                          <div className="flex items-center gap-3 flex-wrap min-w-0">
                            <span className="text-muted text-xs w-4 text-center">{expandedGroups.has(group.key) ? '\u25BE' : '\u25B8'}</span>
                            <span className={`badge ${severityBg(group.highestSeverity)}`}>
                              {group.highestSeverity}
                            </span>
                            <span className="text-text-bright font-medium text-sm min-w-0 flex-1 truncate" title={group.label}>{group.label}</span>
                            {group.groupType === 'custom' && (
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-accent/10 border border-accent/30 text-accent shrink-0">
                                Custom
                              </span>
                            )}
                            <span className="bg-accent/10 text-accent text-[10px] px-2 py-0.5 rounded-full font-medium shrink-0">
                              {group.alerts.length} alerts
                            </span>
                            {groupHl?.label && (
                              <span
                                className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium whitespace-nowrap shrink-0"
                                style={{ backgroundColor: `${groupHl.color}20`, color: groupHl.color, border: `1px solid ${groupHl.color}40` }}
                              >
                                {groupHl.label}
                              </span>
                            )}
                            <span className="text-muted text-xs ml-auto flex items-center gap-2 shrink-0">
                              {timeAgo(alertStartTime(group.alerts.reduce((latest, a) => {
                                const t = new Date(alertStartTime(a)).getTime() || 0;
                                const l = new Date(alertStartTime(latest)).getTime() || 0;
                                return t > l ? a : latest;
                              })))}
                              {dashboardTab === 'firing' && (
                                group.groupType === 'custom' ? (
                                  <CustomGroupControlsButton
                                    onOpen={() => {
                                      setGroupControlsTarget(group);
                                      setGroupSevDropdown(null);
                                      setSilenceDropdown(null);
                                      setGroupActionError(null);
                                    }}
                                  />
                                ) : (
                                <>
                                  <div className="relative">
                                    <button
                                      onClick={(e) => { e.stopPropagation(); setGroupSevDropdown(groupSevDropdown === group.key ? null : group.key); }}
                                      className="text-[10px] px-2 py-0.5 rounded border border-border text-muted hover:text-yellow hover:border-yellow/50 transition-colors"
                                    >
                                      Set Severity
                                    </button>
                                    {groupSevDropdown === group.key && (
                                      <div className="absolute z-50 top-full mt-1 right-0 bg-surface border border-border rounded-md shadow-lg py-1 min-w-[100px]"
                                        onClick={(e) => e.stopPropagation()}
                                      >
                                        {['critical', 'high', 'warning', 'info'].map(s => (
                                          <button
                                            key={s}
                                            onClick={async () => {
                                              const fps = group.alerts.map(a => a.fingerprint);
                                              await overrideSeverityBulk(fps, s);
                                              setGroupSevDropdown(null);
                                              onRefresh();
                                            }}
                                            className={`block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors ${severityColor(s)}`}
                                          >
                                            {s}
                                          </button>
                                        ))}
                                        <button
                                          onClick={async () => {
                                            const fps = group.alerts.map(a => a.fingerprint);
                                            await overrideSeverityBulk(fps, 'none');
                                            setGroupSevDropdown(null);
                                            onRefresh();
                                          }}
                                          className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-muted border-t border-border"
                                        >
                                          Reset to AI
                                        </button>
                                      </div>
                                    )}
                                  </div>
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleGroupAck(group); }}
                                    className="text-[10px] px-2 py-0.5 rounded border border-border text-muted hover:text-green hover:border-green/50 transition-colors"
                                  >
                                    Ack Group
                                  </button>
                                  <button
                                    onClick={(e) => { e.stopPropagation(); handleGroupResolve(group); }}
                                    disabled={resolvingGroups.has(group.key)}
                                    className="text-[10px] px-2 py-0.5 rounded border border-border text-muted hover:text-accent hover:border-accent/50 transition-colors disabled:opacity-40"
                                  >
                                    {resolvingGroups.has(group.key) ? 'Resolving...' : 'Resolve Group'}
                                  </button>
                                  {onSilenceGroup && (
                                    <div className="relative">
                                      <button
                                        onClick={(e) => { e.stopPropagation(); setSilenceDropdown(silenceDropdown === group.key ? null : group.key); }}
                                        className="text-[10px] px-2 py-0.5 rounded border border-border text-muted hover:text-yellow hover:border-yellow/50 transition-colors"
                                      >
                                        Silence
                                      </button>
                                      {silenceDropdown === group.key && (() => {
                                        const alertBase = group.label.split(' â€” ')[0] || group.label;
                                        const hostPart = group.label.split(' â€” ')[1] || undefined;
                                        const durations = [
                                          { label: '1 hour', seconds: 3600 },
                                          { label: '4 hours', seconds: 14400 },
                                          { label: '8 hours', seconds: 28800 },
                                          { label: '24 hours', seconds: 86400 },
                                          { label: '7 days', seconds: 604800 },
                                        ];
                                        return (
                                        <div className="absolute z-50 top-full mt-1 right-0 bg-surface border border-border rounded-md shadow-lg py-1 min-w-[180px]"
                                          onClick={(e) => e.stopPropagation()}
                                        >
                                          <div className="px-3 py-1 text-[10px] text-muted uppercase tracking-wide">Silence this alert</div>
                                          {durations.map(opt => (
                                            <button
                                              key={`alert-${opt.seconds}`}
                                              onClick={async () => {
                                                await onSilenceGroup(alertBase, opt.seconds, hostPart);
                                                setSilenceDropdown(null);
                                              }}
                                              className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-text"
                                            >
                                              {opt.label}
                                            </button>
                                          ))}
                                          {hostPart && (
                                            <>
                                              <div className="border-t border-border my-1" />
                                              <div className="px-3 py-1 text-[10px] text-muted uppercase tracking-wide">Silence all on {hostPart}</div>
                                              {durations.map(opt => (
                                                <button
                                                  key={`host-${opt.seconds}`}
                                                  onClick={async () => {
                                                    // Use wildcard * to match all alert names on this host pattern
                                                    await onSilenceGroup('*', opt.seconds, hostPart);
                                                    setSilenceDropdown(null);
                                                  }}
                                                  className="block w-full text-left text-xs px-3 py-1.5 hover:bg-surface-hover transition-colors text-yellow"
                                                >
                                                  {opt.label}
                                                </button>
                                              ))}
                                            </>
                                          )}
                                        </div>
                                        );
                                      })()}
                                    </div>
                                  )}
                                </>
                                )
                              )}
                            </span>
                          </div>
                        </td>
                      </tr>
                      {expandedGroups.has(group.key) && group.alerts.map(alert => {
                        const rowId = alert.fingerprint || alert.id;
                        const hl = matchHighlightRules(alert, highlightRules);
                        return (
                          <AlertRow
                            key={rowId}
                            alert={alert}
                            expanded={expandedRows.has(rowId)}
                            onToggleExpand={() => toggleRow(rowId)}
                            onOpenDetail={() => onAlertClick(alert)}
                            indented
                            alertState={alertStates.get(alert.fingerprint)}
                            customGroupName={customGroupByFingerprint.get(alert.fingerprint)}
                            isSelected={selectedFingerprints.has(alert.fingerprint)}
                            onToggleSelect={() => onToggleSelectAlert(alert.fingerprint)}
                            onInvestigate={() => onInvestigate(alert)}
                            onAcknowledge={dashboardTab === 'firing' ? () => onAcknowledge(alert) : undefined}
                            onUnacknowledge={dashboardTab === 'acknowledged' ? () => onUnacknowledge(alert) : undefined}
                            showAckInfo={dashboardTab === 'acknowledged'}
                            highlightColor={hl?.color}
                            highlightLabel={hl?.label}
                            highlightStyle={hl?.style}
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
                      customGroupName={customGroupByFingerprint.get(group.alerts[0].fingerprint)}
                      isSelected={selectedFingerprints.has(group.alerts[0].fingerprint)}
                      onToggleSelect={() => onToggleSelectAlert(group.alerts[0].fingerprint)}
                      onInvestigate={() => onInvestigate(group.alerts[0])}
                      onAcknowledge={dashboardTab === 'firing' ? () => onAcknowledge(group.alerts[0]) : undefined}
                      onUnacknowledge={dashboardTab === 'acknowledged' ? () => onUnacknowledge(group.alerts[0]) : undefined}
                      showAckInfo={dashboardTab === 'acknowledged'}
                      highlightColor={groupHl?.color}
                      highlightLabel={groupHl?.label}
                      highlightStyle={groupHl?.style}
                    />
                  )
                  })
                )
              ) : (
                pagedAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="table-cell text-center text-muted py-8">
                      {hasFilter ? 'No alerts match the selected filters' : 'No active alerts'}
                    </td>
                  </tr>
                ) : (
                  pagedAlerts.map((alert) => {
                    const rowId = alert.fingerprint || alert.id;
                    const hl = matchHighlightRules(alert, highlightRules);
                    return (
                      <AlertRow
                        key={rowId}
                        alert={alert}
                        expanded={expandedRows.has(rowId)}
                        onToggleExpand={() => toggleRow(rowId)}
                        onOpenDetail={() => onAlertClick(alert)}
                        alertState={alertStates.get(alert.fingerprint)}
                        customGroupName={customGroupByFingerprint.get(alert.fingerprint)}
                        isSelected={selectedFingerprints.has(alert.fingerprint)}
                        onToggleSelect={() => onToggleSelectAlert(alert.fingerprint)}
                        onInvestigate={() => onInvestigate(alert)}
                        onAcknowledge={dashboardTab === 'firing' ? () => onAcknowledge(alert) : undefined}
                        onUnacknowledge={dashboardTab === 'acknowledged' ? () => onUnacknowledge(alert) : undefined}
                        showAckInfo={dashboardTab === 'acknowledged'}
                        highlightColor={hl?.color}
                        highlightLabel={hl?.label}
                        highlightStyle={hl?.style}
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
                  {displayAlerts.length > 0
                    ? `Showing ${safePage * pageSize + 1}\u2013${Math.min((safePage + 1) * pageSize, displayAlerts.length)} of ${displayAlerts.length}`
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
      )}
      {groupControlsTarget && (
        <CustomGroupControlsModal
          group={groupControlsTarget}
          selectedFingerprints={selectedFingerprints}
          resolving={resolvingGroups.has(groupControlsTarget.key)}
          onClose={() => setGroupControlsTarget(null)}
          onRename={() => {
            setRenameTargetGroup(groupControlsTarget);
            setRenameGroupName(groupControlsTarget.label);
            setGroupActionError(null);
          }}
          onAddSelectedAlerts={() => handleAddSelectedAlerts(groupControlsTarget)}
          onAcknowledge={() => handleGroupAck(groupControlsTarget)}
          onResolve={() => handleGroupResolve(groupControlsTarget)}
          onSetSeverity={async (severity) => {
            const fps = groupControlsTarget.alerts.map(a => a.fingerprint);
            await overrideSeverityBulk(fps, severity);
            onRefresh();
          }}
          onSilenceGroup={onSilenceGroup}
        />
      )}
    </div>
  );
}
