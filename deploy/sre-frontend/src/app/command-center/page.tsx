'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { Alert, AlertStats, AIEnrichment } from '@/lib/types';
import {
  fetchAlerts,
  parseAIEnrichment,
  computeStats,
  severityColor,
  severityBg,
  timeAgo,
} from '@/lib/keep-api';

const SOURCE_LABELS: Record<string, string> = {
  zabbix: 'Zabbix',
  prometheus: 'Prometheus',
  grafana: 'Grafana',
  datadog: 'Datadog',
  cloudwatch: 'CloudWatch',
};

function formatSource(raw: string): string {
  return SOURCE_LABELS[raw.toLowerCase()] || raw.charAt(0).toUpperCase() + raw.slice(1);
}

function getSourceLabel(alert: Alert): string {
  const src = Array.isArray(alert.source) ? alert.source : [alert.source || 'unknown'];
  return src.map(s => formatSource(String(s))).join(', ');
}

export default function CommandCenter() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<AlertStats>({ total: 0, critical: 0, high: 0, warning: 0, low: 0, noise: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await fetchAlerts(100);
      setAlerts(data);
      setStats(computeStats(data));
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
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const activeAlerts = alerts.filter(a => a.status !== 'resolved' && a.status !== 'ok');

  const filteredAlerts = useMemo(() => {
    return activeAlerts.filter(a => {
      if (sevFilter) {
        const enrichment = parseAIEnrichment(a.note);
        const sev = enrichment?.assessed_severity ?? 'unknown';
        if (sevFilter === 'low') {
          if (sev !== 'low' && sev !== 'info') return false;
        } else {
          if (sev !== sevFilter) return false;
        }
      }
      if (sourceFilter) {
        const label = getSourceLabel(a);
        if (label !== sourceFilter) return false;
      }
      return true;
    });
  }, [activeAlerts, sevFilter, sourceFilter]);

  const displayAlerts = filteredAlerts.slice(0, 30);
  const hasFilter = sevFilter !== null || sourceFilter !== null;

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
        <div className="text-xs text-muted">
          {lastUpdated && `Updated ${lastUpdated.toLocaleTimeString()}`}
          {' '}&middot;{' '}Auto-refresh 30s
        </div>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-red text-sm">
          {error}
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard label="Active Alerts" value={stats.total} color="text-text-bright" />
        <StatCard label="Critical" value={stats.critical} color="text-red" />
        <StatCard label="High" value={stats.high} color="text-orange" />
        <StatCard label="Warning" value={stats.warning} color="text-yellow" />
        <StatCard label="Likely Noise" value={stats.noise} color="text-muted" subtext={`of ${stats.total}`} />
      </div>

      {/* Severity Breakdown + Source Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="stat-card md:col-span-1">
          <h3 className="text-sm font-medium text-muted mb-4">Severity Breakdown</h3>
          <SeverityBreakdown stats={stats} activeFilter={sevFilter} onFilter={setSevFilter} />
        </div>

        <div className="stat-card md:col-span-2">
          <h3 className="text-sm font-medium text-muted mb-4">Active Alerts by Source</h3>
          <SourceBreakdown alerts={activeAlerts} activeFilter={sourceFilter} onFilter={setSourceFilter} />
        </div>
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
          {sourceFilter && (
            <button
              onClick={() => setSourceFilter(null)}
              className="badge bg-accent/10 border-accent/30 text-accent cursor-pointer"
            >
              {sourceFilter} &times;
            </button>
          )}
          <button
            onClick={() => { setSevFilter(null); setSourceFilter(null); }}
            className="text-xs text-muted hover:text-text transition-colors ml-2"
          >
            Clear all
          </button>
        </div>
      )}

      {/* Recent Alerts Table */}
      <div className="stat-card overflow-hidden">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-medium text-muted">
            {hasFilter ? `Filtered Alerts (${filteredAlerts.length})` : 'Recent Active Alerts'}
          </h3>
          <a href="/portal/alerts" className="text-xs text-accent hover:text-accent-hover transition-colors">
            View all &rarr;
          </a>
        </div>
        <div className="overflow-x-auto -mx-5">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="table-header">Severity</th>
                <th className="table-header">Alert</th>
                <th className="table-header">Host</th>
                <th className="table-header">Source</th>
                <th className="table-header">Noise</th>
                <th className="table-header">AI Summary</th>
                <th className="table-header">Time</th>
              </tr>
            </thead>
            <tbody>
              {displayAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="table-cell text-center text-muted py-8">
                    {hasFilter ? 'No alerts match the selected filters' : 'No active alerts'}
                  </td>
                </tr>
              ) : (
                displayAlerts.map((alert) => (
                  <AlertRow key={alert.fingerprint || alert.id} alert={alert} />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color, subtext }: {
  label: string; value: number; color: string; subtext?: string;
}) {
  return (
    <div className="stat-card">
      <div className="text-xs text-muted uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-3xl font-bold ${color}`}>
        {value}
        {subtext && <span className="text-sm text-muted font-normal ml-1">{subtext}</span>}
      </div>
    </div>
  );
}

function SeverityBreakdown({ stats, activeFilter, onFilter }: {
  stats: AlertStats;
  activeFilter: string | null;
  onFilter: (sev: string | null) => void;
}) {
  const total = stats.total || 1;
  const bars = [
    { label: 'Critical', key: 'critical', count: stats.critical, color: 'bg-red', activeColor: 'ring-2 ring-red' },
    { label: 'High', key: 'high', count: stats.high, color: 'bg-orange', activeColor: 'ring-2 ring-orange' },
    { label: 'Warning', key: 'warning', count: stats.warning, color: 'bg-yellow', activeColor: 'ring-2 ring-yellow' },
    { label: 'Low/Info', key: 'low', count: stats.low, color: 'bg-blue', activeColor: 'ring-2 ring-blue' },
  ];

  return (
    <div className="space-y-3">
      {bars.map(b => {
        const isActive = activeFilter === b.key;
        return (
          <button
            key={b.label}
            onClick={() => onFilter(isActive ? null : b.key)}
            className={`w-full text-left rounded-md p-1.5 -m-1.5 transition-all ${
              isActive ? 'bg-surface-hover ' + b.activeColor : 'hover:bg-surface-hover/50'
            }`}
          >
            <div className="flex justify-between text-xs mb-1">
              <span className={isActive ? 'text-text-bright font-medium' : 'text-muted'}>{b.label}</span>
              <span className="text-text">{b.count}</span>
            </div>
            <div className="w-full bg-border rounded-full h-2">
              <div
                className={`noise-bar ${b.color}`}
                style={{ width: `${Math.max(b.count / total * 100, b.count > 0 ? 4 : 0)}%` }}
              />
            </div>
          </button>
        );
      })}
    </div>
  );
}

function SourceBreakdown({ alerts, activeFilter, onFilter }: {
  alerts: Alert[];
  activeFilter: string | null;
  onFilter: (source: string | null) => void;
}) {
  const sources: Record<string, number> = {};
  for (const a of alerts) {
    const label = getSourceLabel(a);
    sources[label] = (sources[label] || 0) + 1;
  }
  const sorted = Object.entries(sources).sort((a, b) => b[1] - a[1]);

  if (sorted.length === 0) {
    return <div className="text-muted text-sm">No active alerts</div>;
  }

  const maxCount = sorted[0][1] || 1;

  return (
    <div className="space-y-2">
      {sorted.map(([src, count]) => {
        const isActive = activeFilter === src;
        return (
          <button
            key={src}
            onClick={() => onFilter(isActive ? null : src)}
            className={`w-full flex items-center gap-3 rounded-md p-2 -mx-2 transition-all ${
              isActive
                ? 'bg-accent/10 ring-1 ring-accent/40'
                : 'hover:bg-surface-hover/50'
            }`}
          >
            <span className={`text-sm truncate mr-auto ${isActive ? 'text-accent font-medium' : 'text-text'}`}>
              {src}
            </span>
            <div className="w-24 bg-border rounded-full h-1.5 flex-shrink-0">
              <div
                className="h-1.5 rounded-full bg-accent/60"
                style={{ width: `${(count / maxCount) * 100}%` }}
              />
            </div>
            <span className="text-sm text-muted font-mono w-6 text-right flex-shrink-0">{count}</span>
          </button>
        );
      })}
    </div>
  );
}

function AlertRow({ alert }: { alert: Alert }) {
  const enrichment = parseAIEnrichment(alert.note);
  const sev = enrichment?.assessed_severity ?? 'unknown';
  const host = alert.hostName || alert.hostname || '';
  const source = getSourceLabel(alert);

  return (
    <tr className="border-b border-border/50 hover:bg-surface-hover transition-colors">
      <td className="table-cell">
        <span className={`badge ${severityBg(sev)}`}>
          {sev}
        </span>
      </td>
      <td className="table-cell">
        <a
          href={`/portal/alerts/${alert.fingerprint}`}
          className="text-text-bright hover:text-accent transition-colors"
        >
          {alert.name?.substring(0, 60) || 'Unknown'}
          {(alert.name?.length ?? 0) > 60 ? '...' : ''}
        </a>
        {alert.description && alert.description !== alert.name && (
          <div className="text-xs text-muted mt-0.5 truncate max-w-xs font-mono">
            {alert.description.substring(0, 80)}
            {(alert.description?.length ?? 0) > 80 ? '...' : ''}
          </div>
        )}
      </td>
      <td className="table-cell text-muted text-xs font-mono">{host}</td>
      <td className="table-cell text-xs text-muted">{source}</td>
      <td className="table-cell">
        {enrichment ? (
          <NoiseIndicator score={enrichment.noise_score} />
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
}

function NoiseIndicator({ score }: { score: number }) {
  const color = score >= 7 ? 'bg-muted' : score >= 4 ? 'bg-yellow' : 'bg-green';
  return (
    <div className="flex items-center gap-2">
      <div className="w-12 bg-border rounded-full h-1.5">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${score * 10}%` }} />
      </div>
      <span className="text-xs text-muted font-mono">{score}</span>
    </div>
  );
}
