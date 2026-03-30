'use client';

import { useEffect, useState, useCallback } from 'react';

interface ServiceStatus {
  name: string;
  role: string;
  container: string;
  state: string;
  status: string;
  healthy: boolean;
  created_ts?: number;
  http_check?: {
    reachable: boolean;
    status_code: number | null;
    response_ms: number | null;
  };
}

interface DataFreshness {
  status: string;
  latest_alert?: string;
  alert_count?: number;
  latest_name?: string;
  error?: string;
}

interface HealthReport {
  timestamp: string;
  overall: 'healthy' | 'degraded' | 'unknown';
  docker_available: boolean;
  services: ServiceStatus[];
  data_freshness: DataFreshness;
  missing_containers: string[];
}

function overallColor(status: string): string {
  switch (status) {
    case 'healthy': return 'text-green';
    case 'degraded': return 'text-orange';
    default: return 'text-muted';
  }
}

function overallBg(status: string): string {
  switch (status) {
    case 'healthy': return 'bg-green/10 border-green/30';
    case 'degraded': return 'bg-orange/10 border-orange/30';
    default: return 'bg-muted/10 border-muted/30';
  }
}

function stateColor(state: string): string {
  if (state === 'running') return 'text-green';
  if (state === 'exited' || state === 'dead') return 'text-red';
  if (state === 'restarting') return 'text-orange';
  if (state === 'not_found') return 'text-red';
  return 'text-muted';
}

function stateBg(state: string): string {
  if (state === 'running') return 'bg-green/10 border-green/30';
  if (state === 'exited' || state === 'dead' || state === 'not_found') return 'bg-red/10 border-red/30';
  if (state === 'restarting') return 'bg-orange/10 border-orange/30';
  return 'bg-muted/10 border-muted/30';
}

function uptimeFromStatus(status: string): string {
  // Docker status looks like "Up 34 hours (healthy)" or "Up 2 days"
  if (!status) return '--';
  const match = status.match(/Up\s+(.+?)(?:\s+\(|$)/);
  return match ? match[1] : status;
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return ts;
  }
}

function freshnessAgo(dateStr: string | undefined): string {
  if (!dateStr) return 'unknown';
  try {
    const d = new Date(dateStr);
    const diff = Date.now() - d.getTime();
    if (diff < 0) return 'just now';
    const secs = Math.floor(diff / 1000);
    if (secs < 60) return `${secs}s ago`;
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    return `${hrs}h ago`;
  } catch {
    return dateStr;
  }
}

export default function HealthPage() {
  const [report, setReport] = useState<HealthReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshInterval, setRefreshInterval] = useState(15);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/health/');
      if (!res.ok) throw new Error(`Health API returned ${res.status}`);
      const data: HealthReport = await res.json();
      setReport(data);
      setLastRefresh(new Date());
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to fetch health data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, refreshInterval * 1000);
    return () => clearInterval(interval);
  }, [load, refreshInterval]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted animate-pulse">Checking service health...</div>
      </div>
    );
  }

  const healthyCount = report?.services.filter(s => s.healthy).length ?? 0;
  const totalCount = report?.services.length ?? 0;
  const runningCount = report?.services.filter(s => s.state === 'running').length ?? 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-text-bright">Service Health</h1>
        <div className="flex items-center gap-3">
          <RefreshControl
            refreshInterval={refreshInterval}
            onRefreshIntervalChange={setRefreshInterval}
            onRefresh={() => { setRefreshing(true); load().finally(() => setTimeout(() => setRefreshing(false), 500)); }}
            refreshing={refreshing}
          />
          <span className="text-xs text-muted">
            {lastRefresh && `Checked ${lastRefresh.toLocaleTimeString()}`}
          </span>
        </div>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-red text-sm">
          {error}
        </div>
      )}

      {report && (
        <>
          {/* Overall Status Banner */}
          <div className={`border rounded-lg px-5 py-4 ${overallBg(report.overall)}`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${
                  report.overall === 'healthy' ? 'bg-green animate-pulse' :
                  report.overall === 'degraded' ? 'bg-orange animate-pulse' :
                  'bg-muted'
                }`} />
                <span className={`text-lg font-bold uppercase ${overallColor(report.overall)}`}>
                  {report.overall === 'healthy' ? 'All Systems Operational' :
                   report.overall === 'degraded' ? 'Degraded Performance' :
                   'Status Unknown'}
                </span>
              </div>
              <div className="text-xs text-muted">
                {formatTimestamp(report.timestamp)}
              </div>
            </div>
          </div>

          {/* Summary Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="stat-card">
              <div className="text-xs text-muted uppercase tracking-wider mb-1">Services</div>
              <div className="text-3xl font-bold text-text-bright">{totalCount}</div>
            </div>
            <div className="stat-card">
              <div className="text-xs text-muted uppercase tracking-wider mb-1">Running</div>
              <div className="text-3xl font-bold text-green">{runningCount}</div>
            </div>
            <div className="stat-card">
              <div className="text-xs text-muted uppercase tracking-wider mb-1">Healthy</div>
              <div className={`text-3xl font-bold ${healthyCount === totalCount ? 'text-green' : 'text-orange'}`}>
                {healthyCount}/{totalCount}
              </div>
            </div>
            <div className="stat-card">
              <div className="text-xs text-muted uppercase tracking-wider mb-1">Data Freshness</div>
              <div className={`text-xl font-bold ${
                report.data_freshness.status === 'ok' ? 'text-green' :
                report.data_freshness.status === 'error' ? 'text-red' : 'text-muted'
              }`}>
                {report.data_freshness.status === 'ok'
                  ? freshnessAgo(report.data_freshness.latest_alert)
                  : report.data_freshness.status === 'no_data' ? 'No data' : 'Error'}
              </div>
            </div>
          </div>

          {/* Service Grid */}
          <div className="stat-card overflow-hidden">
            <h3 className="text-sm font-medium text-muted mb-4">Container Status</h3>
            <div className="overflow-x-auto -mx-5">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="table-header">Service</th>
                    <th className="table-header">Role</th>
                    <th className="table-header">State</th>
                    <th className="table-header">Uptime</th>
                    <th className="table-header">HTTP Check</th>
                    <th className="table-header">Health</th>
                  </tr>
                </thead>
                <tbody>
                  {report.services.map(svc => (
                    <tr key={svc.container} className="border-b border-border/50 hover:bg-surface-hover transition-colors">
                      <td className="table-cell">
                        <div className="text-text-bright text-sm font-medium">{svc.name}</div>
                        <div className="text-[10px] text-muted font-mono">{svc.container}</div>
                      </td>
                      <td className="table-cell text-xs text-muted">{svc.role}</td>
                      <td className="table-cell">
                        <span className={`badge ${stateBg(svc.state)}`}>
                          {svc.state}
                        </span>
                      </td>
                      <td className="table-cell text-xs text-muted font-mono">
                        {uptimeFromStatus(svc.status)}
                      </td>
                      <td className="table-cell">
                        {svc.http_check ? (
                          svc.http_check.reachable ? (
                            <span className="text-xs text-green">
                              {svc.http_check.status_code}
                            </span>
                          ) : (
                            <span className="text-xs text-red">unreachable</span>
                          )
                        ) : (
                          <span className="text-xs text-muted">--</span>
                        )}
                      </td>
                      <td className="table-cell">
                        <div className="flex items-center gap-2">
                          <div className={`w-2.5 h-2.5 rounded-full ${
                            svc.healthy ? 'bg-green' : 'bg-red'
                          }`} />
                          <span className={`text-xs ${svc.healthy ? 'text-green' : 'text-red'}`}>
                            {svc.healthy ? 'OK' : 'DOWN'}
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Data Pipeline Status */}
          <div className="stat-card">
            <h3 className="text-sm font-medium text-muted mb-4">Data Pipeline</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <PipelineCard
                label="Zabbix Webhook"
                description="Receives real-time alerts from Zabbix via webhook and pushes to Keep API"
                status="ok"
              />
              <PipelineCard
                label="AI Enricher"
                description="Analyzes new alerts with Ollama LLM every 60 seconds, adds severity/cause/remediation"
                status={report.services.find(s => s.container === 'uip-alert-enricher')?.state === 'running' ? 'ok' : 'down'}
                href="/portal/ai-manage"
                clickHint="Manage"
              />
              <PipelineCard
                label="Alert Data"
                description={
                  report.data_freshness.status === 'ok'
                    ? `Latest: ${report.data_freshness.latest_name || 'unknown'}`
                    : report.data_freshness.error || 'No alert data available'
                }
                status={report.data_freshness.status === 'ok' ? 'ok' : report.data_freshness.status === 'no_data' ? 'warning' : 'down'}
              />
            </div>
          </div>

          {/* Missing Containers Warning */}
          {report.missing_containers.length > 0 && (
            <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3">
              <div className="text-sm font-medium text-red mb-1">Missing Containers</div>
              <div className="text-xs text-muted">
                The following expected containers were not found: {report.missing_containers.join(', ')}
              </div>
            </div>
          )}

          {!report.docker_available && (
            <div className="bg-orange/10 border border-orange/30 rounded-lg px-4 py-3">
              <div className="text-sm font-medium text-orange mb-1">Docker Socket Not Available</div>
              <div className="text-xs text-muted">
                Cannot read container status. Ensure the health-checker container has access to /var/run/docker.sock
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function PipelineCard({ label, description, status, href, clickHint }: {
  label: string;
  description: string;
  status: 'ok' | 'warning' | 'down';
  href?: string;
  clickHint?: string;
}) {
  const colors = {
    ok: 'border-green/30 bg-green/5',
    warning: 'border-yellow/30 bg-yellow/5',
    down: 'border-red/30 bg-red/5',
  };
  const dotColors = {
    ok: 'bg-green',
    warning: 'bg-yellow',
    down: 'bg-red',
  };

  const content = (
    <>
      <div className="flex items-center gap-2 mb-1">
        <div className={`w-2 h-2 rounded-full ${dotColors[status]}`} />
        <span className="text-sm font-medium text-text-bright">{label}</span>
        {clickHint && <span className="text-[10px] text-accent ml-auto">{clickHint} &rarr;</span>}
      </div>
      <div className="text-xs text-muted">{description}</div>
    </>
  );

  if (href) {
    return (
      <a href={href} className={`block border rounded-lg px-4 py-3 ${colors[status]} hover:ring-1 hover:ring-accent/30 transition-all`}>
        {content}
      </a>
    );
  }

  return (
    <div className={`border rounded-lg px-4 py-3 ${colors[status]}`}>
      {content}
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
        <option value={15}>15s</option>
        <option value={30}>30s</option>
        <option value={60}>1m</option>
        <option value={120}>2m</option>
        <option value={300}>5m</option>
        <option value={600}>10m</option>
      </select>
    </div>
  );
}
