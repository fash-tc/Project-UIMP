'use client';

import { useEffect, useState, useMemo, useCallback } from 'react';
import { Alert } from '@/lib/types';
import { fetchAlerts, parseAIEnrichment, timeAgo, alertStartTime, fetchRegistryHealth, RegistryHealthData, RegistryHealthOperator, fetchRegistryTrends } from '@/lib/keep-api';
import {
  REGISTRY_OPERATORS,
  TLD_OPERATOR_MAP,
  RegistryOperator,
  RegistryContact,
  buildRegistryMailto,
  detectRegistryFromAlert,
  RegistryMatch,
} from '@/lib/registry';

interface RegistryAlert {
  alert: Alert;
  match: RegistryMatch;
}

export default function RegistryContactsPage() {
  const [search, setSearch] = useState('');
  const [selectedOperator, setSelectedOperator] = useState<RegistryOperator | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [tldFilter, setTldFilter] = useState('');
  const [healthData, setHealthData] = useState<RegistryHealthData | null>(null);

  useEffect(() => {
    fetchAlerts(250).then(a => {
      setAlerts(a);
      setLoadingAlerts(false);
    }).catch(() => setLoadingAlerts(false));
  }, []);

  const [loadingHealth, setLoadingHealth] = useState(false);

  const loadHealthData = useCallback(() => {
    setLoadingHealth(true);
    fetchRegistryHealth().then(data => {
      setHealthData(data);
      setLoadingHealth(false);
    }).catch(() => setLoadingHealth(false));
  }, []);

  // Match alerts to registries
  const registryAlerts = useMemo(() => {
    const matches: RegistryAlert[] = [];
    for (const alert of alerts) {
      if (alert.status === 'resolved' || alert.status === 'ok') continue;
      const host = alert.hostName || alert.hostname || '';
      const match = detectRegistryFromAlert(alert.name, host, alert.description);
      if (match) {
        matches.push({ alert, match });
      }
    }
    return matches;
  }, [alerts]);

  // Filter operators
  const filteredOperators = useMemo(() => {
    let ops = REGISTRY_OPERATORS;

    if (tldFilter) {
      const tld = tldFilter.startsWith('.') ? tldFilter.toLowerCase() : '.' + tldFilter.toLowerCase();
      const operatorId = TLD_OPERATOR_MAP[tld];
      if (operatorId) {
        ops = ops.filter(o => o.id === operatorId);
      } else {
        ops = ops.filter(o => o.tlds.some(t => t.toLowerCase().includes(tld)));
      }
    }

    if (search) {
      const q = search.toLowerCase();
      ops = ops.filter(o =>
        o.name.toLowerCase().includes(q) ||
        o.tlds.some(t => t.toLowerCase().includes(q)) ||
        o.contacts.some(c =>
          c.role.toLowerCase().includes(q) ||
          c.email?.toLowerCase().includes(q)
        )
      );
    }

    return ops;
  }, [search, tldFilter]);

  // Count alerts per operator
  const alertsByOperator = useMemo(() => {
    const map: Record<string, RegistryAlert[]> = {};
    for (const ra of registryAlerts) {
      const id = ra.match.operator.id;
      if (!map[id]) map[id] = [];
      map[id].push(ra);
    }
    return map;
  }, [registryAlerts]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-bright">Registry</h1>
          <p className="text-sm text-muted mt-1">
            Quick contact for registry operators — click email to launch your mail client
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs text-muted">
          <span>{REGISTRY_OPERATORS.length} registries</span>
          {registryAlerts.length > 0 && (
            <span className="badge bg-orange/10 border-orange/30 text-orange">
              {registryAlerts.length} registry-related alert{registryAlerts.length !== 1 ? 's' : ''}
            </span>
          )}
          <button
            onClick={loadHealthData}
            disabled={loadingHealth}
            className="px-3 py-1.5 text-xs font-medium rounded-md border border-border text-muted hover:text-text-bright hover:bg-surface-hover disabled:opacity-40 transition-colors"
          >
            {loadingHealth ? 'Loading...' : 'Load Health Data'}
          </button>
        </div>
      </div>

      {/* Registry-Related Alerts Banner */}
      {registryAlerts.length > 0 && (
        <div className="bg-orange/5 border border-orange/30 rounded-lg px-5 py-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-2.5 h-2.5 rounded-full bg-orange animate-pulse" />
            <h3 className="text-sm font-medium text-orange">Active Registry-Related Alerts</h3>
          </div>
          <div className="space-y-2">
            {registryAlerts.slice(0, 5).map(ra => (
              <RegistryAlertRow
                key={ra.alert.fingerprint}
                registryAlert={ra}
                onSelectOperator={setSelectedOperator}
              />
            ))}
            {registryAlerts.length > 5 && (
              <div className="text-xs text-muted pt-1">
                + {registryAlerts.length - 5} more registry-related alerts
              </div>
            )}
          </div>
        </div>
      )}

      {/* Registry Health Banner */}
      {healthData && healthData.last_updated ? (
        <RegistryHealthBanner healthData={healthData} />
      ) : !healthData && (
        <div className="bg-surface border border-border rounded-lg px-5 py-3 text-xs text-muted">
          Click &ldquo;Load Health Data&rdquo; to load registry health metrics
        </div>
      )}

      {/* Search & Filter */}
      <div className="flex gap-3">
        <div className="flex-1 relative">
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search registries, TLDs, contacts..."
            className="w-full bg-surface border border-border rounded-md px-3 py-2 pl-9 text-sm text-text placeholder:text-muted/50 focus:outline-none focus:ring-1 focus:ring-accent"
          />
          <svg className="absolute left-3 top-2.5 w-4 h-4 text-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
        <input
          type="text"
          value={tldFilter}
          onChange={e => setTldFilter(e.target.value)}
          placeholder="Filter by TLD (e.g. .com)"
          className="w-48 bg-surface border border-border rounded-md px-3 py-2 text-sm text-text placeholder:text-muted/50 focus:outline-none focus:ring-1 focus:ring-accent font-mono"
        />
      </div>

      {/* Operator Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredOperators.map(op => (
          <OperatorCard
            key={op.id}
            operator={op}
            alertCount={alertsByOperator[op.id]?.length || 0}
            alerts={alertsByOperator[op.id] || []}
            health={healthData?.operators[op.id] || null}
            isSelected={selectedOperator?.id === op.id}
            onSelect={() => setSelectedOperator(selectedOperator?.id === op.id ? null : op)}
          />
        ))}
      </div>

      {filteredOperators.length === 0 && (
        <div className="text-center py-12 text-muted text-sm">
          No registries match your search.
        </div>
      )}

      {/* Detail Panel (Modal) */}
      {selectedOperator && (
        <OperatorDetailModal
          operator={selectedOperator}
          alerts={alertsByOperator[selectedOperator.id] || []}
          health={healthData?.operators[selectedOperator.id] || null}
          onClose={() => setSelectedOperator(null)}
        />
      )}
    </div>
  );
}

/* ── Operator Card ── */

function OperatorCard({ operator, alertCount, alerts, health, isSelected, onSelect }: {
  operator: RegistryOperator;
  alertCount: number;
  alerts: RegistryAlert[];
  health: RegistryHealthOperator | null;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const primaryContact = operator.contacts[0];
  const primaryEmail = primaryContact?.email;

  return (
    <div
      className={`stat-card cursor-pointer ${
        alertCount > 0 ? 'border-orange/40 bg-orange/5' :
        health?.status === 'down' ? 'border-red/40 bg-red/5' :
        health?.status === 'degraded' ? 'border-orange/40 bg-orange/5' : ''
      } ${isSelected ? 'ring-2 ring-accent' : ''}`}
      onClick={onSelect}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-text-bright truncate">{operator.name}</h3>
            {alertCount > 0 && (
              <span className="badge bg-orange/10 border-orange/30 text-orange text-[10px] flex-shrink-0">
                {alertCount} alert{alertCount !== 1 ? 's' : ''}
              </span>
            )}
          </div>
          <div className="flex flex-wrap gap-1.5 mt-1.5">
            {operator.tlds.slice(0, 8).map(tld => (
              <span key={tld} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent/10 text-accent border border-accent/20">
                {tld}
              </span>
            ))}
            {operator.tlds.length > 8 && (
              <span className="text-[10px] text-muted">+{operator.tlds.length - 8} more</span>
            )}
          </div>
        </div>
        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          {primaryEmail && (
            <a
              href={buildRegistryMailto(operator, primaryContact) || '#'}
              onClick={e => e.stopPropagation()}
              className="px-2.5 py-1 rounded-md bg-accent text-bg text-[10px] font-medium hover:bg-accent-hover transition-colors"
              title={`Email ${primaryEmail}`}
            >
              Contact
            </a>
          )}
          {operator.hours && (
            <span className="text-[10px] text-muted">{operator.hours}</span>
          )}
        </div>
      </div>

      {/* Health Metrics */}
      {health && health.status !== 'no_data' && (
        <div className="mt-2 flex items-center gap-3 text-[10px]">
          <span className={`inline-flex items-center gap-1 font-medium ${
            health.status === 'healthy' ? 'text-green' :
            health.status === 'degraded' ? 'text-orange' : 'text-red'
          }`}>
            <span className={`w-1.5 h-1.5 rounded-full ${
              health.status === 'healthy' ? 'bg-green' :
              health.status === 'degraded' ? 'bg-orange animate-pulse' : 'bg-red animate-pulse'
            }`} />
            {health.status}
          </span>
          <span className="text-muted">{health.avg_response_ms.toFixed(0)}ms avg</span>
          <span className="text-muted">{health.request_count.toLocaleString()} req/hr</span>
          {health.error_rate > 0 && (
            <span className={health.error_rate > 0.1 ? 'text-red' : 'text-orange'}>
              {(health.error_rate * 100).toFixed(1)}% err
            </span>
          )}
        </div>
      )}

      {/* Quick contact info */}
      {primaryContact && (
        <div className="mt-3 pt-3 border-t border-border/50">
          <div className="flex items-center gap-4 text-[11px] text-muted">
            {primaryContact.phone && (
              <span className="flex items-center gap-1">
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                </svg>
                <span className="font-mono">{primaryContact.phone}</span>
              </span>
            )}
            {primaryEmail && (
              <span className="flex items-center gap-1 truncate">
                <svg className="w-3 h-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                <span className="truncate">{primaryEmail}</span>
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Registry Alert Row ── */

function RegistryAlertRow({ registryAlert, onSelectOperator }: {
  registryAlert: RegistryAlert;
  onSelectOperator: (op: RegistryOperator) => void;
}) {
  const { alert, match } = registryAlert;
  const enrichment = parseAIEnrichment(alert.note);
  const sev = enrichment?.assessed_severity || alert.severity || 'unknown';
  const host = alert.hostName || alert.hostname || '';
  const primaryContact = match.operator.contacts[0];

  const mailto = primaryContact
    ? buildRegistryMailto(match.operator, primaryContact, {
        alertName: alert.name,
        description: alert.description,
        startTime: alertStartTime(alert),
      })
    : null;

  return (
    <div className="flex items-center gap-3 bg-bg/60 border border-border/50 rounded-md px-3 py-2">
      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
        sev === 'critical' ? 'bg-red' : sev === 'high' ? 'bg-orange' : 'bg-yellow'
      }`} />
      <div className="min-w-0 flex-1">
        <div className="text-xs text-text-bright truncate">{alert.name}</div>
        <div className="text-[10px] text-muted">
          {match.matchReason} &middot; {match.operator.name}
          {host && <span className="font-mono ml-1">{host}</span>}
        </div>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        {mailto && (
          <a
            href={mailto}
            className="px-2.5 py-1 rounded-md bg-accent text-bg text-[10px] font-medium hover:bg-accent-hover transition-colors"
            title={`Email ${match.operator.name}`}
          >
            Contact Registry
          </a>
        )}
        <button
          onClick={() => onSelectOperator(match.operator)}
          className="px-2 py-1 rounded-md border border-border text-[10px] text-muted hover:text-text hover:bg-surface-hover transition-colors"
        >
          Details
        </button>
      </div>
    </div>
  );
}

/* ── Registry Health Banner ── */

function RegistryHealthBanner({ healthData }: { healthData: RegistryHealthData }) {
  const operators = Object.entries(healthData.operators);
  const healthy = operators.filter(([, h]) => h.status === 'healthy').length;
  const degraded = operators.filter(([, h]) => h.status === 'degraded').length;
  const down = operators.filter(([, h]) => h.status === 'down').length;
  const noData = operators.filter(([, h]) => h.status === 'no_data').length;
  const totalRequests = operators.reduce((sum, [, h]) => sum + h.request_count, 0);
  const avgResponse = operators.filter(([, h]) => h.request_count > 0).length > 0
    ? operators.reduce((sum, [, h]) => sum + h.avg_response_ms * h.request_count, 0) /
      operators.reduce((sum, [, h]) => sum + (h.request_count > 0 ? h.request_count : 0), 0)
    : 0;

  const overallStatus = down > 0 ? 'down' : degraded > 0 ? 'degraded' : 'healthy';

  return (
    <div className={`border rounded-lg px-5 py-4 ${
      overallStatus === 'down' ? 'bg-red/5 border-red/30' :
      overallStatus === 'degraded' ? 'bg-orange/5 border-orange/30' :
      'bg-green/5 border-green/30'
    }`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className={`w-2.5 h-2.5 rounded-full ${
              overallStatus === 'healthy' ? 'bg-green' :
              overallStatus === 'degraded' ? 'bg-orange animate-pulse' : 'bg-red animate-pulse'
            }`} />
            <span className="text-sm font-medium text-text-bright">EPP Health</span>
          </div>
          <div className="flex items-center gap-3 text-xs">
            {healthy > 0 && (
              <span className="text-green">{healthy} healthy</span>
            )}
            {degraded > 0 && (
              <span className="text-orange">{degraded} degraded</span>
            )}
            {down > 0 && (
              <span className="text-red">{down} down</span>
            )}
            {noData > 0 && (
              <span className="text-muted">{noData} no data</span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs text-muted">
          <span>{totalRequests.toLocaleString()} req/hr</span>
          {avgResponse > 0 && <span>{avgResponse.toFixed(0)}ms avg</span>}
          {healthData.last_updated && (
            <span>Updated {timeAgo(healthData.last_updated)}</span>
          )}
          {healthData.loki_error && (
            <span className="text-red" title={healthData.loki_error}>Loki error</span>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Code Descriptions ── */

const EPP_CODE_DESC: Record<string, string> = {
  '1000': 'Command completed successfully',
  '1001': 'Command completed successfully; action pending',
  '1300': 'Command completed successfully; no messages',
  '1301': 'Command completed successfully; ack to dequeue',
  '1500': 'Command completed successfully; ending session',
  '2000': 'Unknown command',
  '2001': 'Command syntax error',
  '2002': 'Command use error',
  '2003': 'Required parameter missing',
  '2004': 'Parameter value range error',
  '2005': 'Parameter value syntax error',
  '2100': 'Unimplemented protocol version',
  '2101': 'Unimplemented command',
  '2102': 'Unimplemented option',
  '2103': 'Unimplemented extension',
  '2104': 'Billing failure',
  '2105': 'Object not eligible for renewal',
  '2200': 'Authentication error',
  '2201': 'Authorization error',
  '2202': 'Invalid authorization information',
  '2300': 'Object pending transfer',
  '2301': 'Object not pending transfer',
  '2302': 'Object exists',
  '2303': 'Object does not exist',
  '2304': 'Object status prohibits operation',
  '2305': 'Object association prohibits operation',
  '2306': 'Parameter value policy error',
  '2308': 'Data management policy violation',
  '2400': 'Command failed',
  '2500': 'Command failed; server closing connection',
  '2501': 'Authentication error; server closing connection',
  '2502': 'Session limit exceeded; server closing connection',
};

const RESP_CODE_DESC: Record<string, string> = {
  '200': 'OK / Success',
  '210': 'Domain available',
  '211': 'Domain not available',
  '213': 'Name server exists',
  '420': 'Command failed / timeout',
  '531': 'Authorization error',
  '540': 'Attribute value not unique',
  '541': 'Invalid attribute value',
  '545': 'Object not found',
  '549': 'Command failed',
  '552': 'Object does not exist',
};

/* ── Operator Detail Modal ── */

function OperatorDetailModal({ operator, alerts, health, onClose }: {
  operator: RegistryOperator;
  alerts: RegistryAlert[];
  health: RegistryHealthOperator | null;
  onClose: () => void;
}) {
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [onClose]);

  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);

  const [trendsData, setTrendsData] = useState<any>(null);
  const [trendsLoading, setTrendsLoading] = useState(false);
  const [trendsError, setTrendsError] = useState<string | null>(null);
  const [trendsRange, setTrendsRange] = useState(86400);

  const loadTrends = async (seconds: number) => {
    setTrendsLoading(true);
    setTrendsError(null);
    setTrendsRange(seconds);
    try {
      const data = await fetchRegistryTrends(operator.id, seconds);
      setTrendsData(data);
    } catch (err: any) {
      setTrendsError(err.message || 'Failed to load trends');
      setTrendsData(null);
    } finally {
      setTrendsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center">
      <div className="absolute inset-0 bg-bg/80 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto mt-[5vh] mx-4 bg-surface border border-border rounded-xl shadow-2xl">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 z-10 w-8 h-8 flex items-center justify-center rounded-md text-muted hover:text-text hover:bg-surface-hover transition-colors"
        >
          &times;
        </button>

        <div className="p-6 space-y-5">
          {/* Header */}
          <div>
            <h2 className="text-lg font-bold text-text-bright pr-8">{operator.name}</h2>
            <div className="flex flex-wrap gap-1.5 mt-2">
              {operator.tlds.map(tld => (
                <span key={tld} className="text-xs font-mono px-2 py-0.5 rounded bg-accent/10 text-accent border border-accent/20">
                  {tld}
                </span>
              ))}
            </div>
            <div className="flex flex-wrap gap-3 mt-2 text-xs text-muted">
              {operator.type && <span>Type: <span className="text-text">{operator.type}</span></span>}
              {operator.hours && <span>Hours: <span className="text-text">{operator.hours}</span></span>}
            </div>
          </div>

          {/* Active Alerts for this Registry */}
          {alerts.length > 0 && (
            <div className="bg-orange/5 border border-orange/30 rounded-lg px-4 py-3 space-y-2">
              <h3 className="text-xs font-medium text-orange">
                {alerts.length} Active Alert{alerts.length !== 1 ? 's' : ''} Related to this Registry
              </h3>
              {alerts.map(ra => {
                const host = ra.alert.hostName || ra.alert.hostname || '';
                const enrichment = parseAIEnrichment(ra.alert.note);
                const sev = enrichment?.assessed_severity || ra.alert.severity || 'unknown';
                const primaryContact = operator.contacts[0];
                const mailto = primaryContact
                  ? buildRegistryMailto(operator, primaryContact, {
                      alertName: ra.alert.name,
                      description: ra.alert.description,
                      startTime: alertStartTime(ra.alert),
                    })
                  : null;

                return (
                  <div key={ra.alert.fingerprint} className="flex items-center gap-2 text-xs">
                    <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                      sev === 'critical' ? 'bg-red' : sev === 'high' ? 'bg-orange' : 'bg-yellow'
                    }`} />
                    <span className="text-text-bright truncate flex-1">{ra.alert.name}</span>
                    <span className="text-muted">{timeAgo(alertStartTime(ra.alert))}</span>
                    {mailto && (
                      <a
                        href={mailto}
                        className="px-2 py-0.5 rounded bg-accent text-bg text-[10px] font-medium hover:bg-accent-hover transition-colors"
                      >
                        Email
                      </a>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* EPP Health Metrics */}
          {health && health.status !== 'no_data' && (
            <div className="space-y-3">
              <h3 className="text-sm font-medium text-text-bright">EPP Health Metrics (Last Hour)</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-bg/40 border border-border rounded-lg px-3 py-2 text-center">
                  <div className="text-[10px] text-muted uppercase">Status</div>
                  <div className={`text-sm font-bold ${
                    health.status === 'healthy' ? 'text-green' :
                    health.status === 'degraded' ? 'text-orange' : 'text-red'
                  }`}>{health.status.toUpperCase()}</div>
                </div>
                <div className="bg-bg/40 border border-border rounded-lg px-3 py-2 text-center">
                  <div className="text-[10px] text-muted uppercase">Avg Response</div>
                  <div className="text-sm font-bold text-text-bright">{health.avg_response_ms.toFixed(0)}ms</div>
                  <div className="text-[10px] text-muted">p95: {health.p95_response_ms}ms</div>
                </div>
                <div className="bg-bg/40 border border-border rounded-lg px-3 py-2 text-center">
                  <div className="text-[10px] text-muted uppercase">Requests</div>
                  <div className="text-sm font-bold text-text-bright">{health.request_count.toLocaleString()}</div>
                  <div className="text-[10px] text-muted">last hour</div>
                </div>
                <div className="bg-bg/40 border border-border rounded-lg px-3 py-2 text-center">
                  <div className="text-[10px] text-muted uppercase">Error Rate</div>
                  <div className={`text-sm font-bold ${health.error_rate > 0.1 ? 'text-red' : health.error_rate > 0.01 ? 'text-orange' : 'text-green'}`}>
                    {(health.error_rate * 100).toFixed(1)}%
                  </div>
                </div>
              </div>

              {Object.keys(health.epp_codes).length > 0 && (
                <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
                  <h4 className="text-xs font-medium text-muted mb-2">EPP Response Codes</h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(health.epp_codes).map(([code, count]) => (
                      <span
                        key={code}
                        title={EPP_CODE_DESC[code] || `EPP code ${code}`}
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border cursor-help ${
                          Number(code) >= 2000 ? 'bg-red/10 border-red/30 text-red' :
                          Number(code) > 1000 ? 'bg-orange/10 border-orange/30 text-orange' :
                          'bg-green/10 border-green/30 text-green'
                        }`}
                      >
                        {code}: {count}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {Object.keys(health.resp_codes).length > 0 && (
                <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
                  <h4 className="text-xs font-medium text-muted mb-2">Internal Response Codes</h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(health.resp_codes).map(([code, count]) => (
                      <span
                        key={code}
                        title={RESP_CODE_DESC[code] || `Response code ${code}`}
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border cursor-help ${
                          Number(code) >= 400 ? 'bg-red/10 border-red/30 text-red' :
                          'bg-green/10 border-green/30 text-green'
                        }`}
                      >
                        {code}: {count}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {Object.keys(health.top_operations).length > 0 && (
                <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
                  <h4 className="text-xs font-medium text-muted mb-2">Top Operations</h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(health.top_operations).map(([op, count]) => (
                      <span key={op} className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent/10 text-accent border border-accent/20">
                        {op}: {count}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Performance Trends */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-medium text-text-bright">Performance Trends</h3>
              <div className="flex gap-1">
                {[{ label: '5m', secs: 300 }, { label: '15m', secs: 900 }, { label: '30m', secs: 1800 }, { label: '1h', secs: 3600 }, { label: '6h', secs: 21600 }, { label: '24h', secs: 86400 }, { label: '7d', secs: 604800 }].map(opt => (
                  <button
                    key={opt.secs}
                    onClick={() => loadTrends(opt.secs)}
                    className={`px-2.5 py-1 rounded-md text-[10px] font-medium transition-colors ${
                      trendsRange === opt.secs && trendsData
                        ? 'bg-accent text-bg'
                        : 'border border-border text-muted hover:text-text hover:bg-surface-hover'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
            {trendsLoading && (
              <div className="text-xs text-muted text-center py-6">Loading trends...</div>
            )}
            {trendsError && (
              <div className="text-xs text-red text-center py-4">{trendsError}</div>
            )}
            {trendsData && trendsData.buckets && !trendsLoading && (
              <TrendsTable buckets={trendsData.buckets} />
            )}
            {!trendsData && !trendsLoading && !trendsError && (
              <div className="text-xs text-muted text-center py-6 bg-bg/40 border border-border rounded-lg">
                Click a time range above to load performance trends.
              </div>
            )}
          </div>

          {/* All Contacts */}
          <div className="space-y-3">
            <h3 className="text-sm font-medium text-text-bright">Contacts</h3>
            {operator.contacts.map((contact, i) => (
              <ContactRow key={i} operator={operator} contact={contact} />
            ))}
            {operator.contacts.length === 0 && (
              <div className="text-xs text-muted">No direct contacts listed.</div>
            )}
          </div>

          {/* Status Page */}
          {operator.statusPage && (
            <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
              <h4 className="text-xs font-medium text-muted mb-1">Status Page</h4>
              <a
                href={operator.statusPage}
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-accent hover:text-accent-hover transition-colors"
              >
                {operator.statusPage}
              </a>
            </div>
          )}

          {/* Notes */}
          {operator.notes && (
            <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
              <h4 className="text-xs font-medium text-muted mb-1">Notes</h4>
              <p className="text-sm text-text whitespace-pre-wrap">{operator.notes}</p>
            </div>
          )}

          <div className="flex justify-end pt-2 border-t border-border">
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

/* ── Contact Row ── */

function ContactRow({ operator, contact }: { operator: RegistryOperator; contact: RegistryContact }) {
  const mailto = buildRegistryMailto(operator, contact);

  return (
    <div className="border border-border/50 rounded-md px-4 py-3 bg-bg/30">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-xs font-medium text-text-bright">{contact.role}</div>
          <div className="flex flex-wrap gap-x-4 gap-y-1 mt-1.5">
            {contact.phone && (
              <a
                href={`tel:${contact.phone.replace(/[^+\d]/g, '')}`}
                className="flex items-center gap-1 text-[11px] text-muted hover:text-text transition-colors"
              >
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                </svg>
                <span className="font-mono">{contact.phone}</span>
              </a>
            )}
            {contact.email && (
              <a
                href={mailto || `mailto:${contact.email}`}
                className="flex items-center gap-1 text-[11px] text-accent hover:text-accent-hover transition-colors"
              >
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
                <span>{contact.email}</span>
              </a>
            )}
          </div>
          {contact.notes && (
            <div className="text-[10px] text-muted mt-1.5">{contact.notes}</div>
          )}
        </div>
        {contact.email && (
          <a
            href={mailto || `mailto:${contact.email}`}
            className="px-2.5 py-1 rounded-md border border-accent/30 text-accent text-[10px] font-medium hover:bg-accent/10 transition-colors flex-shrink-0"
          >
            Email
          </a>
        )}
      </div>
    </div>
  );
}

/* ── Trends Chart ── */

function TrendsTable({ buckets }: { buckets: Array<{ timestamp: string; avg_response_ms: number; error_rate: number; request_count: number }> }) {
  if (!buckets.length) return <div className="text-xs text-muted text-center py-4">No data for this time range.</div>;

  // Summary stats across all buckets
  const totalRequests = buckets.reduce((s, b) => s + b.request_count, 0);
  const weightedMs = buckets.reduce((s, b) => s + b.avg_response_ms * b.request_count, 0);
  const avgMs = totalRequests > 0 ? weightedMs / totalRequests : 0;
  const maxMs = Math.max(...buckets.map(b => b.avg_response_ms));
  const totalErrors = buckets.reduce((s, b) => s + Math.round(b.error_rate * b.request_count), 0);
  const overallErrorRate = totalRequests > 0 ? totalErrors / totalRequests : 0;

  const formatTime = (ts: string) => {
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch { return ts; }
  };

  return (
    <div className="space-y-3">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-bg/40 border border-border rounded-lg px-3 py-2 text-center">
          <div className="text-[10px] text-muted uppercase">Avg Response</div>
          <div className="text-sm font-bold text-text-bright">{avgMs.toFixed(0)}ms</div>
          <div className="text-[10px] text-muted">peak: {maxMs.toFixed(0)}ms</div>
        </div>
        <div className="bg-bg/40 border border-border rounded-lg px-3 py-2 text-center">
          <div className="text-[10px] text-muted uppercase">Requests</div>
          <div className="text-sm font-bold text-text-bright">{totalRequests.toLocaleString()}</div>
          <div className="text-[10px] text-muted">{buckets.length} buckets</div>
        </div>
        <div className="bg-bg/40 border border-border rounded-lg px-3 py-2 text-center">
          <div className="text-[10px] text-muted uppercase">Error Rate</div>
          <div className={`text-sm font-bold ${overallErrorRate > 0.1 ? 'text-red' : overallErrorRate > 0.01 ? 'text-orange' : 'text-green'}`}>
            {(overallErrorRate * 100).toFixed(1)}%
          </div>
          <div className="text-[10px] text-muted">{totalErrors} errors</div>
        </div>
        <div className="bg-bg/40 border border-border rounded-lg px-3 py-2 text-center">
          <div className="text-[10px] text-muted uppercase">Status</div>
          <div className={`text-sm font-bold ${overallErrorRate > 0.1 ? 'text-red' : overallErrorRate > 0.01 ? 'text-orange' : 'text-green'}`}>
            {overallErrorRate > 0.1 ? 'DEGRADED' : overallErrorRate > 0.01 ? 'WARNING' : 'HEALTHY'}
          </div>
        </div>
      </div>

      {/* Bucket Table */}
      <div className="bg-bg/40 border border-border rounded-lg overflow-hidden">
        <div className="max-h-[200px] overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface">
              <tr className="border-b border-border">
                <th className="text-left px-3 py-1.5 text-muted font-medium">Time</th>
                <th className="text-right px-3 py-1.5 text-muted font-medium">Avg (ms)</th>
                <th className="text-right px-3 py-1.5 text-muted font-medium">Requests</th>
                <th className="text-right px-3 py-1.5 text-muted font-medium">Errors</th>
              </tr>
            </thead>
            <tbody>
              {buckets.map((b, i) => {
                const errPct = (b.error_rate * 100);
                return (
                  <tr key={i} className="border-b border-border/30 hover:bg-surface-hover/50">
                    <td className="px-3 py-1 text-muted font-mono">{formatTime(b.timestamp)}</td>
                    <td className={`px-3 py-1 text-right font-mono ${b.avg_response_ms > avgMs * 2 ? 'text-orange' : 'text-text-bright'}`}>
                      {b.avg_response_ms.toFixed(0)}
                    </td>
                    <td className="px-3 py-1 text-right font-mono text-text-bright">{b.request_count}</td>
                    <td className={`px-3 py-1 text-right font-mono ${errPct > 10 ? 'text-red' : errPct > 1 ? 'text-orange' : 'text-green'}`}>
                      {errPct.toFixed(1)}%
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
