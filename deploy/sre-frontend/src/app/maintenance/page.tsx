'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { fetchRegistryHealth, RegistryHealthData, RegistryHealthOperator, MaintenanceEvent, fetchMaintenanceEvents } from '@/lib/keep-api';
import { REGISTRY_OPERATORS } from '@/lib/registry';

interface ApiResponse {
  count: number;
  results: MaintenanceEvent[];
}

type Category = 'registry_maintenance' | 'registry_changes' | 'system_changes';

const CATEGORY_META: Record<Category, { label: string; color: string; ringColor: string; description: string }> = {
  registry_maintenance: {
    label: 'Registry Maintenance',
    color: 'text-yellow',
    ringColor: 'ring-yellow/50',
    description: 'Scheduled registry maintenance windows and vendor service disruptions',
  },
  registry_changes: {
    label: 'Registry Changes',
    color: 'text-accent',
    ringColor: 'ring-accent/50',
    description: 'TLD policy changes, domain registration updates, and registry modifications',
  },
  system_changes: {
    label: 'System Changes',
    color: 'text-blue',
    ringColor: 'ring-blue/50',
    description: 'Infrastructure updates, server patches, and deployment changes',
  },
};

// TLD and registry keywords that indicate registry-level changes (not system infra)
const REGISTRY_CHANGE_PATTERNS = [
  /\.[a-z]{2,6}\b/i,         // TLD references like .CAT, .AU, .PL
  /\bFRONTS?\b/i,            // OpenSRS FRONTS (frontend registry changes)
  /\bregistry\b/i,
  /\bregistrar\b/i,
  /\bTLD\b/i,
  /\bdomain\b/i,
  /\bWHOIS\b/i,
  /\bEPP\b/i,
  /\bDNSSEC\b/i,
  /\bzone\b/i,
];

function categorize(event: MaintenanceEvent): Category {
  // All maintenance-type events are registry maintenance (vendor status pages, slack notifications)
  if (event.event_type === 'maintenance') {
    return 'registry_maintenance';
  }

  // For change-type events, check if it's registry-related or system-related
  const text = `${event.title} ${event.summary || ''}`;
  const isRegistryRelated = REGISTRY_CHANGE_PATTERNS.some(p => p.test(text));

  if (isRegistryRelated) {
    return 'registry_changes';
  }

  // Default: system changes (patches, storage, deploys, etc.)
  return 'system_changes';
}

function sourceBg(type: string): string {
  switch (type) {
    case 'jira': return 'bg-blue/20 border-blue/40 text-blue';
    case 'vendor_status': return 'bg-orange/20 border-orange/40 text-orange';
    case 'slack': return 'bg-accent/20 border-accent/40 text-accent';
    default: return 'bg-muted/20 border-muted/40 text-muted';
  }
}

function sourceLabel(type: string): string {
  switch (type) {
    case 'jira': return 'Jira';
    case 'vendor_status': return 'Vendor';
    case 'slack': return 'Slack';
    default: return type;
  }
}

function statusColor(status: string | null): string {
  if (!status) return 'text-muted';
  const s = status.toLowerCase();
  if (s === 'in_progress' || s === 'in progress') return 'text-orange';
  if (s === 'scheduled') return 'text-blue';
  if (s === 'planning' || s === 'peer review') return 'text-yellow';
  if (s === 'awaiting implementation') return 'text-muted';
  if (s === 'completed' || s === 'resolved') return 'text-green';
  return 'text-text';
}

function formatStatus(status: string | null): string {
  if (!status) return 'Active';
  return status.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatTime(dateStr: string): string {
  try {
    const d = new Date(dateStr);
    return d.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
  } catch {
    return dateStr;
  }
}

function timeUntil(dateStr: string): string {
  const now = new Date();
  const target = new Date(dateStr);
  const diffMs = target.getTime() - now.getTime();

  if (diffMs < 0) {
    const ago = Math.abs(diffMs);
    if (ago < 3600000) return `${Math.floor(ago / 60000)}m ago`;
    if (ago < 86400000) return `${Math.floor(ago / 3600000)}h ago`;
    return `${Math.floor(ago / 86400000)}d ago`;
  }

  if (diffMs < 3600000) return `in ${Math.floor(diffMs / 60000)}m`;
  if (diffMs < 86400000) return `in ${Math.floor(diffMs / 3600000)}h`;
  return `in ${Math.floor(diffMs / 86400000)}d`;
}

function isActive(event: MaintenanceEvent): boolean {
  const now = new Date();
  const start = new Date(event.start_time);
  const end = event.end_time ? new Date(event.end_time) : null;
  return start <= now && (!end || end > now);
}

export default function MaintenancePage() {
  const [events, setEvents] = useState<MaintenanceEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [search, setSearch] = useState('');
  const [healthData, setHealthData] = useState<RegistryHealthData | null>(null);

  const load = useCallback(async () => {
    try {
      const results = await fetchMaintenanceEvents();
      setEvents(results);
      setLastUpdated(new Date());
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to fetch maintenance data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 60000);
    return () => clearInterval(interval);
  }, [load]);

  useEffect(() => {
    const loadHealth = () => { fetchRegistryHealth().then(setHealthData); };
    loadHealth();
    const interval = setInterval(loadHealth, 300_000);
    return () => clearInterval(interval);
  }, []);

  const filtered = useMemo(() => {
    if (!search.trim()) return events;
    const q = search.toLowerCase();
    return events.filter(e => {
      const text = [e.title, e.vendor, e.summary, e.impact, e.status]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return text.includes(q);
    });
  }, [events, search]);

  const categorized = useMemo(() => {
    const groups: Record<Category, MaintenanceEvent[]> = {
      registry_maintenance: [],
      registry_changes: [],
      system_changes: [],
    };
    for (const e of filtered) {
      groups[categorize(e)].push(e);
    }
    // Sort each group: active first, then by start_time descending
    for (const key of Object.keys(groups) as Category[]) {
      groups[key].sort((a, b) => {
        const aActive = isActive(a) ? 0 : 1;
        const bActive = isActive(b) ? 0 : 1;
        if (aActive !== bActive) return aActive - bActive;
        return new Date(b.start_time).getTime() - new Date(a.start_time).getTime();
      });
    }
    return groups;
  }, [filtered]);

  const activeCount = events.filter(isActive).length;
  const totalFiltered = filtered.length;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted animate-pulse">Loading maintenance data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-text-bright">Maintenance Tracker</h1>
        <div className="text-xs text-muted">
          {lastUpdated && `Updated ${lastUpdated.toLocaleTimeString()}`}
          {' '}&middot;{' '}Auto-refresh 60s
        </div>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-red text-sm">
          {error}
        </div>
      )}

      {/* Search */}
      <div className="relative">
        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search events by keyword (vendor, title, impact...)"
          className="w-full bg-surface border border-border rounded-lg px-4 py-2.5 pl-10 text-sm text-text placeholder:text-muted focus:outline-none focus:border-accent/50 focus:ring-1 focus:ring-accent/30 transition-colors"
        />
        <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        {search && (
          <button
            onClick={() => setSearch('')}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text transition-colors text-sm"
          >
            &times;
          </button>
        )}
      </div>

      {search && (
        <div className="text-xs text-muted">
          Showing {totalFiltered} of {events.length} events matching &ldquo;{search}&rdquo;
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="text-xs text-muted uppercase tracking-wider mb-1">Total Events</div>
          <div className="text-3xl font-bold text-text-bright">{events.length}</div>
        </div>
        <div className="stat-card">
          <div className="text-xs text-muted uppercase tracking-wider mb-1">Active Now</div>
          <div className="text-3xl font-bold text-orange">{activeCount}</div>
        </div>
        <div className="stat-card">
          <div className="text-xs text-muted uppercase tracking-wider mb-1">Registry</div>
          <div className="text-3xl font-bold text-yellow">
            {categorized.registry_maintenance.length + categorized.registry_changes.length}
          </div>
        </div>
        <div className="stat-card">
          <div className="text-xs text-muted uppercase tracking-wider mb-1">System</div>
          <div className="text-3xl font-bold text-blue">{categorized.system_changes.length}</div>
        </div>
      </div>

      {/* EPP Health Issues */}
      {healthData && <EppHealthSection healthData={healthData} />}

      {/* Category Sections */}
      {(Object.keys(CATEGORY_META) as Category[]).map(cat => (
        <CategorySection
          key={cat}
          category={cat}
          events={categorized[cat]}
        />
      ))}

      {totalFiltered === 0 && (
        <div className="stat-card text-center text-muted py-12">
          {search ? `No events matching "${search}"` : 'No active maintenance events or change requests'}
        </div>
      )}
    </div>
  );
}

function CategorySection({ category, events }: { category: Category; events: MaintenanceEvent[] }) {
  const meta = CATEGORY_META[category];

  if (events.length === 0) return null;

  return (
    <div>
      <div className="flex items-center gap-3 mb-3">
        <h2 className={`text-lg font-semibold ${meta.color}`}>{meta.label}</h2>
        <span className="text-xs text-muted bg-surface-hover rounded-full px-2 py-0.5">
          {events.length}
        </span>
        <span className="text-xs text-muted hidden md:inline">{meta.description}</span>
      </div>
      <div className="space-y-2">
        {events.map(event => (
          <EventCard key={`${event.source_type}-${event.id}`} event={event} />
        ))}
      </div>
    </div>
  );
}

/* ── EPP Code Descriptions ── */

const EPP_CODE_DESC: Record<string, string> = {
  '1000': 'Command completed successfully',
  '1001': 'Command completed successfully; action pending',
  '1300': 'Command completed successfully; no messages',
  '1301': 'Command completed successfully; ack to dequeue',
  '2000': 'Unknown command',
  '2001': 'Command syntax error',
  '2003': 'Required parameter missing',
  '2005': 'Parameter value syntax error',
  '2104': 'Billing failure',
  '2200': 'Authentication error',
  '2201': 'Authorization error',
  '2202': 'Invalid authorization information',
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

function operatorDisplayName(opId: string): string {
  const op = REGISTRY_OPERATORS.find(o => o.id === opId);
  return op?.name || opId.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

/* ── EPP Maintenance Codes ── */

// Only these EPP codes indicate a registry maintenance window (server going offline)
const EPP_MAINTENANCE_CODES = new Set(['2500', '2501', '2502']);

function EppHealthSection({ healthData }: { healthData: RegistryHealthData }) {
  // Build list of operators returning maintenance codes
  const maintOps: [string, RegistryHealthOperator, [string, number][]][] = [];
  for (const [opId, health] of Object.entries(healthData.operators)) {
    const maintCodes = Object.entries(health.epp_codes)
      .filter(([c]) => EPP_MAINTENANCE_CODES.has(c));
    if (maintCodes.length > 0) {
      maintOps.push([opId, health, maintCodes]);
    }
  }

  if (maintOps.length === 0) return null;

  return (
    <div>
      <div className="flex items-center gap-3 mb-3">
        <h2 className="text-lg font-semibold text-red">Registry EPP Maintenance</h2>
        <span className="text-xs text-muted bg-surface-hover rounded-full px-2 py-0.5">
          {maintOps.length} operator{maintOps.length !== 1 ? 's' : ''}
        </span>
        <span className="text-xs text-muted hidden md:inline">
          Registries returning EPP &ldquo;server closing connection&rdquo; codes
        </span>
        {healthData.last_updated && (
          <span className="text-[10px] text-muted ml-auto">
            Updated {timeUntil(healthData.last_updated).replace('ago', 'ago')}
          </span>
        )}
      </div>

      <div className="space-y-2">
        {maintOps.map(([opId, health, codes]) => (
          <div key={opId} className="stat-card border-red/40 transition-all">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-2">
                  <span className="badge bg-red/20 border-red/40 text-red">Maintenance</span>
                  <span className="text-sm font-medium text-text-bright">
                    {operatorDisplayName(opId)}
                  </span>
                  <span className="text-xs text-muted">
                    {health.request_count.toLocaleString()} req/hr
                  </span>
                </div>

                <div className="flex flex-wrap gap-1.5">
                  {codes.map(([code, count]) => (
                    <span
                      key={code}
                      title={EPP_CODE_DESC[code] || `EPP code ${code}`}
                      className="text-[10px] font-mono px-2 py-0.5 rounded border cursor-help bg-red/10 border-red/30 text-red"
                    >
                      {code}: {count} &mdash; {EPP_CODE_DESC[code] || 'Unknown'}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function EventCard({ event }: { event: MaintenanceEvent }) {
  const active = isActive(event);

  return (
    <div className={`stat-card transition-all ${active ? 'border-orange/30' : ''}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          {/* Header badges */}
          <div className="flex items-center gap-2 flex-wrap mb-2">
            <span className={`badge ${sourceBg(event.source_type)}`}>
              {sourceLabel(event.source_type)}
            </span>
            {active && (
              <span className="badge bg-orange/20 border-orange/40 text-orange">
                ACTIVE
              </span>
            )}
            {event.status && (
              <span className={`text-xs ${statusColor(event.status)}`}>
                {formatStatus(event.status)}
              </span>
            )}
            <span className="text-xs text-muted">{event.vendor}</span>
          </div>

          {/* Title */}
          <a
            href={event.permalink}
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm font-medium text-text-bright hover:text-accent transition-colors"
          >
            {event.title}
          </a>

          {/* Impact */}
          {event.impact && event.impact !== 'maintenance' && event.impact !== 'N/A' && event.impact !== 'None' && (
            <div className="text-xs text-text mt-2 bg-surface-hover/50 rounded px-2 py-1.5">
              <span className="text-muted">Impact: </span>{event.impact}
            </div>
          )}
          {/* Summary */}
          {event.summary && event.summary !== 'N/A' && event.summary !== 'None' && event.summary !== event.impact && (
            <div className="text-xs text-muted mt-1.5 line-clamp-2">
              {event.summary}
            </div>
          )}
        </div>

        {/* Time column */}
        <div className="text-right flex-shrink-0">
          <div className="text-xs text-muted">
            {formatTime(event.start_time)}
          </div>
          {event.end_time && (
            <div className="text-xs text-muted">
              {'\u2192'} {formatTime(event.end_time)}
            </div>
          )}
          <div className={`text-xs mt-1 font-mono ${active ? 'text-orange' : 'text-muted'}`}>
            {timeUntil(event.start_time)}
          </div>
        </div>
      </div>
    </div>
  );
}
