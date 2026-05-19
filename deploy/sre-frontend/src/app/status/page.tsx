'use client';

import { useEffect, useState } from 'react';
import { fetchInternalStatuspageSummary } from '@/lib/keep-api';
import type { InternalStatuspageSummary } from '@/lib/types';

function statusLabel(status: string) {
  return status.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function statusTone(status: string) {
  if (status === 'critical') return 'text-red-300 border-red-500/40 bg-red-500/10';
  if (status === 'major') return 'text-yellow-300 border-yellow-500/40 bg-yellow-500/10';
  if (status === 'minor' || status === 'maintenance') return 'text-accent border-accent/40 bg-accent/10';
  return 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10';
}

export default function StatusPage() {
  const [summary, setSummary] = useState<InternalStatuspageSummary | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchInternalStatuspageSummary()
      .then(setSummary)
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to load statuspage'));
  }, []);

  if (error) {
    return <div className="border border-red-500/40 bg-red-500/10 rounded-lg p-4 text-red-300">{error}</div>;
  }

  if (!summary) {
    return <div className="text-muted animate-pulse">Loading status...</div>;
  }

  const hasActive = summary.active_incidents.length > 0;
  const overall = hasActive ? summary.overall_status : 'operational';

  return (
    <div className="min-h-screen bg-bg">
      <header className={`border-b ${statusTone(overall)}`}>
        <div className="max-w-5xl mx-auto px-4 py-8">
          <div className="text-xs uppercase text-muted">Tucows Domains SRE</div>
          <h1 className="text-3xl font-semibold text-text-bright mt-1">Service Status</h1>
          <p className="mt-2 text-lg">{hasActive ? statusLabel(summary.overall_status) : 'All systems operational'}</p>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8 space-y-8">
      <section>
        <h2 className="text-lg font-semibold text-text-bright mb-3">Components</h2>
        <div className="space-y-4">
          {summary.component_groups.map((group) => (
            <div key={group.id ?? 'ungrouped'} className="border border-border rounded-lg bg-surface">
              <div className="px-4 py-3 border-b border-border">
                <div className="font-medium text-text-bright">{group.name}</div>
                {group.description && <div className="text-xs text-muted mt-1">{group.description}</div>}
              </div>
              <div className="divide-y divide-border">
                {group.components.map((component) => (
                  <div key={component.id} className="p-4 flex items-center justify-between gap-4">
                    <div>
                      <div className="font-medium text-text-bright">{component.name}</div>
                      {component.description && <div className="text-xs text-muted mt-1">{component.description}</div>}
                    </div>
                    <span className="text-sm text-accent whitespace-nowrap">{statusLabel(component.status)}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
          {summary.components.length === 0 && (
            <div className="border border-border rounded-lg p-4 bg-surface text-muted">No components configured.</div>
          )}
        </div>
      </section>

      <section>
        <h2 className="text-lg font-semibold text-text-bright mb-3">Active Incidents</h2>
        {summary.active_incidents.length === 0 ? (
          <div className="border border-border rounded-lg p-4 bg-surface text-muted">No active incidents.</div>
        ) : (
          <div className="space-y-3">
            {summary.active_incidents.map((incident) => (
              <article key={incident.id} className="border border-border rounded-lg p-4 bg-surface">
                <div className="text-text-bright font-medium">{incident.title}</div>
                <div className="text-sm text-muted mt-1">{statusLabel(incident.status)} - {statusLabel(incident.impact)}</div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="text-lg font-semibold text-text-bright mb-3">Recent History</h2>
        <div className="space-y-2">
          {summary.recent_incidents.map((incident) => (
            <div key={incident.id} className="border border-border rounded-lg p-3 bg-surface flex justify-between gap-4">
              <span>{incident.title}</span>
              <span className="text-muted text-sm whitespace-nowrap">{incident.resolved_at || incident.updated_at}</span>
            </div>
          ))}
          {summary.recent_incidents.length === 0 && <div className="text-muted">No resolved incidents yet.</div>}
        </div>
      </section>
      </main>
    </div>
  );
}

