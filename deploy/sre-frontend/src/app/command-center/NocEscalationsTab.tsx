'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';

interface BotStatus {
  ok: boolean;
  config: {
    noc_turnover_enabled: boolean;
    noc_turnover_channel_id: string;
  };
  noc_turnover?: {
    next_refresh_ts: string | null;
    active_shift_key: string | null;
    open_count: number;
  } | null;
}

interface OngoingIncident {
  slack_ts: string;
  posted_at: number;
  poster_user_id: string;
  text_preview: string;
  permalink: string;
  occir_key: string | null;
  occir_status: string | null;
  reply_count: number;
  unique_responder_count: number;
  resolved_at: number | null;
  resolved_source: string | null;
  mttr_seconds: number | null;
  claimed_by_user_id?: string | null;
}

interface OngoingMetrics {
  total: number;
  open: number;
  resolved: number;
  median_ack_seconds: number | null;
  pct_acked_within_threshold: number | null;
  threshold_minutes: number;
  avg_replies: number | null;
  mttr_seconds: number | null;
}

interface OngoingResponse {
  open: OngoingIncident[];
  closed_today: OngoingIncident[];
  metrics: OngoingMetrics;
}

const JIRA = 'https://wiki-tucows.atlassian.net';

function cleanSlackText(text: string): string {
  return text
    .replace(/<!subteam\^[A-Z0-9]+(?:\|[^>]+)?>/g, '')
    .replace(/<@[UW][A-Z0-9]+(?:\|[^>]+)?>/g, '')
    .replace(/<!(channel|here|everyone)(?:\|[^>]+)?>/g, '')
    .replace(/<([^|>]+)\|([^>]+)>/g, '$2')
    .replace(/<([^>]+)>/g, '$1')
    .replace(/\s+/g, ' ')
    .replace(/^[\s,.:;-]+/, '')
    .trim();
}

function fmtDuration(seconds: number | null): string {
  if (seconds === null) return '-';
  if (seconds < 60) return '<1m';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

function fmtPct(p: number | null): string {
  return p === null ? '-' : `${Math.round(p * 100)}%`;
}

function fmtAvg(v: number | null): string {
  return v === null ? '-' : v.toFixed(1);
}

function fmtET(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString('en-US', {
    timeZone: 'America/New_York',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function shortShift(key: string | null | undefined): string {
  if (!key) return '-';
  const [, month, day, slot] = key.split('-');
  return slot ? `${month}/${day} ${slot}` : key;
}

export default function NocEscalationsTab() {
  const [status, setStatus] = useState<BotStatus | null>(null);
  const [ongoing, setOngoing] = useState<OngoingResponse | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [resolving, setResolving] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [statusRes, ongoingRes] = await Promise.all([
        fetch('/api/noc-bot/status'),
        fetch('/api/noc-bot/ongoing'),
      ]);
      if (!statusRes.ok) throw new Error(`NOC status ${statusRes.status}`);
      if (!ongoingRes.ok) throw new Error(`NOC ongoing ${ongoingRes.status}`);
      setStatus(await statusRes.json());
      setOngoing(await ongoingRes.json());
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'NOC bot API unavailable');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 30000);
    return () => clearInterval(id);
  }, [fetchData]);

  async function refreshTurnover() {
    setRefreshing(true);
    try {
      await fetch('/api/noc-bot/turnover/refresh', { method: 'POST' });
      await fetchData();
    } finally {
      setRefreshing(false);
    }
  }

  async function resolveIncident(slackTs: string) {
    setResolving(slackTs);
    try {
      await fetch(`/api/noc-bot/incident/${slackTs}/resolve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: 'dashboard' }),
      });
      await fetchData();
    } finally {
      setResolving(null);
    }
  }

  const metrics = ongoing?.metrics;
  const now = Math.floor(Date.now() / 1000);
  const open = useMemo(
    () => [...(ongoing?.open ?? [])].sort((a, b) => a.posted_at - b.posted_at),
    [ongoing?.open],
  );
  const closed = ongoing?.closed_today ?? [];

  if (loading) {
    return <div className="stat-card py-10 text-center text-sm text-muted">Loading NOC escalations...</div>;
  }

  return (
    <div className="space-y-5">
      {error && (
        <div className="rounded-lg border border-red/30 bg-red/10 px-4 py-3 text-sm text-red">
          {error}
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-4">
        <Metric label="Open now" value={String(metrics?.open ?? status?.noc_turnover?.open_count ?? 0)} tone="red" />
        <Metric label="Median ack" value={fmtDuration(metrics?.median_ack_seconds ?? null)} />
        <Metric label="Ack target" value={`${fmtPct(metrics?.pct_acked_within_threshold ?? null)} <= ${metrics?.threshold_minutes ?? 15}m`} />
        <Metric label="Avg replies" value={fmtAvg(metrics?.avg_replies ?? null)} />
      </div>

      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <section className="stat-card overflow-hidden p-0">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div>
              <h3 className="text-sm font-semibold text-text-bright">Active Queue</h3>
              <p className="text-xs text-muted mt-0.5">Open escalation threads currently visible to turnover.</p>
            </div>
            <button
              onClick={fetchData}
              className="rounded-md border border-border px-2.5 py-1 text-xs text-muted hover:text-text hover:bg-surface-hover"
            >
              Refresh
            </button>
          </div>

          {open.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-muted">No open escalations.</div>
          ) : (
            <div className="divide-y divide-border/60">
              {open.map((incident) => (
                <IncidentRow
                  key={incident.slack_ts}
                  incident={incident}
                  ageSeconds={now - incident.posted_at}
                  resolving={resolving === incident.slack_ts}
                  onResolve={() => resolveIncident(incident.slack_ts)}
                />
              ))}
            </div>
          )}
        </section>

        <aside className="space-y-4">
          <section className="stat-card">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-text-bright">Turnover</h3>
                <p className="text-xs text-muted mt-0.5">Shift post state and resolve check.</p>
              </div>
              <span className={`rounded-full border px-2 py-0.5 text-[10px] ${
                status?.config?.noc_turnover_enabled
                  ? 'border-green/30 bg-green/10 text-green'
                  : 'border-orange/30 bg-orange/10 text-orange'
              }`}>
                {status?.config?.noc_turnover_enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
            <div className="mt-4 space-y-2 text-xs">
              <Info label="Active shift" value={shortShift(status?.noc_turnover?.active_shift_key)} />
              <Info label="Open carried" value={String(status?.noc_turnover?.open_count ?? 0)} />
              <Info label="Next refresh" value={status?.noc_turnover?.next_refresh_ts ?? '-'} />
              <Info label="Channel" value={status?.config?.noc_turnover_channel_id || '-'} mono />
            </div>
            <button
              onClick={refreshTurnover}
              disabled={refreshing}
              className="mt-4 w-full rounded-md bg-accent px-3 py-2 text-xs font-medium text-bg hover:bg-accent-hover disabled:opacity-40"
            >
              {refreshing ? 'Refreshing...' : 'Run Resolve Check + Refresh'}
            </button>
          </section>

          <section className="stat-card">
            <h3 className="text-sm font-semibold text-text-bright">Closed Today</h3>
            <div className="mt-3 space-y-2">
              {closed.length === 0 ? (
                <div className="text-xs text-muted">No resolved escalations today.</div>
              ) : (
                closed.slice(0, 6).map((incident) => (
                  <a
                    key={incident.slack_ts}
                    href={incident.permalink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block rounded-md border border-border/70 bg-bg/60 px-3 py-2 hover:border-muted"
                  >
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="truncate text-text-bright">{incident.occir_key ?? 'No ticket'}</span>
                      <span className="text-green">{fmtDuration(incident.mttr_seconds)}</span>
                    </div>
                    <div className="mt-1 truncate text-[11px] text-muted">{cleanSlackText(incident.text_preview)}</div>
                  </a>
                ))
              )}
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}

function Metric({ label, value, tone = 'default' }: { label: string; value: string; tone?: 'default' | 'red' }) {
  return (
    <div className="stat-card">
      <div className="text-xs text-muted uppercase tracking-wider">{label}</div>
      <div className={`mt-1 text-2xl font-bold ${tone === 'red' ? 'text-red' : 'text-text-bright'}`}>{value}</div>
    </div>
  );
}

function Info({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="text-muted">{label}</span>
      <span className={`text-right text-text-bright ${mono ? 'font-mono' : ''}`}>{value}</span>
    </div>
  );
}

function IncidentRow({
  incident,
  ageSeconds,
  resolving,
  onResolve,
}: {
  incident: OngoingIncident;
  ageSeconds: number;
  resolving: boolean;
  onResolve: () => void;
}) {
  const title = cleanSlackText(incident.text_preview) || 'No alert title';
  return (
    <article className="grid gap-3 px-4 py-3 hover:bg-surface-hover md:grid-cols-[120px_1fr_auto]">
      <div className="flex items-center gap-2 text-xs">
        <span className="h-2.5 w-2.5 rounded-full bg-red" />
        <div>
          <div className="font-semibold text-text-bright tabular-nums">{fmtET(incident.posted_at)}</div>
          <div className="text-[11px] text-muted">{fmtDuration(ageSeconds)} old</div>
        </div>
      </div>
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          {incident.occir_key ? (
            <a
              href={`${JIRA}/browse/${incident.occir_key}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs font-semibold text-accent hover:underline"
            >
              {incident.occir_key}
            </a>
          ) : (
            <span className="rounded border border-orange/30 bg-orange/10 px-1.5 py-0.5 text-[10px] font-medium text-orange">
              no ticket
            </span>
          )}
          <span className="text-[11px] text-muted">{incident.reply_count} replies</span>
          <span className="text-[11px] text-muted">{incident.unique_responder_count} responders</span>
          {incident.claimed_by_user_id && (
            <span className="rounded border border-green/30 bg-green/10 px-1.5 py-0.5 text-[10px] font-medium text-green">
              owned
            </span>
          )}
        </div>
        <div className="mt-1 text-sm text-text-bright line-clamp-2">{title}</div>
      </div>
      <div className="flex items-center gap-2 md:justify-end">
        <a
          href={incident.permalink}
          target="_blank"
          rel="noopener noreferrer"
          className="rounded-md border border-border px-2.5 py-1 text-[11px] text-muted hover:text-text hover:bg-surface-hover"
        >
          Slack
        </a>
        <button
          onClick={onResolve}
          disabled={resolving}
          className="rounded-md border border-green/40 bg-green/10 px-2.5 py-1 text-[11px] font-medium text-green hover:bg-green/20 disabled:opacity-40"
        >
          {resolving ? '...' : 'Resolve'}
        </button>
      </div>
    </article>
  );
}
