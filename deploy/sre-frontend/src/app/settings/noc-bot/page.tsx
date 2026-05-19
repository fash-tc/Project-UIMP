'use client';

import { useState, useEffect, useCallback, useRef } from 'react';

interface BotConfig {
  enabled: boolean;
  escalation_enabled: boolean;
  cr_summary_enabled: boolean;
  ollama_model: string;
  ticket_reaction_enabled: boolean;
  ticket_any_channel: boolean;
  test_mode_enabled: boolean;
  test_channels: string[];
  test_mode_live_grafana: boolean;
  change_tracker_enabled: boolean;
  change_tracker_channel_id: string;
  noc_turnover_enabled: boolean;
  noc_turnover_channel_id: string;
  noc_turnover_ack_threshold_min: number;
}

interface BotStatus {
  ok: boolean;
  uptime_seconds: number;
  config: BotConfig;
  channel_id: string;
  group_ids: string[];
  dedup_cache_size: number;
  change_tracker?: {
    last_poll_ts: string | null;
    next_poll_ts: string | null;
    today_date: string;
    today_count: number;
  } | null;
  noc_turnover?: {
    last_refresh_ts: string | null;
    next_refresh_ts: string | null;
    active_shift_key: string | null;
    open_count: number;
  } | null;
}

interface ActivityEntry {
  ts: number;
  time: string;
  action: string;
  detail: string;
  user: string;
  cr_key: string;
  ticket_key: string;
}

interface LogEntry {
  ts: number;
  time: string;
  level: string;
  logger: string;
  message: string;
  traceback?: string;
}

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function actionBadge(action: string): { label: string; color: string } {
  switch (action) {
    case 'escalation':
      return { label: 'Escalation', color: 'bg-red/15 border-red/30 text-red' };
    case 'escalation_failed':
      return { label: 'Escalation Failed', color: 'bg-red/25 border-red/50 text-red' };
    case 'escalation_skipped':
      return { label: 'Skipped', color: 'bg-orange/15 border-orange/30 text-orange' };
    case 'cr_summary':
      return { label: 'CR Summary', color: 'bg-blue/15 border-blue/30 text-blue' };
    case 'test_escalation':
      return { label: 'Test Escalation', color: 'bg-yellow/15 border-yellow/30 text-yellow' };
    case 'ticket_created':
      return { label: 'Ticket', color: 'bg-green/15 border-green/30 text-green' };
    case 'ticket_failed':
      return { label: 'Ticket Failed', color: 'bg-red/20 border-red/40 text-red' };
    case 'config_change':
      return { label: 'Config', color: 'bg-accent/15 border-accent/30 text-accent' };
    default:
      return { label: action, color: 'bg-muted/15 border-muted/30 text-muted' };
  }
}

export default function NocBotPage() {
  const [status, setStatus] = useState<BotStatus | null>(null);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logLevel, setLogLevel] = useState('');
  const [expandedLog, setExpandedLog] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  const [newChannel, setNewChannel] = useState('');

  // Local config state for editing
  const [localConfig, setLocalConfig] = useState<BotConfig>({
    enabled: true,
    escalation_enabled: true,
    cr_summary_enabled: true,
    ollama_model: 'qwen-assistant',
    ticket_reaction_enabled: true,
    ticket_any_channel: false,
    test_mode_enabled: false,
    test_channels: [],
    test_mode_live_grafana: false,
    change_tracker_enabled: true,
    change_tracker_channel_id: '',
    noc_turnover_enabled: true,
    noc_turnover_channel_id: '',
    noc_turnover_ack_threshold_min: 15,
  });

  const fetchLogs = useCallback(async (level: string) => {
    try {
      const url = level ? `/api/noc-bot/logs?level=${level}` : '/api/noc-bot/logs';
      const res = await fetch(url);
      if (!res.ok) return;
      const data = await res.json();
      setLogs(data.entries || []);
    } catch { /* swallow — logs are best-effort */ }
  }, []);

  const configSeededRef = useRef(false);

  const fetchStatus = useCallback(async () => {
    try {
      const [statusRes, activityRes] = await Promise.all([
        fetch('/api/noc-bot/status'),
        fetch('/api/noc-bot/activity'),
      ]);
      if (!statusRes.ok) throw new Error(`Status ${statusRes.status}`);
      const statusData: BotStatus = await statusRes.json();
      const activityData = await activityRes.json();

      setStatus(statusData);
      // Only seed localConfig from server on first successful load, to avoid
      // clobbering in-progress user edits on every polling refresh.
      if (!configSeededRef.current) {
        setLocalConfig(statusData.config);
        configSeededRef.current = true;
      }
      setActivity(activityData.entries || []);
      setError('');
    } catch (e) {
      setError('Cannot reach NOC bot API. Bot may be down.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchLogs(logLevel);
    const interval = setInterval(() => {
      fetchStatus();
      fetchLogs(logLevel);
    }, 15000);
    return () => clearInterval(interval);
  }, [fetchStatus, fetchLogs, logLevel]);

  async function saveConfig(updates: Partial<BotConfig>) {
    setSaving(true);
    setSaveMsg(null);
    try {
      const res = await fetch('/api/noc-bot/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });
      if (!res.ok) throw new Error(`Status ${res.status}`);
      const updated = await res.json();
      setLocalConfig(updated);
      if (status) setStatus({ ...status, config: updated });
      setSaveMsg({ type: 'ok', text: 'Saved' });
      setTimeout(() => setSaveMsg(null), 2000);
    } catch {
      setSaveMsg({ type: 'err', text: 'Failed to save config' });
    } finally {
      setSaving(false);
    }
  }

  function handleToggle(key: keyof BotConfig) {
    const newVal = !localConfig[key];
    setLocalConfig({ ...localConfig, [key]: newVal });
    saveConfig({ [key]: newVal });
  }

  function handleModelSave() {
    saveConfig({ ollama_model: localConfig.ollama_model });
  }

  function addTestChannel() {
    const id = newChannel.trim();
    if (!id || localConfig.test_channels.includes(id)) return;
    const updated = [...localConfig.test_channels, id];
    setLocalConfig({ ...localConfig, test_channels: updated });
    setNewChannel('');
    saveConfig({ test_channels: updated });
  }

  function removeTestChannel(id: string) {
    const updated = localConfig.test_channels.filter((c) => c !== id);
    setLocalConfig({ ...localConfig, test_channels: updated });
    saveConfig({ test_channels: updated });
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="text-sm text-muted">Loading...</div>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-bright">NOC Escalation Bot</h1>
          <p className="text-xs text-muted mt-0.5">Controls for the #ops-noc escalation and CR summary bot</p>
        </div>
        {status && (
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${status.ok ? 'bg-green' : 'bg-red'}`} />
            <span className="text-xs text-muted">
              {status.ok ? `Up ${formatUptime(status.uptime_seconds)}` : 'Offline'}
            </span>
          </div>
        )}
      </div>

      {error && (
        <div className="rounded px-3 py-2 text-xs bg-red/10 border border-red/30 text-red">
          {error}
        </div>
      )}

      {saveMsg && (
        <div
          className={`rounded px-3 py-2 text-xs ${
            saveMsg.type === 'ok'
              ? 'bg-green/10 border border-green/30 text-green'
              : 'bg-red/10 border border-red/30 text-red'
          }`}
        >
          {saveMsg.text}
        </div>
      )}

      {/* Master Toggle */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-text-bright">Bot Enabled</h2>
            <p className="text-[11px] text-muted mt-0.5">
              Master kill switch. When off, the bot ignores all messages.
            </p>
          </div>
          <Toggle checked={localConfig.enabled} onChange={() => handleToggle('enabled')} disabled={saving} />
        </div>
      </div>

      {/* Feature Toggles */}
      <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
        <h2 className="text-sm font-semibold text-text-bright">Features</h2>

        <div className="flex items-center justify-between py-2 border-b border-border/50">
          <div>
            <div className="text-sm text-text-bright">IRM Escalation</div>
            <div className="text-[11px] text-muted">
              Page domains-sre via Grafana IRM when @noc/@domains-sre is mentioned by a non-member
            </div>
          </div>
          <Toggle
            checked={localConfig.escalation_enabled}
            onChange={() => handleToggle('escalation_enabled')}
            disabled={saving || !localConfig.enabled}
          />
        </div>

        <div className="flex items-center justify-between py-2">
          <div>
            <div className="text-sm text-text-bright">CR Summary</div>
            <div className="text-[11px] text-muted">
              Detect CR-XXXXX references and post a Jira summary thread reply
            </div>
          </div>
          <Toggle
            checked={localConfig.cr_summary_enabled}
            onChange={() => handleToggle('cr_summary_enabled')}
            disabled={saving || !localConfig.enabled}
          />
        </div>
      </div>

      {/* Model Config */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <h2 className="text-sm font-semibold text-text-bright mb-3">LLM Model</h2>
        <p className="text-[11px] text-muted mb-3">
          Ollama model used for CR summarization. Changes take effect on the next CR summary.
        </p>
        <div className="flex gap-2">
          <input
            type="text"
            value={localConfig.ollama_model}
            onChange={(e) => setLocalConfig({ ...localConfig, ollama_model: e.target.value })}
            className="flex-1 bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright focus:outline-none focus:border-accent/50"
            placeholder="qwen-assistant"
            disabled={!localConfig.enabled}
          />
          <button
            onClick={handleModelSave}
            disabled={saving || !localConfig.enabled}
            className="px-4 py-2 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent-hover disabled:opacity-40 transition-colors"
          >
            Save
          </button>
        </div>
      </div>

      {/* Ticket Reaction */}
      <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
        <h2 className="text-sm font-semibold text-text-bright">Ticket Reaction</h2>
        <p className="text-[11px] text-muted">
          When a member of @noc or @domains-sre reacts with{' '}
          <code className="bg-bg border border-border rounded px-1 font-mono">:ticket:</code>
          {' '}on a message, the bot creates an OCCIR Jira incident ticket and posts the link in the thread.
        </p>

        <div className="flex items-center justify-between py-2 border-b border-border/50">
          <div>
            <div className="text-sm text-text-bright">Ticket Reaction Enabled</div>
            <div className="text-[11px] text-muted">
              Master switch for :ticket: → OCCIR ticket creation
            </div>
          </div>
          <Toggle
            checked={localConfig.ticket_reaction_enabled}
            onChange={() => handleToggle('ticket_reaction_enabled')}
            disabled={saving || !localConfig.enabled}
          />
        </div>

        <div className="flex items-center justify-between py-2">
          <div>
            <div className="text-sm text-text-bright">Any Channel</div>
            <div className="text-[11px] text-muted">
              When enabled, works in any channel the bot is in (not just #ops-noc)
            </div>
          </div>
          <Toggle
            checked={localConfig.ticket_any_channel}
            onChange={() => handleToggle('ticket_any_channel')}
            disabled={saving || !localConfig.enabled || !localConfig.ticket_reaction_enabled}
          />
        </div>
      </div>

      {/* Change Tracker */}
      <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-text-bright">Change Tracker</h2>
          <p className="text-[11px] text-muted mt-0.5">
            Scans Jira CR project every 5 hours and posts a daily summary to a Slack channel.
          </p>
        </div>

        <div className="flex items-center justify-between py-2 border-b border-border/50">
          <div>
            <div className="text-sm text-text-bright">Enabled</div>
          </div>
          <Toggle
            checked={localConfig.change_tracker_enabled}
            onChange={() => handleToggle('change_tracker_enabled')}
            disabled={saving || !localConfig.enabled}
          />
        </div>

        <div className="space-y-2">
          <div className="text-sm text-text-bright">Slack channel ID</div>
          <div className="flex gap-2">
            <input
              type="text"
              value={localConfig.change_tracker_channel_id}
              onChange={(e) => setLocalConfig({ ...localConfig, change_tracker_channel_id: e.target.value })}
              className="flex-1 bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright font-mono focus:outline-none focus:border-accent/50"
              placeholder="C0AT76PKANB"
              disabled={!localConfig.enabled}
            />
            <button
              onClick={() => saveConfig({ change_tracker_channel_id: localConfig.change_tracker_channel_id })}
              disabled={saving || !localConfig.enabled}
              className="px-4 py-2 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent-hover disabled:opacity-40 transition-colors"
            >
              Save
            </button>
          </div>
        </div>

        {status?.change_tracker && (
          <div className="text-[11px] text-muted space-y-0.5 pt-2 border-t border-border/50">
            <div>Last poll: {status.change_tracker.last_poll_ts ?? '—'}</div>
            <div>Next poll: {status.change_tracker.next_poll_ts ?? '—'}</div>
            <div>
              Today&apos;s post: {status.change_tracker.today_date || '—'} ({status.change_tracker.today_count ?? 0} CRs)
            </div>
          </div>
        )}
      </div>

      {/* NOC Turnover */}
      <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-text-bright">NOC Turnover</h2>
          <p className="text-[11px] text-muted mt-0.5">
            Tracks open escalation threads and posts a shift-handoff summary to a Slack channel.
          </p>
        </div>

        <div className="flex items-center justify-between py-2 border-b border-border/50">
          <div>
            <div className="text-sm text-text-bright">Enabled</div>
          </div>
          <Toggle
            checked={localConfig.noc_turnover_enabled}
            onChange={() => handleToggle('noc_turnover_enabled')}
            disabled={saving || !localConfig.enabled}
          />
        </div>

        <div className="space-y-2">
          <div className="text-sm text-text-bright">Slack channel ID</div>
          <div className="flex gap-2">
            <input
              type="text"
              value={localConfig.noc_turnover_channel_id}
              onChange={(e) => setLocalConfig({ ...localConfig, noc_turnover_channel_id: e.target.value })}
              className="flex-1 bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright font-mono focus:outline-none focus:border-accent/50"
              placeholder="C0477H3BFHD"
              disabled={!localConfig.enabled}
            />
            <button
              onClick={() => saveConfig({ noc_turnover_channel_id: localConfig.noc_turnover_channel_id })}
              disabled={saving || !localConfig.enabled}
              className="px-4 py-2 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent-hover disabled:opacity-40 transition-colors"
            >
              Save
            </button>
          </div>
        </div>

        <div className="space-y-2">
          <div className="text-sm text-text-bright">Ack threshold (minutes)</div>
          <div className="flex gap-2">
            <input
              type="number"
              min={1}
              max={120}
              value={localConfig.noc_turnover_ack_threshold_min}
              onChange={(e) =>
                setLocalConfig({ ...localConfig, noc_turnover_ack_threshold_min: Number(e.target.value) })
              }
              className="w-28 bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright focus:outline-none focus:border-accent/50"
              placeholder="15"
              disabled={!localConfig.enabled}
            />
            <button
              onClick={() =>
                saveConfig({ noc_turnover_ack_threshold_min: localConfig.noc_turnover_ack_threshold_min })
              }
              disabled={saving || !localConfig.enabled}
              className="px-4 py-2 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent-hover disabled:opacity-40 transition-colors"
            >
              Save
            </button>
          </div>
          <div className="text-[11px] text-muted">
            Escalations without a reply within this window are flagged as unacknowledged.
          </div>
        </div>

        {status?.noc_turnover && (
          <div className="text-[11px] text-muted space-y-0.5 pt-2 border-t border-border/50">
            <div>Last refresh: {status.noc_turnover.last_refresh_ts ?? '—'}</div>
            <div>Next refresh: {status.noc_turnover.next_refresh_ts ?? '—'}</div>
            <div>Active shift: {status.noc_turnover.active_shift_key ?? '—'}</div>
            <div>Open escalations: {status.noc_turnover.open_count ?? 0}</div>
          </div>
        )}
      </div>

      {/* Test Mode */}
      <div className="bg-surface border border-border rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-text-bright">Test Mode</h2>
            <p className="text-[11px] text-muted mt-0.5">
              Process messages in test channels with sender exclusion bypassed and IRM escalation replaced by a dry-run reply.
            </p>
          </div>
          <Toggle
            checked={localConfig.test_mode_enabled}
            onChange={() => handleToggle('test_mode_enabled')}
            disabled={saving || !localConfig.enabled}
          />
        </div>

        {localConfig.test_mode_enabled && (
          <div className="pt-2 border-t border-border/50 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-border/50">
              <div>
                <div className="text-xs font-medium text-text-bright">Fire real Grafana page from test channels</div>
                <p className="text-[11px] text-muted mt-0.5">
                  When on, test-channel mentions trigger a real IRM escalation (thread reply marked [TEST CHANNEL]). Use sparingly — this pages the real on-call.
                </p>
              </div>
              <Toggle
                checked={localConfig.test_mode_live_grafana}
                onChange={() => handleToggle('test_mode_live_grafana')}
                disabled={saving || !localConfig.enabled || !localConfig.test_mode_enabled}
              />
            </div>
            <div className="text-[11px] text-muted">
              Add Slack channel IDs where the bot should listen in test mode.
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={newChannel}
                onChange={(e) => setNewChannel(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addTestChannel()}
                className="flex-1 bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright font-mono focus:outline-none focus:border-accent/50"
                placeholder="C0ATG4P87QA"
                disabled={saving}
              />
              <button
                onClick={addTestChannel}
                disabled={saving || !newChannel.trim()}
                className="px-4 py-2 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent-hover disabled:opacity-40 transition-colors"
              >
                Add
              </button>
            </div>
            {localConfig.test_channels.length === 0 ? (
              <div className="text-[11px] text-muted py-2">No test channels configured</div>
            ) : (
              <div className="space-y-1.5">
                {localConfig.test_channels.map((ch) => (
                  <div key={ch} className="flex items-center justify-between bg-bg rounded-md px-3 py-2 border border-border/50">
                    <span className="text-sm text-text-bright font-mono">{ch}</span>
                    <button
                      onClick={() => removeTestChannel(ch)}
                      disabled={saving}
                      className="text-[10px] text-red hover:text-red/80 disabled:opacity-40 transition-colors"
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Bot Info */}
      {status && (
        <div className="bg-surface border border-border rounded-lg p-5">
          <h2 className="text-sm font-semibold text-text-bright mb-3">Info</h2>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-muted">Channel ID</span>
              <div className="text-text-bright font-mono mt-0.5">{status.channel_id}</div>
            </div>
            <div>
              <span className="text-muted">Watched Groups</span>
              <div className="text-text-bright font-mono mt-0.5">{status.group_ids.length} group{status.group_ids.length !== 1 ? 's' : ''}</div>
            </div>
            <div>
              <span className="text-muted">Dedup Cache</span>
              <div className="text-text-bright font-mono mt-0.5">{status.dedup_cache_size} messages</div>
            </div>
            <div>
              <span className="text-muted">Uptime</span>
              <div className="text-text-bright font-mono mt-0.5">{formatUptime(status.uptime_seconds)}</div>
            </div>
          </div>
        </div>
      )}

      {/* Activity Log */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-text-bright">Activity Log</h2>
          <button
            onClick={fetchStatus}
            className="text-[10px] text-muted hover:text-text-bright transition-colors"
          >
            Refresh
          </button>
        </div>

        {activity.length === 0 ? (
          <div className="text-xs text-muted py-4 text-center">No activity yet</div>
        ) : (
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {activity.map((entry, i) => {
              const badge = actionBadge(entry.action);
              return (
                <div key={`${entry.ts}-${i}`} className="flex items-start gap-3 py-2 border-b border-border/30 last:border-0">
                  <span className={`badge text-[10px] mt-0.5 shrink-0 ${badge.color}`}>
                    {badge.label}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs text-text-bright truncate">{entry.detail}</div>
                    <div className="text-[10px] text-muted mt-0.5">
                      {entry.time}
                      {entry.user && <span> &middot; {entry.user}</span>}
                      {entry.cr_key && <span> &middot; {entry.cr_key}</span>}
                      {entry.ticket_key && <span> &middot; {entry.ticket_key}</span>}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Logs */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-text-bright">Logs</h2>
          <div className="flex items-center gap-2">
            {(['', 'ERROR', 'WARNING', 'INFO'] as const).map((lvl) => (
              <button
                key={lvl || 'ALL'}
                onClick={() => { setLogLevel(lvl); setExpandedLog(null); }}
                className={`text-[10px] px-2 py-0.5 rounded border transition-colors ${
                  logLevel === lvl
                    ? 'bg-accent/20 border-accent/50 text-accent'
                    : 'border-border text-muted hover:text-text-bright hover:border-muted'
                }`}
              >
                {lvl || 'ALL'}
              </button>
            ))}
            <button
              onClick={() => fetchLogs(logLevel)}
              className="text-[10px] text-muted hover:text-text-bright transition-colors ml-1"
            >
              Refresh
            </button>
          </div>
        </div>

        {logs.length === 0 ? (
          <div className="text-xs text-muted py-4 text-center">No log entries</div>
        ) : (
          <div className="space-y-0.5 max-h-96 overflow-y-auto font-mono">
            {logs.map((entry, i) => {
              const levelColor =
                entry.level === 'ERROR' || entry.level === 'CRITICAL'
                  ? 'text-red'
                  : entry.level === 'WARNING'
                  ? 'text-orange'
                  : entry.level === 'INFO'
                  ? 'text-blue'
                  : 'text-muted';
              const isExpanded = expandedLog === i;
              const hasTraceback = !!entry.traceback;
              return (
                <div
                  key={`${entry.ts}-${i}`}
                  className={`rounded px-2 py-1 text-[11px] ${hasTraceback ? 'cursor-pointer hover:bg-surface-hover' : ''} ${isExpanded ? 'bg-surface-hover' : ''}`}
                  onClick={() => hasTraceback && setExpandedLog(isExpanded ? null : i)}
                >
                  <div className="flex items-start gap-2">
                    <span className="text-muted shrink-0 tabular-nums">{entry.time}</span>
                    <span className={`font-semibold shrink-0 w-14 ${levelColor}`}>{entry.level}</span>
                    <span className="text-muted/70 shrink-0 hidden sm:block truncate max-w-[120px]">{entry.logger}</span>
                    <span className="text-text-bright flex-1 break-words">{entry.message}</span>
                    {hasTraceback && (
                      <span className="text-muted shrink-0">{isExpanded ? '▲' : '▼'}</span>
                    )}
                  </div>
                  {isExpanded && entry.traceback && (
                    <pre className="mt-2 text-[10px] text-red/80 whitespace-pre-wrap break-words bg-bg rounded p-2 border border-red/20">
                      {entry.traceback}
                    </pre>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function Toggle({ checked, onChange, disabled }: { checked: boolean; onChange: () => void; disabled?: boolean }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      onClick={onChange}
      disabled={disabled}
      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed ${
        checked ? 'bg-accent' : 'bg-border'
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition-transform duration-200 ease-in-out ${
          checked ? 'translate-x-5' : 'translate-x-0'
        }`}
      />
    </button>
  );
}
