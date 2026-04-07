'use client';

import { useEffect, useState } from 'react';
import {
  WebhookSubscriber,
  WebhookDelivery,
} from '@/lib/types';
import {
  clearMaintenanceAuthToken,
  bootstrapSharedMaintenanceAuth,
  fetchWebhookSubscribers,
  createWebhookSubscriber,
  updateWebhookSubscriber,
  deleteWebhookSubscriber,
  rotateWebhookSecret,
  testWebhookDelivery,
  sendIncidentWebhookPreview,
  fetchWebhookDeliveries,
  fetchWebhookTestDeliveries,
  clearWebhookTestDeliveries,
  hasMaintenanceAuthToken,
  loginMaintenanceAuth,
  persistWebhookSubscriberSecret,
  WebhookTestDelivery,
} from '@/lib/keep-api';
import { useAuth } from '@/lib/auth';

type Tab = 'subscribers' | 'deliveries' | 'settings' | 'preview';

function isBuiltInLocalTestSubscriber(sub: Pick<WebhookSubscriber, 'name' | 'url' | 'is_active'>) {
  if (sub.name !== 'Local Test') return false;
  try {
    const parsed = new URL(sub.url);
    return parsed.pathname === '/api/webhooks/receive-test';
  } catch {
    return sub.url.includes('/api/webhooks/receive-test');
  }
}

function inferCapturedDeliveryType(capture: WebhookTestDelivery | null | undefined) {
  if (!capture) return 'delivery';
  if (capture.body?.incident) return 'incident';
  if (Array.isArray(capture.body?.notices) && capture.body.notices.some((notice: any) => notice?.event_type === 'incident')) {
    return 'incident';
  }
  return capture.body?.event_type || 'maintenance';
}

function parseWebhookTimestamp(value: string) {
  const text = (value || '').trim();
  if (!text) return new Date(0);
  const normalized = /(?:Z|[+-]\d{2}:\d{2})$/.test(text) ? text : `${text}Z`;
  const parsed = new Date(normalized);
  if (!Number.isNaN(parsed.getTime())) return parsed;
  return new Date(text);
}

function hasNearbyDelivery(deliveries: WebhookDelivery[], capture: WebhookTestDelivery, subscriberId: number) {
  const captureTs = parseWebhookTimestamp(capture.timestamp).getTime();
  return deliveries.some((delivery) => {
    if (delivery.subscriber_id !== subscriberId) return false;
    return Math.abs(parseWebhookTimestamp(delivery.timestamp).getTime() - captureTs) < 10000;
  });
}

export default function WebhooksPage() {
  const [tab, setTab] = useState<Tab>('subscribers');

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-text">Webhook Management</h1>
      </div>

      <MaintenanceAuthCard />

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-border">
        {([
          ['subscribers', 'Subscribers'],
          ['deliveries', 'Delivery Log'],
          ['settings', 'Settings'],
          ['preview', 'Customer Preview'],
        ] as [Tab, string][]).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === key
                ? 'border-accent text-accent'
                : 'border-transparent text-muted hover:text-text'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'subscribers' && <SubscribersTab />}
      {tab === 'deliveries' && <DeliveriesTab />}
      {tab === 'settings' && <SettingsTab />}
      {tab === 'preview' && <CustomerPreviewTab />}
    </div>
  );
}

function MaintenanceAuthCard() {
  const { user, loading: authLoading } = useAuth();
  const [connected, setConnected] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const eligibleForSharedBootstrap = user?.role?.name === 'Admin' || user?.role?.name === 'SRE';

  useEffect(() => {
    if (authLoading) return;
    if (hasMaintenanceAuthToken()) {
      setConnected(true);
      return;
    }
    if (!eligibleForSharedBootstrap) {
      setConnected(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    bootstrapSharedMaintenanceAuth()
      .then((result) => {
        if (cancelled) return;
        if (result.ok) {
          setConnected(true);
          setError('');
        } else {
          setConnected(false);
          setError(result.error || 'Shared maintenance auth is not configured.');
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [authLoading, eligibleForSharedBootstrap]);

  async function handleLogin() {
    setLoading(true);
    setError('');
    const result = await loginMaintenanceAuth(username, password);
    if (!result.ok) {
      setError(result.error || 'Failed to sign in to Maintenance API');
      setConnected(false);
    } else {
      setConnected(true);
      setPassword('');
    }
    setLoading(false);
  }

  function handleDisconnect() {
    clearMaintenanceAuthToken();
    setConnected(false);
    setPassword('');
    setError('');
  }

  return (
    <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-text">Maintenance Auth</h2>
          <p className="text-xs text-muted mt-1">
            Admin and SRE users auto-connect using the shared maintenance credential. Other roles sign in
            here per session to enable protected maintenance actions.
          </p>
        </div>
        <div className={`text-xs font-medium ${connected ? 'text-green' : 'text-yellow'}`}>
          {connected ? 'Connected' : 'Not Connected'}
        </div>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">
          {error}
        </div>
      )}

      {connected ? (
        <div className="flex items-center justify-between gap-3">
          <div className="text-xs text-muted">
            Maintenance token is stored in this browser session only.
          </div>
          <button
            onClick={handleDisconnect}
            className="px-3 py-1.5 rounded border border-border text-xs text-text hover:bg-surface-hover transition-colors"
          >
            Forget Token
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-[1fr_1fr_auto] gap-3">
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text focus:outline-none focus:border-accent"
            placeholder="Maintenance username"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text focus:outline-none focus:border-accent"
            placeholder="Maintenance password"
          />
          <button
            onClick={handleLogin}
            disabled={loading || !username.trim() || !password}
            className="px-4 py-2 rounded bg-accent/20 border border-accent/40 text-sm font-medium text-accent hover:bg-accent/30 disabled:opacity-50 transition-colors"
          >
            {loading ? 'Signing In...' : 'Sign In'}
          </button>
        </div>
      )}
    </div>
  );
}

/* ─── Subscribers Tab ─────────────────────────────── */

function SubscribersTab() {
  const [subscribers, setSubscribers] = useState<WebhookSubscriber[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Add form
  const [showAdd, setShowAdd] = useState(false);
  const [addName, setAddName] = useState('');
  const [addUrl, setAddUrl] = useState('');
  const [adding, setAdding] = useState(false);
  const [newSecret, setNewSecret] = useState<string | null>(null);

  // Edit modal
  const [editing, setEditing] = useState<WebhookSubscriber | null>(null);
  const [editName, setEditName] = useState('');
  const [editUrl, setEditUrl] = useState('');
  const [saving, setSaving] = useState(false);

  // Rotated secret display
  const [rotatedSecret, setRotatedSecret] = useState<{ id: number; secret: string } | null>(null);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const subs = await fetchWebhookSubscribers();
      setSubscribers(subs.filter(sub => sub.is_active));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load subscribers');
    }
    setLoading(false);
  }

  useEffect(() => { load(); }, []);

  async function handleAdd() {
    setAdding(true);
    const { subscriber, error: err } = await createWebhookSubscriber(addName, addUrl);
    if (err) {
      setError(err);
    } else if (subscriber) {
      if (subscriber.secret) {
        const persistResult = await persistWebhookSubscriberSecret(subscriber.id, subscriber.name, subscriber.url, subscriber.secret);
        if (!persistResult.ok) {
          setError(persistResult.error || 'Failed to store webhook signing secret');
        }
      }
      setNewSecret(subscriber.secret || null);
      setAddName('');
      setAddUrl('');
      setShowAdd(false);
      await load();
    }
    setAdding(false);
  }

  async function handleToggle(sub: WebhookSubscriber) {
    await updateWebhookSubscriber(sub.id, { is_active: !sub.is_active });
    await load();
  }

  async function handleDelete(sub: WebhookSubscriber) {
    const builtIn = isBuiltInLocalTestSubscriber(sub);
    const confirmMessage = builtIn
      ? `Hide built-in subscriber "${sub.name}"? The upstream maintenance service does not delete this receiver cleanly.`
      : `Remove subscriber "${sub.name}"? If hard delete is unavailable upstream, UIP will archive it instead.`;
    if (!confirm(confirmMessage)) return;

    if (!builtIn) {
      const { ok, error: err } = await deleteWebhookSubscriber(sub.id);
      if (ok && !err) {
        await load();
        return;
      }
      if (err && !/internal server error|http 500/i.test(err)) {
        setError(err);
        return;
      }
    }

    const { ok, error: err } = await updateWebhookSubscriber(sub.id, { is_active: false });
    if (!ok || err) {
      setError(err || 'Failed to archive subscriber');
      return;
    }
    await load();
  }

  async function handleRotate(sub: WebhookSubscriber) {
    if (!confirm(`Rotate secret for "${sub.name}"? The old secret will stop working immediately.`)) return;
    const { secret, error: err } = await rotateWebhookSecret(sub.id);
    if (err) setError(err);
    else if (secret) {
      const persistResult = await persistWebhookSubscriberSecret(sub.id, sub.name, sub.url, secret);
      if (!persistResult.ok) {
        setError(persistResult.error || 'Failed to store webhook signing secret');
        return;
      }
      setRotatedSecret({ id: sub.id, secret });
    }
  }

  async function handleTest(sub: WebhookSubscriber) {
    const { ok, error: err } = await testWebhookDelivery(sub.id);
    if (err) setError(err);
    else if (ok) alert(`Test delivery sent to "${sub.name}"`);
  }

  async function handleSaveEdit() {
    if (!editing) return;
    setSaving(true);
    const { error: err } = await updateWebhookSubscriber(editing.id, { name: editName, url: editUrl });
    if (err) setError(err);
    else {
      setEditing(null);
      await load();
    }
    setSaving(false);
  }

  function openEdit(sub: WebhookSubscriber) {
    setEditing(sub);
    setEditName(sub.name);
    setEditUrl(sub.url);
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red flex items-center justify-between">
          {error}
          <button onClick={() => setError('')} className="text-red/60 hover:text-red ml-2">dismiss</button>
        </div>
      )}

      {/* Secret display banners */}
      {newSecret && (
        <div className="bg-yellow/10 border border-yellow/30 rounded px-4 py-3 space-y-1">
          <div className="text-xs font-semibold text-yellow">New Subscriber Secret (shown once):</div>
          <code className="block text-sm font-mono text-text bg-bg px-3 py-2 rounded border border-border select-all break-all">
            {newSecret}
          </code>
          <button onClick={() => setNewSecret(null)} className="text-xs text-muted hover:text-text mt-1">Dismiss</button>
        </div>
      )}

      {rotatedSecret && (
        <div className="bg-yellow/10 border border-yellow/30 rounded px-4 py-3 space-y-1">
          <div className="text-xs font-semibold text-yellow">Rotated Secret (shown once):</div>
          <code className="block text-sm font-mono text-text bg-bg px-3 py-2 rounded border border-border select-all break-all">
            {rotatedSecret.secret}
          </code>
          <button onClick={() => setRotatedSecret(null)} className="text-xs text-muted hover:text-text mt-1">Dismiss</button>
        </div>
      )}

      {/* Add button / form */}
      {!showAdd ? (
        <button
          onClick={() => setShowAdd(true)}
          className="px-4 py-1.5 rounded bg-accent/20 border border-accent/40 text-xs font-medium text-accent hover:bg-accent/30 transition-colors"
        >
          + Add Subscriber
        </button>
      ) : (
        <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
          <h3 className="text-sm font-semibold text-text">New Subscriber</h3>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-muted mb-1">Name</label>
              <input
                type="text"
                value={addName}
                onChange={e => setAddName(e.target.value)}
                className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
                placeholder="e.g. PagerDuty"
              />
            </div>
            <div>
              <label className="block text-xs text-muted mb-1">Webhook URL</label>
              <input
                type="text"
                value={addUrl}
                onChange={e => setAddUrl(e.target.value)}
                className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
                placeholder="https://..."
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleAdd}
              disabled={adding || !addName.trim() || !addUrl.trim()}
              className="px-4 py-1.5 rounded bg-accent/20 border border-accent/40 text-xs font-medium text-accent hover:bg-accent/30 disabled:opacity-50 transition-colors"
            >
              {adding ? 'Creating...' : 'Create'}
            </button>
            <button
              onClick={() => setShowAdd(false)}
              className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Subscribers table */}
      {loading ? (
        <div className="text-sm text-muted animate-pulse">Loading subscribers...</div>
      ) : subscribers.length === 0 ? (
        <div className="text-sm text-muted">No subscribers configured.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs text-muted">
                <th className="text-left py-2 px-3 font-medium">Name</th>
                <th className="text-left py-2 px-3 font-medium">URL</th>
                <th className="text-left py-2 px-3 font-medium">Status</th>
                <th className="text-left py-2 px-3 font-medium">Created</th>
                <th className="text-right py-2 px-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {subscribers.map(sub => (
                <tr key={sub.id} className="border-b border-border/50 hover:bg-surface-hover/50">
                  <td className="py-2.5 px-3 font-medium text-text">{sub.name}</td>
                  <td className="py-2.5 px-3 text-muted font-mono text-xs max-w-[300px] truncate">{sub.url}</td>
                  <td className="py-2.5 px-3">
                    <button
                      onClick={() => handleToggle(sub)}
                      className={`px-2 py-0.5 rounded text-xs font-medium ${
                        sub.is_active
                          ? 'bg-green/10 text-green border border-green/30'
                          : 'bg-red/10 text-red border border-red/30'
                      }`}
                    >
                      {sub.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td className="py-2.5 px-3 text-xs text-muted">
                    {new Date(sub.created_at).toLocaleDateString()}
                  </td>
                  <td className="py-2.5 px-3">
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => openEdit(sub)}
                        className="px-2 py-1 rounded text-xs text-muted hover:text-text hover:bg-surface-hover transition-colors"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleTest(sub)}
                        className="px-2 py-1 rounded text-xs text-accent hover:bg-accent/10 transition-colors"
                      >
                        Test
                      </button>
                      <button
                        onClick={() => handleRotate(sub)}
                        className="px-2 py-1 rounded text-xs text-yellow hover:bg-yellow/10 transition-colors"
                      >
                        Rotate Secret
                      </button>
                      <button
                        onClick={() => handleDelete(sub)}
                        className="px-2 py-1 rounded text-xs text-red hover:bg-red/10 transition-colors"
                      >
                        {isBuiltInLocalTestSubscriber(sub) ? 'Hide' : 'Delete'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Edit modal */}
      {editing && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setEditing(null)}>
          <div className="bg-surface border border-border rounded-lg p-6 w-full max-w-md space-y-4" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-text">Edit Subscriber</h3>
            <div>
              <label className="block text-xs text-muted mb-1">Name</label>
              <input
                type="text"
                value={editName}
                onChange={e => setEditName(e.target.value)}
                className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
              />
            </div>
            <div>
              <label className="block text-xs text-muted mb-1">URL</label>
              <input
                type="text"
                value={editUrl}
                onChange={e => setEditUrl(e.target.value)}
                className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
              />
            </div>
            <div className="flex items-center gap-2 justify-end">
              <button
                onClick={() => setEditing(null)}
                className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEdit}
                disabled={saving || !editName.trim() || !editUrl.trim()}
                className="px-4 py-1.5 rounded bg-accent/20 border border-accent/40 text-xs font-medium text-accent hover:bg-accent/30 disabled:opacity-50 transition-colors"
              >
                {saving ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Deliveries Tab ──────────────────────────────── */

function DeliveriesTab() {
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedDelivery, setSelectedDelivery] = useState<WebhookDelivery | null>(null);
  const [testCaptures, setTestCaptures] = useState<WebhookTestDelivery[]>([]);

  // Filters
  const [filterSuccess, setFilterSuccess] = useState<boolean | undefined>(undefined);
  const [filterSubscriber, setFilterSubscriber] = useState<number | undefined>(undefined);
  const [subscribers, setSubscribers] = useState<WebhookSubscriber[]>([]);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const [data, captures] = await Promise.all([
        fetchWebhookDeliveries(filterSubscriber, filterSuccess),
        fetchWebhookTestDeliveries(),
      ]);
      setDeliveries(data);
      setTestCaptures(captures);
      setSelectedDelivery((current) => {
        if (!current) return null;
        return data.find(d => d.id === current.id) || null;
      });
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load deliveries');
    }
    setLoading(false);
  }

  useEffect(() => {
    fetchWebhookSubscribers().then(setSubscribers).catch(() => {});
  }, []);

  useEffect(() => { load(); }, [filterSuccess, filterSubscriber]);

  const subscriberNames = new Map(subscribers.map(s => [s.id, s.name]));
  const previewSubscriberIds = new Set(
    subscribers.filter(s => s.url?.includes('webhook-test/receive')).map(s => s.id),
  );
  const previewSubscriberId = subscribers.find(s => s.url?.includes('webhook-test/receive'))?.id;

  function getSubscriberName(delivery: WebhookDelivery) {
    return delivery.subscriber_name || subscriberNames.get(delivery.subscriber_id) || `#${delivery.subscriber_id}`;
  }

  function findMatchingCapture(delivery: WebhookDelivery | null) {
    if (!delivery || !previewSubscriberIds.has(delivery.subscriber_id)) return null;
    const deliveryTs = parseWebhookTimestamp(delivery.timestamp).getTime();
    let bestMatch: WebhookTestDelivery | null = null;
    let bestDelta = Number.POSITIVE_INFINITY;
    for (const capture of testCaptures) {
      const captureTs = parseWebhookTimestamp(capture.timestamp).getTime();
      const delta = Math.abs(captureTs - deliveryTs);
      if (delta < 10000 && delta < bestDelta) {
        bestMatch = capture;
        bestDelta = delta;
      }
    }
    return bestMatch;
  }

  function getDisplayDeliveryType(delivery: WebhookDelivery, capture?: WebhookTestDelivery | null) {
    const capturedType = inferCapturedDeliveryType(capture);
    if (capturedType !== 'maintenance' && capturedType !== 'delivery') return capturedType;
    return delivery.event_type || capturedType;
  }

  const matchingCapture = findMatchingCapture(selectedDelivery);
  const syntheticPreviewDeliveries: WebhookDelivery[] = previewSubscriberId
    ? testCaptures
        .filter((capture) => !hasNearbyDelivery(deliveries, capture, previewSubscriberId))
        .filter((capture) => filterSuccess !== false)
        .filter((capture) => filterSubscriber === undefined || filterSubscriber === previewSubscriberId)
        .map((capture) => ({
          id: -capture.id,
          subscriber_id: previewSubscriberId,
          subscriber_name: subscriberNames.get(previewSubscriberId) || 'Test Receiver (Customer Preview)',
          timestamp: capture.timestamp,
          http_status: 200,
          attempts: 1,
          success: true,
          is_test: true,
          event_type: inferCapturedDeliveryType(capture),
          error_message: null,
          payload_hash: '',
        }))
    : [];
  const displayedDeliveries = [...syntheticPreviewDeliveries, ...deliveries]
    .sort((a, b) => parseWebhookTimestamp(b.timestamp).getTime() - parseWebhookTimestamp(a.timestamp).getTime());

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">
          {error}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div>
          <label className="block text-xs text-muted mb-1">Subscriber</label>
          <select
            value={filterSubscriber ?? ''}
            onChange={e => setFilterSubscriber(e.target.value ? Number(e.target.value) : undefined)}
            className="bg-bg border border-border rounded px-3 py-1.5 text-sm text-text"
          >
            <option value="">All</option>
            {subscribers.map(s => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-muted mb-1">Status</label>
          <select
            value={filterSuccess === undefined ? '' : filterSuccess ? 'true' : 'false'}
            onChange={e => setFilterSuccess(e.target.value === '' ? undefined : e.target.value === 'true')}
            className="bg-bg border border-border rounded px-3 py-1.5 text-sm text-text"
          >
            <option value="">All</option>
            <option value="true">Success</option>
            <option value="false">Failed</option>
          </select>
        </div>
        <div className="flex items-end">
          <button
            onClick={load}
            className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors mt-4"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Deliveries table */}
      {loading ? (
        <div className="text-sm text-muted animate-pulse">Loading deliveries...</div>
      ) : displayedDeliveries.length === 0 ? (
        <div className="text-sm text-muted">No deliveries found.</div>
      ) : (
        <div className="space-y-4">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-muted">
                  <th className="text-left py-2 px-3 font-medium">Subscriber</th>
                  <th className="text-left py-2 px-3 font-medium">Timestamp</th>
                  <th className="text-left py-2 px-3 font-medium">HTTP Status</th>
                  <th className="text-left py-2 px-3 font-medium">Attempts</th>
                  <th className="text-left py-2 px-3 font-medium">Result</th>
                  <th className="text-left py-2 px-3 font-medium">Type</th>
                  <th className="text-left py-2 px-3 font-medium">Details</th>
                </tr>
              </thead>
              <tbody>
                {displayedDeliveries.map(d => {
                  const rowCapture = findMatchingCapture(d);
                  const displayType = getDisplayDeliveryType(d, rowCapture);
                  return (
                    <tr
                      key={d.id}
                      onClick={() => setSelectedDelivery(d)}
                      className={`border-b border-border/50 cursor-pointer transition-colors ${
                        selectedDelivery?.id === d.id ? 'bg-accent/5' : 'hover:bg-surface-hover/50'
                      }`}
                    >
                      <td className="py-2.5 px-3 text-text">{getSubscriberName(d)}</td>
                      <td className="py-2.5 px-3 text-xs text-muted font-mono">
                        {parseWebhookTimestamp(d.timestamp).toLocaleString()}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-xs">
                        <span className={d.http_status && d.http_status < 400 ? 'text-green' : 'text-red'}>
                          {d.http_status ?? '—'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-xs text-muted">{d.attempts}</td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          d.success
                            ? 'bg-green/10 text-green border border-green/30'
                            : 'bg-red/10 text-red border border-red/30'
                        }`}>
                          {d.success ? 'OK' : 'Failed'}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                          d.is_test
                            ? 'bg-accent/10 text-accent border border-accent/30'
                            : 'bg-surface-hover text-muted border border-border'
                        }`}>
                          {(displayType || 'delivery').toUpperCase()}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 max-w-[420px]">
                        <div className={`text-xs break-words ${d.error_message ? 'text-red' : 'text-text'}`}>
                          {d.error_message || (d.http_status ? `HTTP ${d.http_status}` : 'Delivered')}
                        </div>
                        {d.payload_hash && (
                          <div className="text-[10px] text-muted font-mono truncate mt-1">
                            Payload: {d.payload_hash}
                          </div>
                        )}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedDelivery(d);
                          }}
                          className="mt-2 text-[11px] font-medium text-accent hover:text-accent/80 transition-colors"
                        >
                          View details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {selectedDelivery && (
            <div
              className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4"
              onClick={() => setSelectedDelivery(null)}
            >
              <div
                className="w-full max-w-4xl max-h-[85vh] overflow-y-auto bg-surface border border-border rounded-xl p-5 space-y-4 shadow-2xl"
                onClick={(e) => e.stopPropagation()}
              >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-text">Delivery #{selectedDelivery.id}</h3>
                  <p className="text-xs text-muted mt-1">
                    {getSubscriberName(selectedDelivery)} · {parseWebhookTimestamp(selectedDelivery.timestamp).toLocaleString()}
                  </p>
                </div>
                <button
                  onClick={() => setSelectedDelivery(null)}
                  className="text-xs text-muted hover:text-text transition-colors"
                >
                  Close
                </button>
              </div>

              <div className="grid gap-3 md:grid-cols-4">
                <div className="bg-bg border border-border rounded p-3">
                  <div className="text-[10px] text-muted uppercase tracking-wide">HTTP Status</div>
                  <div className="text-sm font-mono text-text mt-1">{selectedDelivery.http_status ?? '—'}</div>
                </div>
                <div className="bg-bg border border-border rounded p-3">
                  <div className="text-[10px] text-muted uppercase tracking-wide">Attempts</div>
                  <div className="text-sm text-text mt-1">{selectedDelivery.attempts}</div>
                </div>
                <div className="bg-bg border border-border rounded p-3">
                  <div className="text-[10px] text-muted uppercase tracking-wide">Event Type</div>
                  <div className="text-sm text-text mt-1">{getDisplayDeliveryType(selectedDelivery, matchingCapture)}</div>
                </div>
                <div className="bg-bg border border-border rounded p-3">
                  <div className="text-[10px] text-muted uppercase tracking-wide">Payload Hash</div>
                  <div className="text-xs font-mono text-text mt-1 break-all">{selectedDelivery.payload_hash || 'Unavailable'}</div>
                </div>
              </div>

              <div>
                <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-1">Error / Result</h4>
                <pre className="bg-bg border border-border rounded p-3 text-[11px] font-mono text-muted overflow-x-auto whitespace-pre-wrap">
                  {selectedDelivery.error_message || `HTTP ${selectedDelivery.http_status ?? '—'} · ${selectedDelivery.success ? 'Delivered successfully' : 'Delivery failed'}`}
                </pre>
              </div>

              <div>
                <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-1">Payload Sent</h4>
                {matchingCapture ? (
                  <pre className="bg-bg border border-border rounded p-3 text-[11px] font-mono text-muted overflow-x-auto max-h-[320px] overflow-y-auto whitespace-pre-wrap">
                    {JSON.stringify(matchingCapture.body, null, 2)}
                  </pre>
                ) : (
                  <div className="bg-bg border border-border rounded p-3 text-xs text-muted">
                    Full payload content is only available for deliveries captured by the built-in test receiver.
                    This delivery still includes the full error text and payload hash above.
                  </div>
                )}
              </div>

              {matchingCapture && (
                <div>
                  <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-1">Captured Headers</h4>
                  <pre className="bg-bg border border-border rounded p-3 text-[11px] font-mono text-muted overflow-x-auto max-h-[220px] overflow-y-auto whitespace-pre-wrap">
                    {JSON.stringify(matchingCapture.headers, null, 2)}
                  </pre>
                </div>
              )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ─── Settings Tab ────────────────────────────────── */

function SettingsTab() {
  return (
    <div className="space-y-4">
      <div className="bg-surface border border-border rounded-lg p-4 space-y-4">
        <h3 className="text-sm font-semibold text-text">Webhook Configuration Reference</h3>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <div className="text-xs text-muted mb-1">Dispatch Interval</div>
            <div className="text-text">Immediate (on incident creation)</div>
          </div>
          <div>
            <div className="text-xs text-muted mb-1">Retry Policy</div>
            <div className="text-text">Up to 3 attempts with exponential backoff</div>
          </div>
          <div>
            <div className="text-xs text-muted mb-1">Signature Header</div>
            <div className="text-text font-mono text-xs">X-Webhook-Signature</div>
          </div>
          <div>
            <div className="text-xs text-muted mb-1">Signature Algorithm</div>
            <div className="text-text font-mono text-xs">HMAC-SHA256</div>
          </div>
          <div>
            <div className="text-xs text-muted mb-1">Payload Format</div>
            <div className="text-text">JSON (application/json)</div>
          </div>
          <div>
            <div className="text-xs text-muted mb-1">Timeout</div>
            <div className="text-text">10 seconds per attempt</div>
          </div>
        </div>
      </div>

      <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-semibold text-text">Payload Structure</h3>
        <pre className="bg-bg border border-border rounded p-3 text-xs font-mono text-muted overflow-x-auto">
{`{
  "event_type": "incident",
  "timestamp": "2026-03-30T12:00:00Z",
  "incident": {
    "title": "Service Disruption",
    "description": "Customer-facing description",
    "source": "uip_sre",
    "started_at": "2026-03-30T11:45:00Z"
  }
}`}
        </pre>
      </div>

      <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-semibold text-text">Verifying Signatures</h3>
        <div className="text-xs text-muted space-y-2">
          <p>
            Each delivery includes an <code className="text-accent">X-Webhook-Signature</code> header containing an HMAC-SHA256
            signature of the request body, using the subscriber&apos;s secret as the key.
          </p>
          <p>To verify:</p>
          <pre className="bg-bg border border-border rounded p-3 font-mono overflow-x-auto">
{`import hmac, hashlib

expected = hmac.new(
    secret.encode(),
    request.body,
    hashlib.sha256
).hexdigest()

assert hmac.compare_digest(
    request.headers["X-Webhook-Signature"],
    expected
)`}
          </pre>
        </div>
      </div>
    </div>
  );
}

/* ─── Customer Preview Tab ───────────────────────────── */

function CustomerPreviewTab() {
  const [deliveries, setDeliveries] = useState<WebhookTestDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedDelivery, setSelectedDelivery] = useState<WebhookTestDelivery | null>(null);
  const [registered, setRegistered] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');

  function getTestReceiverUrl() {
    if (typeof window === 'undefined') {
      return '/api/runbook/webhook-test/receive';
    }
    return `${window.location.origin}/api/runbook/webhook-test/receive`;
  }

  async function ensureTestEndpoint() {
    const endpointUrl = getTestReceiverUrl();
    const existing = (await fetchWebhookSubscribers()).find(
      (sub) => sub.name === 'Test Receiver (Customer Preview)' || sub.url?.includes('webhook-test/receive'),
    );

    if (existing) {
      if (existing.url !== endpointUrl || !existing.is_active || existing.name !== 'Test Receiver (Customer Preview)') {
        const { ok, error: updateError } = await updateWebhookSubscriber(existing.id, {
          name: 'Test Receiver (Customer Preview)',
          url: endpointUrl,
          is_active: true,
        });
        if (!ok) {
          throw new Error(updateError || 'Failed to repair test receiver');
        }
      }
      return existing;
    }

    const result = await createWebhookSubscriber('Test Receiver (Customer Preview)', endpointUrl);
    if (!result.subscriber) {
      throw new Error(result.error || 'Failed to create test receiver');
    }
    return result.subscriber;
  }

  async function loadDeliveries() {
    const data = await fetchWebhookTestDeliveries();
    setDeliveries(data);
    setLoading(false);
    setSelectedDelivery((current) => {
      if (data.length === 0) return null;
      if (!current) return data[data.length - 1];
      return data.find((delivery) => delivery.id === current.id) || data[data.length - 1];
    });
  }

  useEffect(() => {
    loadDeliveries();
    const interval = setInterval(loadDeliveries, 5000);
    return () => clearInterval(interval);
  }, []);

  async function handleRegisterTestEndpoint() {
    setRegistering(true);
    setError('');
    try {
      await ensureTestEndpoint();
      setRegistered(true);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to register test receiver');
    } finally {
      setRegistering(false);
    }
  }

  async function handleSendTestMaintenance() {
    setSending(true);
    setError('');
    try {
      const testSub = await ensureTestEndpoint();
      setRegistered(true);
      const result = await testWebhookDelivery(testSub.id);
      if (!result.ok) {
        throw new Error(result.error || 'Failed to send test maintenance webhook');
      }
      setTimeout(loadDeliveries, 1000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to send test maintenance webhook');
    } finally {
      setSending(false);
    }
  }

  async function handleSendTestIncident() {
    setSending(true);
    setError('');
    try {
      await ensureTestEndpoint();
      setRegistered(true);
      const result = await sendIncidentWebhookPreview();
      if (!result.ok) {
        throw new Error(result.error || 'Failed to send test incident webhook');
      }
      setTimeout(loadDeliveries, 1000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to send test incident webhook');
    } finally {
      setSending(false);
    }
  }

  async function handleClear() {
    setError('');
    const result = await clearWebhookTestDeliveries();
    if (!result.ok) {
      setError('Failed to clear captured deliveries');
      return;
    }
    setDeliveries([]);
    setSelectedDelivery(null);
  }

  useEffect(() => {
    fetchWebhookSubscribers().then(subs => {
      if (subs.some(s => s.url?.includes('webhook-test/receive'))) {
        setRegistered(true);
      }
    });
  }, []);

  const sigColor = (result: string) => {
    switch (result) {
      case 'valid':
      case 'captured':
        return 'text-green';
      case 'missing':
        return 'text-yellow';
      default: return 'text-yellow';
    }
  };

  const sigLabel = (result: string) => {
    switch (result) {
      case 'valid':
        return 'VERIFIED';
      case 'captured':
        return 'CAPTURED';
      case 'missing':
        return 'MISSING';
      case 'invalid':
        return 'CAPTURED';
      default:
        return result.toUpperCase();
    }
  };

  return (
    <div className="space-y-4">
      {error && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">
          {error}
        </div>
      )}

      {/* Action bar */}
      <div className="flex items-center gap-3">
        {!registered ? (
          <button
            onClick={handleRegisterTestEndpoint}
            disabled={registering}
            className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90 transition-colors disabled:opacity-50"
          >
            {registering ? 'Registering...' : 'Register Test Endpoint'}
          </button>
        ) : (
          <>
            <button
              onClick={handleSendTestMaintenance}
              disabled={sending}
              className="px-4 py-2 bg-accent text-white rounded-lg text-sm font-medium hover:bg-accent/90 transition-colors disabled:opacity-50"
            >
              {sending ? 'Sending...' : 'Send Test Maintenance'}
            </button>
            <button
              onClick={handleSendTestIncident}
              disabled={sending}
              className="px-4 py-2 bg-orange text-white rounded-lg text-sm font-medium hover:bg-orange/90 transition-colors disabled:opacity-50"
            >
              {sending ? 'Sending...' : 'Send Test Incident'}
            </button>
            <button
              onClick={handleClear}
              className="px-3 py-2 border border-border text-muted rounded-lg text-sm hover:text-text hover:bg-surface-hover transition-colors"
            >
              Clear
            </button>
            <span className="text-xs text-muted ml-auto">
              {deliveries.length} deliveries received · Auto-refreshing
            </span>
          </>
        )}
      </div>

      {!registered && (
        <div className="bg-surface border border-border rounded-lg p-6 text-center">
          <p className="text-sm text-muted">
            Register a test endpoint to start receiving webhook deliveries. This creates an internal subscriber
            that captures payloads so you can preview exactly what customers will receive.
          </p>
        </div>
      )}

      {registered && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: Customer Dashboard Mock */}
          <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
            <div className="bg-gray-50 border-b border-gray-200 px-4 py-3">
              <h3 className="text-sm font-semibold text-gray-800">Customer Status Page</h3>
              <p className="text-xs text-gray-500 mt-0.5">This is how your customers would see maintenance and incident updates</p>
            </div>
            <div className="p-4 space-y-3 min-h-[300px]">
              {deliveries.length === 0 ? (
                <div className="flex items-center justify-center h-48 text-gray-400 text-sm">
                  No webhook previews yet. Send a test to see the preview.
                </div>
              ) : (
                deliveries.slice().reverse().map(d => {
                  const incident = d.body?.incident || d.body;
                  const eventType = d.body?.event_type || 'notification';
                  const isMaintenance = eventType === 'maintenance';
                  return (
                    <div
                      key={d.id}
                      onClick={() => setSelectedDelivery(d)}
                      className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                        selectedDelivery?.id === d.id
                          ? 'border-blue-400 bg-blue-50'
                          : 'border-gray-200 hover:border-gray-300 bg-white'
                      }`}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`w-2 h-2 rounded-full ${isMaintenance ? 'bg-blue-500' : 'bg-red-500'}`} />
                        <span className="text-sm font-medium text-gray-800">
                          {incident?.title || incident?.name || 'Notification'}
                        </span>
                      </div>
                      {(incident?.description || incident?.summary) && (
                        <p className="text-xs text-gray-600 ml-4">
                          {(incident?.description || incident?.summary || '').substring(0, 120)}
                        </p>
                      )}
                      <div className="flex items-center gap-3 mt-2 ml-4 text-[10px] text-gray-400">
                        <span>{new Date(d.timestamp).toLocaleString()}</span>
                        <span className="uppercase">{eventType}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right: Raw Inspector */}
          <div className="bg-surface border border-border rounded-xl overflow-hidden">
            <div className="bg-surface border-b border-border px-4 py-3">
              <h3 className="text-sm font-semibold text-text">Raw Payload Inspector</h3>
              <p className="text-xs text-muted mt-0.5">Technical details of the webhook delivery</p>
            </div>
            {selectedDelivery ? (
              <div className="p-4 space-y-4 max-h-[600px] overflow-y-auto">
                {/* Signature verification */}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted">Signature:</span>
                  <span className={`text-xs font-medium ${sigColor(selectedDelivery.signature_result)}`}>
                    {sigLabel(selectedDelivery.signature_result)}
                  </span>
                  {selectedDelivery.signature_header && (
                    <span className="text-[10px] text-muted font-mono truncate flex-1">
                      {selectedDelivery.signature_header.substring(0, 32)}...
                    </span>
                  )}
                </div>

                {/* Headers */}
                <div>
                  <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-1">Headers</h4>
                  <div className="bg-bg border border-border rounded p-2 space-y-0.5 max-h-[150px] overflow-y-auto">
                    {Object.entries(selectedDelivery.headers).map(([k, v]) => (
                      <div key={k} className="text-[11px] font-mono">
                        <span className="text-accent">{k}:</span>{' '}
                        <span className="text-muted">{v}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Body */}
                <div>
                  <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-1">Body</h4>
                  <pre className="bg-bg border border-border rounded p-2 text-[11px] font-mono text-muted overflow-x-auto max-h-[300px] overflow-y-auto whitespace-pre-wrap">
                    {JSON.stringify(selectedDelivery.body, null, 2)}
                  </pre>
                </div>

                {/* Meta */}
                <div className="flex items-center gap-4 text-[10px] text-muted">
                  <span>Delivery #{selectedDelivery.id}</span>
                  <span>{new Date(selectedDelivery.timestamp).toLocaleString()}</span>
                  <span>{selectedDelivery.content_length} bytes</span>
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-center h-48 text-muted text-sm">
                Select a delivery to inspect
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
