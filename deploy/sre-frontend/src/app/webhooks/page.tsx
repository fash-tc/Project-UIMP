'use client';

import { useEffect, useState } from 'react';
import {
  WebhookSubscriber,
  WebhookDelivery,
} from '@/lib/types';
import {
  fetchWebhookSubscribers,
  createWebhookSubscriber,
  updateWebhookSubscriber,
  deleteWebhookSubscriber,
  rotateWebhookSecret,
  testWebhookDelivery,
  fetchWebhookDeliveries,
} from '@/lib/keep-api';

type Tab = 'subscribers' | 'deliveries' | 'settings';

export default function WebhooksPage() {
  const [tab, setTab] = useState<Tab>('subscribers');

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-text">Webhook Management</h1>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-border">
        {([
          ['subscribers', 'Subscribers'],
          ['deliveries', 'Delivery Log'],
          ['settings', 'Settings'],
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
      setSubscribers(subs);
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
    if (!confirm(`Delete subscriber "${sub.name}"? This cannot be undone.`)) return;
    const { error: err } = await deleteWebhookSubscriber(sub.id);
    if (err) setError(err);
    else await load();
  }

  async function handleRotate(sub: WebhookSubscriber) {
    if (!confirm(`Rotate secret for "${sub.name}"? The old secret will stop working immediately.`)) return;
    const { secret, error: err } = await rotateWebhookSecret(sub.id);
    if (err) setError(err);
    else if (secret) setRotatedSecret({ id: sub.id, secret });
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
                        Delete
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

  // Filters
  const [filterSuccess, setFilterSuccess] = useState<boolean | undefined>(undefined);
  const [filterSubscriber, setFilterSubscriber] = useState<number | undefined>(undefined);
  const [subscribers, setSubscribers] = useState<WebhookSubscriber[]>([]);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const data = await fetchWebhookDeliveries(filterSubscriber, filterSuccess);
      setDeliveries(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load deliveries');
    }
    setLoading(false);
  }

  useEffect(() => {
    fetchWebhookSubscribers().then(setSubscribers).catch(() => {});
  }, []);

  useEffect(() => { load(); }, [filterSuccess, filterSubscriber]);

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
      ) : deliveries.length === 0 ? (
        <div className="text-sm text-muted">No deliveries found.</div>
      ) : (
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
              </tr>
            </thead>
            <tbody>
              {deliveries.map(d => (
                <tr key={d.id} className="border-b border-border/50 hover:bg-surface-hover/50">
                  <td className="py-2.5 px-3 text-text">{d.subscriber_name || `#${d.subscriber_id}`}</td>
                  <td className="py-2.5 px-3 text-xs text-muted font-mono">
                    {new Date(d.timestamp).toLocaleString()}
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
                    {d.is_test && (
                      <span className="px-2 py-0.5 rounded text-xs font-medium bg-accent/10 text-accent border border-accent/30">
                        Test
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
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
