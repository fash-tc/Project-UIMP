'use client';

import { useEffect, useState } from 'react';
import {
  addInternalStatuspageComponent,
  addInternalStatuspageComponentGroup,
  addStatuspageSubscriber,
  fetchInternalStatuspageSummary,
  fetchStatuspageEmailDeliveries,
  fetchStatuspageSmtpSettings,
  fetchStatuspageSubscribers,
  removeInternalStatuspageComponent,
  removeInternalStatuspageComponentGroup,
  retryStatuspageEmailDelivery,
  updateInternalStatuspageComponent,
  updateInternalStatuspageComponentGroup,
  updateStatuspageSmtpSettings,
  updateStatuspageSubscriber,
} from '@/lib/keep-api';
import type {
  InternalComponentStatus,
  InternalStatuspageComponent,
  InternalStatuspageComponentGroup,
  InternalStatuspageSummary,
  StatuspageEmailDelivery,
  StatuspageSubscriber,
  StatuspageSmtpSettings,
} from '@/lib/types';

function label(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const COMPONENT_STATUS_OPTIONS: InternalComponentStatus[] = ['operational', 'degraded_performance', 'partial_outage', 'major_outage', 'maintenance'];

export default function StatusAdminPage() {
  const [summary, setSummary] = useState<InternalStatuspageSummary | null>(null);
  const [subscribers, setSubscribers] = useState<StatuspageSubscriber[]>([]);
  const [deliveries, setDeliveries] = useState<StatuspageEmailDelivery[]>([]);
  const [smtpSettings, setSmtpSettings] = useState<StatuspageSmtpSettings | null>(null);
  const [smtpPassword, setSmtpPassword] = useState('');
  const [message, setMessage] = useState('');

  const [groupName, setGroupName] = useState('');
  const [groupDescription, setGroupDescription] = useState('');
  const [componentName, setComponentName] = useState('');
  const [componentDescription, setComponentDescription] = useState('');
  const [componentGroupId, setComponentGroupId] = useState<number | null>(null);
  const [subscriberEmail, setSubscriberEmail] = useState('');
  const [subscriberLabel, setSubscriberLabel] = useState('');

  async function load() {
    const [nextSummary, nextSubscribers, nextDeliveries, nextSmtpSettings] = await Promise.all([
      fetchInternalStatuspageSummary(),
      fetchStatuspageSubscribers(),
      fetchStatuspageEmailDeliveries(),
      fetchStatuspageSmtpSettings(),
    ]);
    setSummary(nextSummary);
    setSubscribers(nextSubscribers);
    setDeliveries(nextDeliveries);
    setSmtpSettings(nextSmtpSettings);
  }

  useEffect(() => {
    load().catch((err) => setMessage(err instanceof Error ? err.message : 'Failed to load admin data'));
  }, []);

  async function saveGroup() {
    const result = await addInternalStatuspageComponentGroup({
      name: groupName,
      description: groupDescription,
      display_order: summary?.component_groups.length ?? 0,
    });
    if (!result.ok) return setMessage(result.error || 'Failed to save group');
    setGroupName('');
    setGroupDescription('');
    setMessage('Group saved.');
    await load();
  }

  async function saveGroupEdit(group: InternalStatuspageComponentGroup) {
    if (!group.id) return;
    const result = await updateInternalStatuspageComponentGroup(group.id, group);
    if (!result.ok) return setMessage(result.error || 'Failed to update group');
    await load();
  }

  async function saveComponent() {
    const result = await addInternalStatuspageComponent({
      name: componentName,
      description: componentDescription,
      group_id: componentGroupId,
      display_order: summary?.components.length ?? 0,
    });
    if (!result.ok) return setMessage(result.error || 'Failed to save component');
    setComponentName('');
    setComponentDescription('');
    setComponentGroupId(null);
    setMessage('Component saved.');
    await load();
  }

  async function saveComponentEdit(component: InternalStatuspageComponent) {
    const result = await updateInternalStatuspageComponent(component.id, {
      name: component.name,
      description: component.description,
      group_id: component.group_id ?? null,
      display_order: component.display_order,
      status: component.status,
    });
    if (!result.ok) return setMessage(result.error || 'Failed to update component');
    await load();
  }

  async function addSubscriber() {
    const result = await addStatuspageSubscriber(subscriberEmail, subscriberLabel);
    if (!result.ok) return setMessage(result.error || 'Failed to add subscriber');
    setSubscriberEmail('');
    setSubscriberLabel('');
    await load();
  }

  async function saveSmtpSettings() {
    if (!smtpSettings) return;
    const result = await updateStatuspageSmtpSettings({
      host: smtpSettings.host,
      port: smtpSettings.port,
      tls: smtpSettings.tls,
      username: smtpSettings.username,
      password: smtpPassword,
      email_from: smtpSettings.email_from,
    });
    if (!result.ok) return setMessage(result.error || 'Failed to save SMTP settings');
    setSmtpSettings(result.result || smtpSettings);
    setSmtpPassword('');
    setMessage('SMTP settings saved.');
  }

  function replaceComponent(updated: InternalStatuspageComponent) {
    setSummary((current) => current ? {
      ...current,
      components: current.components.map((component) => component.id === updated.id ? updated : component),
    } : current);
  }

  function replaceGroup(updated: InternalStatuspageComponentGroup) {
    setSummary((current) => current ? {
      ...current,
      component_groups: current.component_groups.map((group) => group.id === updated.id ? { ...group, ...updated } : group),
    } : current);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-text-bright">Statuspage Admin</h1>
        <p className="text-muted mt-1">Manage component groups, components, SMTP, and subscribers.</p>
      </div>

      {message && <div className="border border-accent/40 bg-accent/10 rounded-lg p-3 text-sm">{message}</div>}

      <section className="border border-border rounded-lg bg-surface p-4 space-y-3">
        <h2 className="font-semibold text-text-bright">Component Groups</h2>
        <div className="grid gap-2 md:grid-cols-[1fr_1.5fr_auto]">
          <input className="bg-bg border border-border rounded-md px-3 py-2" value={groupName} onChange={(e) => setGroupName(e.target.value)} placeholder="Group name" />
          <input className="bg-bg border border-border rounded-md px-3 py-2" value={groupDescription} onChange={(e) => setGroupDescription(e.target.value)} placeholder="Description" />
          <button className="border border-border rounded-md px-3 py-2 disabled:opacity-50" disabled={!groupName.trim()} onClick={saveGroup}>Add</button>
        </div>
        <div className="space-y-2">
          {summary?.component_groups.filter((group) => group.id !== null).map((group) => (
            <div key={group.id} className="grid gap-2 md:grid-cols-[1fr_1.5fr_100px_auto_auto] items-center border border-border rounded-md p-3">
              <input className="bg-bg border border-border rounded-md px-3 py-2" value={group.name} onChange={(e) => replaceGroup({ ...group, name: e.target.value })} />
              <input className="bg-bg border border-border rounded-md px-3 py-2" value={group.description} onChange={(e) => replaceGroup({ ...group, description: e.target.value })} />
              <input className="bg-bg border border-border rounded-md px-3 py-2" type="number" value={group.display_order} onChange={(e) => replaceGroup({ ...group, display_order: Number(e.target.value) || 0 })} />
              <button className="text-sm text-accent" onClick={() => saveGroupEdit(group)}>Save</button>
              <button className="text-sm text-red-300" onClick={() => group.id && removeInternalStatuspageComponentGroup(group.id).then(load)}>Remove</button>
            </div>
          ))}
        </div>
      </section>

      <section className="border border-border rounded-lg bg-surface p-4 space-y-3">
        <h2 className="font-semibold text-text-bright">Components</h2>
        <div className="grid gap-2 md:grid-cols-[1fr_1.5fr_180px_auto]">
          <input className="bg-bg border border-border rounded-md px-3 py-2" value={componentName} onChange={(e) => setComponentName(e.target.value)} placeholder="Component name" />
          <input className="bg-bg border border-border rounded-md px-3 py-2" value={componentDescription} onChange={(e) => setComponentDescription(e.target.value)} placeholder="Description" />
          <select className="bg-bg border border-border rounded-md px-3 py-2" value={componentGroupId ?? ''} onChange={(e) => setComponentGroupId(e.target.value ? Number(e.target.value) : null)}>
            <option value="">Ungrouped</option>
            {summary?.component_groups.filter((group) => group.id !== null).map((group) => <option key={group.id} value={group.id ?? ''}>{group.name}</option>)}
          </select>
          <button className="border border-border rounded-md px-3 py-2 disabled:opacity-50" disabled={!componentName.trim()} onClick={saveComponent}>Add</button>
        </div>
        <div className="space-y-2">
          {summary?.components.map((component) => (
            <div key={component.id} className="grid gap-2 md:grid-cols-[1fr_1.3fr_180px_190px_80px_auto_auto] items-center border border-border rounded-md p-3">
              <input className="bg-bg border border-border rounded-md px-3 py-2" value={component.name} onChange={(e) => replaceComponent({ ...component, name: e.target.value })} />
              <input className="bg-bg border border-border rounded-md px-3 py-2" value={component.description} onChange={(e) => replaceComponent({ ...component, description: e.target.value })} />
              <select className="bg-bg border border-border rounded-md px-3 py-2" value={component.group_id ?? ''} onChange={(e) => replaceComponent({ ...component, group_id: e.target.value ? Number(e.target.value) : null })}>
                <option value="">Ungrouped</option>
                {summary.component_groups.filter((group) => group.id !== null).map((group) => <option key={group.id} value={group.id ?? ''}>{group.name}</option>)}
              </select>
              <select className="bg-bg border border-border rounded-md px-3 py-2" value={component.status} onChange={(e) => replaceComponent({ ...component, status: e.target.value as InternalComponentStatus })}>
                {COMPONENT_STATUS_OPTIONS.map((option) => <option key={option} value={option}>{label(option)}</option>)}
              </select>
              <input className="bg-bg border border-border rounded-md px-3 py-2" type="number" value={component.display_order} onChange={(e) => replaceComponent({ ...component, display_order: Number(e.target.value) || 0 })} />
              <button className="text-sm text-accent" onClick={() => saveComponentEdit(component)}>Save</button>
              <button className="text-sm text-red-300" onClick={() => removeInternalStatuspageComponent(component.id).then(load)}>Remove</button>
            </div>
          ))}
          {summary?.components.length === 0 && <div className="text-muted">No components yet.</div>}
        </div>
      </section>

      <section className="border border-border rounded-lg bg-surface p-4 space-y-3">
        <div className="flex items-center justify-between gap-3">
          <h2 className="font-semibold text-text-bright">SMTP Settings</h2>
          <span className={`text-xs px-2 py-1 rounded border ${smtpSettings?.host && smtpSettings?.email_from ? 'border-green/30 text-green bg-green/10' : 'border-yellow/30 text-yellow bg-yellow/10'}`}>
            {smtpSettings?.host && smtpSettings?.email_from ? 'Configured' : 'Missing relay'}
          </span>
        </div>
        {smtpSettings && (
          <>
            <div className="grid gap-3 md:grid-cols-[1fr_120px]">
              <input className="w-full bg-bg border border-border rounded-md px-3 py-2 text-text" value={smtpSettings.host} onChange={(e) => setSmtpSettings({ ...smtpSettings, host: e.target.value })} placeholder="SMTP host" />
              <input className="w-full bg-bg border border-border rounded-md px-3 py-2 text-text" type="number" min={1} max={65535} value={smtpSettings.port} onChange={(e) => setSmtpSettings({ ...smtpSettings, port: Number(e.target.value) || 25 })} />
            </div>
            <div className="grid gap-3 md:grid-cols-2">
              <input className="w-full bg-bg border border-border rounded-md px-3 py-2 text-text" value={smtpSettings.email_from} onChange={(e) => setSmtpSettings({ ...smtpSettings, email_from: e.target.value })} placeholder="From address" />
              <input className="w-full bg-bg border border-border rounded-md px-3 py-2 text-text" value={smtpSettings.username} onChange={(e) => setSmtpSettings({ ...smtpSettings, username: e.target.value })} placeholder="Username" />
            </div>
            <div className="grid gap-3 md:grid-cols-[1fr_auto]">
              <input className="w-full bg-bg border border-border rounded-md px-3 py-2 text-text" type="password" value={smtpPassword} onChange={(e) => setSmtpPassword(e.target.value)} placeholder={smtpSettings.password_set ? 'Leave blank to keep saved password' : 'Password'} />
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={smtpSettings.tls} onChange={(e) => setSmtpSettings({ ...smtpSettings, tls: e.target.checked })} />
                STARTTLS
              </label>
            </div>
            <button className="bg-accent text-bg px-4 py-2 rounded-md font-medium disabled:opacity-50" disabled={!smtpSettings.host || !smtpSettings.email_from} onClick={saveSmtpSettings}>Save SMTP Settings</button>
          </>
        )}
      </section>

      <section className="border border-border rounded-lg bg-surface p-4 space-y-3">
        <h2 className="font-semibold text-text-bright">Subscribers</h2>
        <div className="grid gap-2 md:grid-cols-[1fr_1fr_auto]">
          <input className="bg-bg border border-border rounded-md px-3 py-2" value={subscriberEmail} onChange={(e) => setSubscriberEmail(e.target.value)} placeholder="email@example.com" />
          <input className="bg-bg border border-border rounded-md px-3 py-2" value={subscriberLabel} onChange={(e) => setSubscriberLabel(e.target.value)} placeholder="Label" />
          <button className="border border-border rounded-md px-3 py-2" onClick={addSubscriber}>Add</button>
        </div>
        <div className="space-y-2">
          {subscribers.map((sub) => (
            <div key={sub.id} className="flex items-center justify-between border border-border rounded-md p-3">
              <div>
                <div>{sub.email}</div>
                <div className="text-xs text-muted">{sub.label || 'No label'}</div>
              </div>
              <button className="text-sm text-muted hover:text-text-bright" onClick={() => updateStatuspageSubscriber(sub.id, { active: !sub.active, label: sub.label }).then(load)}>
                {sub.active ? 'Disable' : 'Enable'}
              </button>
            </div>
          ))}
        </div>
      </section>

      <section className="border border-border rounded-lg bg-surface p-4 space-y-3">
        <h2 className="font-semibold text-text-bright">Email Deliveries</h2>
        {deliveries.map((delivery) => (
          <div key={delivery.id} className="flex items-center justify-between border border-border rounded-md p-3">
            <div>
              <div>{delivery.recipient_email}</div>
              <div className="text-xs text-muted">{label(delivery.status)} - attempts {delivery.attempts}{delivery.last_error ? ` - ${delivery.last_error}` : ''}</div>
            </div>
            {delivery.status === 'failed' && <button className="text-sm text-accent" onClick={() => retryStatuspageEmailDelivery(delivery.id).then(load)}>Retry</button>}
          </div>
        ))}
        {deliveries.length === 0 && <div className="text-muted">No email deliveries yet.</div>}
      </section>
    </div>
  );
}
