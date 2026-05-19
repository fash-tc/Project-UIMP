'use client';

import { useEffect, useState } from 'react';
import { createInternalStatuspageIncident, fetchInternalStatuspageSummary, updateInternalStatuspageIncident } from '@/lib/keep-api';
import type {
  InternalComponentStatus,
  InternalStatuspageComponent,
  InternalStatuspageIncident,
  InternalStatuspageSummary,
  StatuspageImpact,
  StatuspageIncidentStatus,
} from '@/lib/types';

function label(value: string) {
  return value.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const INCIDENT_STATUS_OPTIONS: StatuspageIncidentStatus[] = ['investigating', 'identified', 'monitoring', 'resolved', 'scheduled_maintenance'];
const EDIT_COMPONENT_STATUS_OPTIONS: InternalComponentStatus[] = ['operational', 'degraded_performance', 'partial_outage', 'major_outage', 'maintenance'];
const NEW_COMPONENT_STATUS_OPTIONS: InternalComponentStatus[] = ['degraded_performance', 'partial_outage', 'major_outage', 'maintenance'];

export default function StatusIncidentsPage() {
  const [tab, setTab] = useState<'active' | 'new'>('active');
  const [summary, setSummary] = useState<InternalStatuspageSummary | null>(null);
  const [message, setMessage] = useState('');

  const [editing, setEditing] = useState<InternalStatuspageIncident | null>(null);
  const [editBody, setEditBody] = useState('');
  const [editStatus, setEditStatus] = useState<StatuspageIncidentStatus>('monitoring');
  const [editNotify, setEditNotify] = useState(true);
  const [editComponents, setEditComponents] = useState<Record<number, InternalComponentStatus>>({});
  const [saving, setSaving] = useState(false);

  const [title, setTitle] = useState('');
  const [newBody, setNewBody] = useState('');
  const [newStatus, setNewStatus] = useState<StatuspageIncidentStatus>('investigating');
  const [impact, setImpact] = useState<StatuspageImpact>('major');
  const [newComponents, setNewComponents] = useState<Record<number, InternalComponentStatus>>({});
  const [newNotify, setNewNotify] = useState(true);
  const [publishing, setPublishing] = useState(false);

  async function load() {
    setSummary(await fetchInternalStatuspageSummary());
  }

  useEffect(() => {
    if (typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('tab') === 'new') {
      setTab('new');
    }
    load().catch((err) => setMessage(err instanceof Error ? err.message : 'Failed to load incidents'));
  }, []);

  function componentSelection(incident: InternalStatuspageIncident) {
    const next: Record<number, InternalComponentStatus> = {};
    for (const component of incident.components || []) {
      next[component.component_id || component.id] = component.component_status || component.status;
    }
    return next;
  }

  function beginEdit(incident: InternalStatuspageIncident) {
    setEditing(incident);
    setEditStatus(incident.status);
    setEditBody('');
    setEditComponents(componentSelection(incident));
    setTab('active');
  }

  function toggleEditComponent(componentId: number) {
    setEditComponents((current) => {
      const next = { ...current };
      if (next[componentId]) delete next[componentId];
      else next[componentId] = 'degraded_performance';
      return next;
    });
  }

  function toggleNewComponent(component: InternalStatuspageComponent) {
    setNewComponents((current) => {
      const next = { ...current };
      if (next[component.id]) delete next[component.id];
      else next[component.id] = component.status === 'operational' ? 'degraded_performance' : component.status;
      return next;
    });
  }

  async function saveUpdate() {
    if (!editing) return;
    setSaving(true);
    setMessage('');
    const components = Object.entries(editComponents).map(([componentId, componentStatus]) => ({
      component_id: Number(componentId),
      status: componentStatus,
    }));
    const result = await updateInternalStatuspageIncident(editing.id, { status: editStatus, body: editBody, notify: editNotify, components });
    setSaving(false);
    if (!result.ok) return setMessage(result.error || 'Failed to update incident');
    setEditing(null);
    setEditBody('');
    setEditComponents({});
    setMessage('Incident updated.');
    await load();
  }

  async function publish() {
    setMessage('');
    setPublishing(true);
    const components = Object.entries(newComponents).map(([componentId, componentStatus]) => ({
      component_id: Number(componentId),
      status: componentStatus,
    }));
    const result = await createInternalStatuspageIncident({ title, body: newBody, status: newStatus, impact, notify: newNotify, components });
    setPublishing(false);
    if (!result.ok) return setMessage(result.error || 'Publish failed');
    setTitle('');
    setNewBody('');
    setNewComponents({});
    setMessage('Incident published.');
    setTab('active');
    await load();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-text-bright">Statuspage Incidents</h1>
        <p className="text-muted mt-1">Create incidents and update currently running incidents from one place.</p>
      </div>

      <div className="inline-flex border border-border rounded-md overflow-hidden">
        <button className={`px-4 py-2 text-sm ${tab === 'active' ? 'bg-accent text-bg' : 'bg-surface text-muted hover:text-text-bright'}`} onClick={() => setTab('active')}>Active Incidents</button>
        <button className={`px-4 py-2 text-sm ${tab === 'new' ? 'bg-accent text-bg' : 'bg-surface text-muted hover:text-text-bright'}`} onClick={() => setTab('new')}>New Incident</button>
      </div>

      {message && <div className="border border-accent/40 bg-accent/10 rounded-lg p-3 text-sm">{message}</div>}

      {tab === 'active' && (
        <>
          <section className="border border-border rounded-lg bg-surface p-4 space-y-3">
            <h2 className="font-semibold text-text-bright">Currently Running</h2>
            {summary?.active_incidents.map((incident) => (
              <div key={incident.id} className="border border-border rounded-md p-3 flex items-center justify-between gap-4">
                <div>
                  <div className="font-medium text-text-bright">{incident.title}</div>
                  <div className="text-xs text-muted">{label(incident.status)} - {label(incident.impact)}</div>
                </div>
                <button className="text-sm text-accent" onClick={() => beginEdit(incident)}>Edit</button>
              </div>
            ))}
            {summary?.active_incidents.length === 0 && <div className="text-muted">No active incidents.</div>}
          </section>

          {editing && (
            <section className="border border-border rounded-lg bg-surface p-4 space-y-4">
              <div>
                <h2 className="font-semibold text-text-bright">Edit: {editing.title}</h2>
                <div className="text-xs text-muted">Latest update: {editing.latest_update?.created_at || editing.updated_at}</div>
              </div>
              <textarea className="w-full bg-bg border border-border rounded-md px-3 py-2 min-h-32" value={editBody} onChange={(e) => setEditBody(e.target.value)} placeholder="What changed?" />
              <div className="grid gap-3 md:grid-cols-[220px_auto]">
                <select className="bg-bg border border-border rounded-md px-3 py-2" value={editStatus} onChange={(e) => setEditStatus(e.target.value as StatuspageIncidentStatus)}>
                  {INCIDENT_STATUS_OPTIONS.map((option) => <option key={option} value={option}>{label(option)}</option>)}
                </select>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={editNotify} onChange={(e) => setEditNotify(e.target.checked)} />
                  Email subscribers
                </label>
              </div>

              <ComponentPicker
                summary={summary}
                selectedComponents={editComponents}
                options={EDIT_COMPONENT_STATUS_OPTIONS}
                onToggle={(component) => toggleEditComponent(component.id)}
                onStatus={(component, status) => setEditComponents((current) => ({ ...current, [component.id]: status }))}
              />

              <div className="flex gap-2">
                <button className="bg-accent text-bg px-4 py-2 rounded-md font-medium disabled:opacity-50" disabled={!editBody.trim() || saving} onClick={saveUpdate}>{saving ? 'Saving...' : 'Save Update'}</button>
                <button className="border border-border px-4 py-2 rounded-md" onClick={() => setEditing(null)}>Cancel</button>
              </div>
            </section>
          )}
        </>
      )}

      {tab === 'new' && (
        <>
          <section className="border border-border rounded-lg bg-surface p-4 space-y-3">
            <input className="w-full bg-bg border border-border rounded-md px-3 py-2" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Incident title" />
            <textarea className="w-full bg-bg border border-border rounded-md px-3 py-2 min-h-32" value={newBody} onChange={(e) => setNewBody(e.target.value)} placeholder="Update body" />
            <div className="grid gap-3 md:grid-cols-3">
              <select className="bg-bg border border-border rounded-md px-3 py-2" value={newStatus} onChange={(e) => setNewStatus(e.target.value as StatuspageIncidentStatus)}>
                {INCIDENT_STATUS_OPTIONS.map((option) => <option key={option} value={option}>{label(option)}</option>)}
              </select>
              <select className="bg-bg border border-border rounded-md px-3 py-2" value={impact} onChange={(e) => setImpact(e.target.value as StatuspageImpact)}>
                <option value="minor">Minor</option>
                <option value="major">Major</option>
                <option value="critical">Critical</option>
                <option value="maintenance">Maintenance</option>
                <option value="none">None</option>
              </select>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={newNotify} onChange={(e) => setNewNotify(e.target.checked)} />
                Email subscribers
              </label>
            </div>
          </section>

          <ComponentPicker
            summary={summary}
            selectedComponents={newComponents}
            options={NEW_COMPONENT_STATUS_OPTIONS}
            onToggle={toggleNewComponent}
            onStatus={(component, status) => setNewComponents((current) => ({ ...current, [component.id]: status }))}
          />

          <button className="bg-accent text-bg px-4 py-2 rounded-md font-medium disabled:opacity-50" disabled={!title.trim() || !newBody.trim() || publishing} onClick={publish}>
            {publishing ? 'Publishing...' : 'Publish Incident'}
          </button>
        </>
      )}
    </div>
  );
}

function ComponentPicker({
  summary,
  selectedComponents,
  options,
  onToggle,
  onStatus,
}: {
  summary: InternalStatuspageSummary | null;
  selectedComponents: Record<number, InternalComponentStatus>;
  options: InternalComponentStatus[];
  onToggle: (component: InternalStatuspageComponent) => void;
  onStatus: (component: InternalStatuspageComponent, status: InternalComponentStatus) => void;
}) {
  return (
    <section className="border border-border rounded-lg bg-surface p-4 space-y-4">
      <h2 className="font-semibold text-text-bright">Affected Components</h2>
      {summary?.component_groups.map((group) => (
        <div key={group.id ?? 'ungrouped'} className="space-y-2">
          <div className="text-sm font-medium text-muted">{group.name}</div>
          {group.components.map((component) => {
            const selectedStatus = selectedComponents[component.id];
            return (
              <div key={component.id} className="grid gap-2 md:grid-cols-[1fr_220px] items-center border border-border rounded-md p-3">
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={Boolean(selectedStatus)} onChange={() => onToggle(component)} />
                  <span>{component.name}</span>
                  <span className="text-xs text-muted">current: {label(component.status)}</span>
                </label>
                <select
                  className="bg-bg border border-border rounded-md px-3 py-2 disabled:opacity-50"
                  disabled={!selectedStatus}
                  value={selectedStatus || 'degraded_performance'}
                  onChange={(e) => onStatus(component, e.target.value as InternalComponentStatus)}
                >
                  {options.map((option) => <option key={option} value={option}>{label(option)}</option>)}
                </select>
              </div>
            );
          })}
        </div>
      ))}
      {summary?.components.length === 0 && <div className="text-sm text-muted">Add components from Statuspage Admin first.</div>}
    </section>
  );
}
