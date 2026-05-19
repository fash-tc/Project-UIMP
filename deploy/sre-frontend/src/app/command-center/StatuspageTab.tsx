'use client';

import { useEffect, useState } from 'react';
import { StatuspageComponent, StatuspageComponentUpdate, StatuspageIncident } from '@/lib/types';
import {
  createStatuspageIncident,
  fetchStatuspageComponents,
  fetchStatuspageIncidents,
  updateStatuspageIncident,
} from '@/lib/keep-api';
import StatuspageIncidentEditor from './StatuspageIncidentEditor';

type IncidentFormState = {
  title: string;
  body: string;
  status: string;
  impact: string;
  components: StatuspageComponentUpdate[];
};

const EMPTY_FORM: IncidentFormState = {
  title: '',
  body: '',
  status: 'investigating',
  impact: 'minor',
  components: [],
};

function formatRefreshLabel(iso: string | null): string {
  if (!iso) return '--';
  return new Date(iso).toLocaleTimeString();
}

export default function StatuspageTab({
  onIncidentCountChange,
}: {
  onIncidentCountChange?: (count: number) => void;
}) {
  const [incidents, setIncidents] = useState<StatuspageIncident[]>([]);
  const [components, setComponents] = useState<StatuspageComponent[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<string | null>(null);
  const [createForm, setCreateForm] = useState<IncidentFormState>(EMPTY_FORM);
  const [editingIncidentId, setEditingIncidentId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<IncidentFormState>(EMPTY_FORM);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [incidentData, componentData] = await Promise.all([
        fetchStatuspageIncidents(),
        fetchStatuspageComponents(),
      ]);
      setIncidents(incidentData);
      onIncidentCountChange?.(incidentData.length);
      setComponents(componentData);
      setLastRefreshed(new Date().toISOString());
    } catch (err) {
      onIncidentCountChange?.(0);
      setError(err instanceof Error ? err.message : 'Failed to load Statuspage data.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void loadData();
    const timer = window.setInterval(() => {
      void loadData();
    }, 45000);
    return () => window.clearInterval(timer);
  }, []);

  async function handleCreate() {
    setSaving(true);
    setError(null);
    const { error: createError } = await createStatuspageIncident({
      name: createForm.title,
      body: createForm.body,
      status: createForm.status,
      impact_override: createForm.impact,
      components: createForm.components,
    });
    setSaving(false);
    if (createError) {
      setError(createError);
      return;
    }
    setCreateForm(EMPTY_FORM);
    await loadData();
  }

  async function handleUpdate(incidentId: string) {
    setSaving(true);
    setError(null);
    const { error: updateError } = await updateStatuspageIncident(incidentId, {
      name: editForm.title,
      body: editForm.body,
      status: editForm.status,
      impact_override: editForm.impact,
      components: editForm.components,
    });
    setSaving(false);
    if (updateError) {
      setError(updateError);
      return;
    }
    setEditingIncidentId(null);
    setEditForm(EMPTY_FORM);
    await loadData();
  }

  function startEditing(incident: StatuspageIncident, resolving: boolean) {
    setEditingIncidentId(incident.id);
    setEditForm({
      title: incident.name,
      body: '',
      status: resolving ? 'resolved' : incident.status,
      impact: resolving ? 'none' : incident.impact || 'minor',
      components: incident.components.map(component => ({
        component_id: component.id,
        status: resolving ? 'operational' : component.status,
      })),
    });
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-text-bright">Statuspage</h3>
          <p className="text-xs text-muted">Create and control active customer-facing incidents from UIP.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] uppercase tracking-wide text-muted">
            Last refreshed {formatRefreshLabel(lastRefreshed)}
          </span>
          <button
            onClick={() => void loadData()}
            className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red/30 bg-red/10 px-4 py-3 text-xs text-red">
          {error}
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-[1.2fr,0.8fr]">
        <div className="space-y-3">
          <h4 className="text-xs uppercase tracking-wide text-muted">Active Incidents</h4>
          {loading ? (
            <div className="rounded-xl border border-border bg-surface px-4 py-6 text-sm text-muted">
              Loading Statuspage incidents...
            </div>
          ) : incidents.length === 0 ? (
            <div className="rounded-xl border border-border bg-surface px-4 py-6 text-sm text-muted">
              No active Statuspage incidents.
            </div>
          ) : (
            incidents.map(incident => (
              <div key={incident.id} className="rounded-xl border border-border bg-surface p-4 space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-text-bright">{incident.name}</div>
                    <div className="text-xs text-muted mt-1">
                      Status: {incident.status} · Impact: {incident.impact || 'minor'}
                    </div>
                  </div>
                  <a
                    href={incident.shortlink}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-accent hover:underline whitespace-nowrap"
                  >
                    Open in Statuspage
                  </a>
                </div>

                <div className="flex flex-wrap gap-2">
                  {incident.components.map(component => (
                    <span
                      key={component.id}
                      className="inline-flex items-center px-2 py-1 rounded border border-border text-[10px] text-muted"
                    >
                      {component.name}: {component.status}
                    </span>
                  ))}
                </div>

                {editingIncidentId === incident.id ? (
                  <StatuspageIncidentEditor
                    title={editForm.title}
                    body={editForm.body}
                    status={editForm.status}
                    impact={editForm.impact}
                    components={components}
                    componentUpdates={editForm.components}
                    loadingComponents={loading}
                    resolving={editForm.status === 'resolved'}
                    submitting={saving}
                    submitLabel={editForm.status === 'resolved' ? 'Resolve Statuspage Incident' : 'Post Update'}
                    onChangeTitle={(value) => setEditForm(prev => ({ ...prev, title: value }))}
                    onChangeBody={(value) => setEditForm(prev => ({ ...prev, body: value }))}
                    onChangeStatus={(value) => setEditForm(prev => ({ ...prev, status: value }))}
                    onChangeImpact={(value) => setEditForm(prev => ({ ...prev, impact: value }))}
                    onChangeComponents={(value) => setEditForm(prev => ({ ...prev, components: value }))}
                    onSubmit={() => void handleUpdate(incident.id)}
                  />
                ) : (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => startEditing(incident, false)}
                      className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
                    >
                      Post Update
                    </button>
                    <button
                      onClick={() => startEditing(incident, true)}
                      className="px-3 py-1.5 rounded border border-green/30 text-xs text-green hover:bg-green/10 transition-colors"
                    >
                      Resolve
                    </button>
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        <div className="rounded-xl border border-border bg-surface p-4 space-y-3">
          <h4 className="text-xs uppercase tracking-wide text-muted">Create Incident</h4>
          <StatuspageIncidentEditor
            title={createForm.title}
            body={createForm.body}
            status={createForm.status}
            impact={createForm.impact}
            components={components}
            componentUpdates={createForm.components}
            loadingComponents={loading}
            submitting={saving}
            submitLabel="Create Statuspage Incident"
            onChangeTitle={(value) => setCreateForm(prev => ({ ...prev, title: value }))}
            onChangeBody={(value) => setCreateForm(prev => ({ ...prev, body: value }))}
            onChangeStatus={(value) => setCreateForm(prev => ({ ...prev, status: value }))}
            onChangeImpact={(value) => setCreateForm(prev => ({ ...prev, impact: value }))}
            onChangeComponents={(value) => setCreateForm(prev => ({ ...prev, components: value }))}
            onSubmit={() => void handleCreate()}
          />
        </div>
      </div>
    </div>
  );
}
