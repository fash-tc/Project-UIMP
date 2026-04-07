'use client';

import { useEffect, useState, useCallback, useMemo } from 'react';
import { Alert, AIEnrichment, RunbookEntry, AlertState, SSEEvent, RunbookFeedback, CustomAlertGroup } from '@/lib/types';
import { useSSE } from '@/hooks/useSSE';
import {
  fetchAlerts,
  parseAIEnrichment,
  submitSREFeedback,
  submitStructuredFeedback,
  severityColor,
  severityBg,
  timeAgo,
  alertStartTime,
  fetchRunbookMatches,
  searchRunbookEntries,
  attachRunbookEntry,
  submitRunbookEntry,
  resolveAlert,
  resolveAlerts,
  unresolveAlert,
  unresolveAlerts,
  silenceAlert,
  createJiraIncident,
  fetchAlertStates,
  syncCustomAlertGroups,
  createCustomAlertGroup,
  renameCustomAlertGroup,
  addAlertsToCustomAlertGroup,
  toggleInvestigating,
  acknowledgeAlerts,
  unacknowledgeAlerts,
  markAlertsUpdated,
  getSourceLabel,
  forceEnrich,
  fetchEscalationTeams,
  fetchEscalationUsers,
  escalateAlert,
  storeIncidentState,
  storeIncidentStateBulk,
  storeEscalationState,
  submitRunbookFeedback,
  fetchRunbookFeedback,
  fetchSilenceRules,
  createSilenceRule,
  cancelSilenceRule,
  SilenceRule,
  MaintenanceEvent,
  fetchMaintenanceEvents,
} from '@/lib/keep-api';
import { getClientUsername } from '@/lib/auth';
import { detectRegistryFromAlert, buildRegistryMailto, matchMaintenanceToOperators } from '@/lib/registry';
import DashboardView from './DashboardView';
import AlertsTableView from './AlertsTableView';
import KnowledgeBasePage from './KnowledgeBasePage';
import IncidentWizard from './IncidentWizard';
import BulkIncidentTicketModal from './BulkIncidentTicketModal';

function extractAlertBase(alertName: string, hostname: string): string {
  if (!alertName) return 'Unknown';
  if (hostname) {
    const lower = alertName.toLowerCase();
    const hostLower = hostname.toLowerCase();
    for (const sep of [' on ', ' for ', ' at ', ' - ', ': ']) {
      const idx = lower.indexOf(sep + hostLower);
      if (idx !== -1) return alertName.substring(0, idx).trim();
    }
    if (lower.endsWith(hostLower)) {
      return alertName.substring(0, alertName.length - hostname.length).replace(/[\s\-:]+$/, '').trim();
    }
  }
  return alertName;
}

function getParentDomain(hostname: string): string {
  if (!hostname) return '';
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  return parts.slice(1).join('.');
}

function normalizeDomain(domain: string): string {
  if (!domain) return '';
  return domain.split('.').map(part => part.replace(/\d+$/, '')).join('.');
}

function buildInferredGroupMembership(alerts: Alert[]): Map<string, string> {
  const domainMap = new Map<string, Alert[]>();
  for (const alert of alerts) {
    const host = alert.hostName || alert.hostname || '';
    const base = extractAlertBase(alert.name || '', host);
    const key = `${base}::${normalizeDomain(getParentDomain(host))}`;
    if (!domainMap.has(key)) domainMap.set(key, []);
    domainMap.get(key)!.push(alert);
  }

  const membership = new Map<string, string>();
  const singlesByBase = new Map<string, Alert[]>();

  Array.from(domainMap.entries()).forEach(([key, groupedAlerts]) => {
    if (groupedAlerts.length >= 2) {
      groupedAlerts.forEach(alert => membership.set(alert.fingerprint, key));
      return;
    }
    const alert = groupedAlerts[0];
    const host = alert.hostName || alert.hostname || '';
    const base = extractAlertBase(alert.name || '', host);
    if (!singlesByBase.has(base)) singlesByBase.set(base, []);
    singlesByBase.get(base)!.push(alert);
  });

  Array.from(singlesByBase.entries()).forEach(([base, groupedAlerts]) => {
    const key = `name::${base}`;
    groupedAlerts.forEach(alert => membership.set(alert.fingerprint, key));
  });

  return membership;
}

function buildSuggestedGroupName(alerts: Alert[]): string {
  if (alerts.length === 0) return 'Temporary Alert Group';
  const first = alerts[0];
  const host = first.hostName || first.hostname || '';
  const base = extractAlertBase(first.name || '', host);
  if (alerts.length === 1) return base || 'Temporary Alert Group';
  return `${base || 'Selected Alerts'} Group`;
}

export default function CommandCenter() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [refreshInterval, setRefreshInterval] = useState(60);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [alertStates, setAlertStates] = useState<Map<string, AlertState>>(new Map());
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'knowledge-base'>('dashboard');
  const [situationTrigger, setSituationTrigger] = useState(0);
  const [silenceRules, setSilenceRules] = useState<SilenceRule[]>([]);
  const [maintenanceEvents, setMaintenanceEvents] = useState<MaintenanceEvent[]>([]);
  const [customGroups, setCustomGroups] = useState<CustomAlertGroup[]>([]);
  const [selectedFingerprints, setSelectedFingerprints] = useState<Set<string>>(new Set());
  const [showBulkTicketModal, setShowBulkTicketModal] = useState(false);
  const [showCreateGroupModal, setShowCreateGroupModal] = useState(false);
  const [pendingGroupName, setPendingGroupName] = useState('');
  const [selectedGroupMode, setSelectedGroupMode] = useState<'create' | 'existing'>('create');
  const [selectedExistingGroupId, setSelectedExistingGroupId] = useState<number | null>(null);
  const [bulkError, setBulkError] = useState<string | null>(null);
  const [bulkNotice, setBulkNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [data, states, rules, maint] = await Promise.all([fetchAlerts(250), fetchAlertStates(), fetchSilenceRules(), fetchMaintenanceEvents()]);

      // Build states map
      let stateMap = new Map<string, AlertState>();
      for (const s of states) stateMap.set(s.alert_fingerprint, s);

      // Re-fire detection: check alerts with any persisted state for new firingStartTime
      // This catches acked alerts, investigated alerts, and alerts with stale Jira tickets
      const refired: string[] = [];
      for (const alert of data) {
        const st = stateMap.get(alert.fingerprint);
        if (!st) continue;
        const hasState = st.acknowledged_by || st.investigating_user || st.incident_jira_key;
        if (!hasState) continue;
        const cur = alert.firingStartTime || alert.startedAt || '';
        if (!cur) continue;
        // Compare against the alert firing baseline, not the ticket creation time.
        const stateTime = st.ack_firing_start || (st.investigating_user ? st.investigating_since : '') || '';
        if (stateTime && new Date(cur).getTime() > new Date(stateTime).getTime()) {
          refired.push(alert.fingerprint);
        }
      }
      if (refired.length > 0) {
        await markAlertsUpdated(refired);
        const fresh = await fetchAlertStates();
        stateMap = new Map<string, AlertState>();
        for (const s of fresh) stateMap.set(s.alert_fingerprint, s);
      }

      const activeFingerprints = data
        .filter(alert => alert.status !== 'resolved' && alert.status !== 'ok')
        .map(alert => alert.fingerprint);
      const groups = await syncCustomAlertGroups(activeFingerprints);

      setAlerts(data);
      setAlertStates(stateMap);
      setSilenceRules(rules);
      setMaintenanceEvents(maint);
      setCustomGroups(groups);
      setSelectedFingerprints(prev => {
        const known = new Set(data.map(alert => alert.fingerprint));
        return new Set(Array.from(prev).filter(fp => known.has(fp)));
      });
      setLastUpdated(new Date());
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  }, []);

  const handleSSEEvent = useCallback((event: SSEEvent) => {
    if (event.type === '_reset') {
      load();
      return;
    }

    if (event.type === 'situation_update') {
      setSituationTrigger(prev => prev + 1);
      return;
    }

    if (event.type === 'silence_created' || event.type === 'silence_cancelled') {
      // Refresh silence rules on any change
      fetchSilenceRules().then(rules => setSilenceRules(rules));
      return;
    }

    if (event.type === 'custom_groups_changed') {
      load();
      return;
    }

    setAlertStates(prev => {
      const next = new Map(prev);
      const defaultState = (fp: string): AlertState => ({
        alert_fingerprint: fp, alert_name: '', investigating_user: null,
        investigating_since: null, acknowledged_by: null, acknowledged_at: null,
        ack_firing_start: null, is_updated: 0,
      });

      if (event.fingerprint) {
        const fp = event.fingerprint;
        const existing = next.get(fp) || defaultState(fp);
        switch (event.type) {
          case 'investigate':
            next.set(fp, { ...existing, investigating_user: event.active ? (event.user || null) : null, investigating_since: event.active ? event.timestamp : null });
            break;
          case 'incident_created':
            next.set(fp, { ...existing, incident_jira_key: event.jira_key || null, incident_jira_url: event.jira_url || null, incident_created_by: event.user || null, incident_created_at: event.timestamp || null });
            break;
          case 'escalated':
            next.set(fp, { ...existing, escalated_to: event.escalated_to || null, escalated_by: event.user || null, escalated_at: event.timestamp || null });
            break;
          case 'force_enrich':
            break;
          case 'severity_override':
            next.set(fp, { ...existing, severity_override: event.severity === 'none' ? null : (event.severity || null), severity_override_by: event.user || null });
            break;
          case 'runbook_feedback':
            break;
        }
      }

      if (event.fingerprints) {
        for (const fp of event.fingerprints) {
          const existing = next.get(fp) || defaultState(fp);
          switch (event.type) {
            case 'acknowledge':
              next.set(fp, { ...existing, acknowledged_by: event.user || null, acknowledged_at: event.timestamp || null, is_updated: 0 });
              break;
            case 'unacknowledge':
              next.set(fp, { ...existing, acknowledged_by: null, acknowledged_at: null, ack_firing_start: null, is_updated: 0 });
              break;
            case 'mark_updated':
              next.set(fp, { ...existing,
                acknowledged_by: null, acknowledged_at: null, ack_firing_start: null,
                investigating_user: null, investigating_since: null,
                incident_jira_key: null, incident_jira_url: null,
                incident_created_by: null, incident_created_at: null,
                escalated_to: null, escalated_by: null, escalated_at: null,
                severity_override: null, severity_override_by: null,
                is_updated: 1,
              });
              break;
          }
        }
      }

      return next;
    });
  }, [load]);

  const { connected } = useSSE('/api/alert-states/events', handleSSEEvent);

  useEffect(() => {
    load();
    const interval = setInterval(load, refreshInterval * 1000);
    return () => clearInterval(interval);
  }, [load, refreshInterval]);

  const activeAlerts = useMemo(
    () => alerts.filter(alert => alert.status !== 'resolved' && alert.status !== 'ok'),
    [alerts],
  );
  const selectedAlerts = useMemo(
    () => alerts.filter(alert => selectedFingerprints.has(alert.fingerprint)),
    [alerts, selectedFingerprints],
  );
  const customGroupByFingerprint = useMemo(() => {
    const map = new Map<string, CustomAlertGroup>();
    customGroups.forEach(group => {
      group.fingerprints.forEach(fp => map.set(fp, group));
    });
    return map;
  }, [customGroups]);
  const customGroupNameByFingerprint = useMemo(() => {
    const map = new Map<string, string>();
    customGroups.forEach(group => {
      group.fingerprints.forEach(fp => map.set(fp, group.name));
    });
    return map;
  }, [customGroups]);
  const inferredGroupByFingerprint = useMemo(
    () => buildInferredGroupMembership(activeAlerts),
    [activeAlerts],
  );
  const shouldOfferGroupingForSelection = useMemo(() => {
    if (selectedAlerts.length <= 1) return false;
    const sharedCustomGroup = customGroupByFingerprint.get(selectedAlerts[0].fingerprint);
    if (sharedCustomGroup && selectedAlerts.every(alert => customGroupByFingerprint.get(alert.fingerprint)?.id === sharedCustomGroup.id)) {
      return false;
    }
    const inferredKey = inferredGroupByFingerprint.get(selectedAlerts[0].fingerprint);
    if (inferredKey && selectedAlerts.every(alert => inferredGroupByFingerprint.get(alert.fingerprint) === inferredKey)) {
      return false;
    }
    return true;
  }, [selectedAlerts, customGroupByFingerprint, inferredGroupByFingerprint]);

  function toggleAlertSelection(fingerprint: string) {
    setSelectedFingerprints(prev => {
      const next = new Set(prev);
      if (next.has(fingerprint)) next.delete(fingerprint);
      else next.add(fingerprint);
      return next;
    });
  }

  function setAlertSelection(fingerprints: string[], checked: boolean) {
    setSelectedFingerprints(prev => {
      const next = new Set(prev);
      fingerprints.forEach(fp => {
        if (checked) next.add(fp);
        else next.delete(fp);
      });
      return next;
    });
  }

  function clearAlertSelection() {
    setSelectedFingerprints(new Set());
  }

  async function handleInvestigate(alert: Alert) {
    await toggleInvestigating(alert.fingerprint, alert.name || '');
    load();
  }

  async function handleAcknowledge(alert: Alert) {
    const names: Record<string, string> = { [alert.fingerprint]: alert.name || '' };
    const starts: Record<string, string> = { [alert.fingerprint]: alertStartTime(alert) };
    await acknowledgeAlerts([alert.fingerprint], names, starts);
    load();
  }

  async function handleUnacknowledge(alert: Alert) {
    await unacknowledgeAlerts([alert.fingerprint]);
    load();
  }

  async function handleGroupAcknowledge(fingerprints: string[], names: Record<string, string>, starts: Record<string, string>) {
    await acknowledgeAlerts(fingerprints, names, starts);
    load();
  }

  async function handleGroupResolve(fingerprints: string[]) {
    await resolveAlerts(fingerprints);
    load();
  }

  async function handleGroupUnresolve(fingerprints: string[]) {
    await unresolveAlerts(fingerprints);
    load();
  }

  async function handleBulkAcknowledge() {
    if (selectedAlerts.length === 0) return;
    const names: Record<string, string> = {};
    const starts: Record<string, string> = {};
    selectedAlerts.forEach(alert => {
      names[alert.fingerprint] = alert.name || '';
      starts[alert.fingerprint] = alertStartTime(alert);
    });
    await acknowledgeAlerts(selectedAlerts.map(alert => alert.fingerprint), names, starts);
    setBulkNotice(`Acknowledged ${selectedAlerts.length} alert${selectedAlerts.length === 1 ? '' : 's'}.`);
    setBulkError(null);
    load();
  }

  async function handleBulkResolve() {
    if (selectedAlerts.length === 0) return;
    if (!confirm(`Resolve ${selectedAlerts.length} selected alert${selectedAlerts.length === 1 ? '' : 's'}?`)) return;
    await resolveAlerts(selectedAlerts.map(alert => alert.fingerprint));
    setBulkNotice(`Resolved ${selectedAlerts.length} alert${selectedAlerts.length === 1 ? '' : 's'}.`);
    setBulkError(null);
    load();
  }

  async function handleCreateSharedGroup(name: string, fingerprints: string[]) {
    const result = await createCustomAlertGroup(name, fingerprints);
    if (!result.ok) {
      const errorMessage = result.error || 'Failed to create custom group';
      setBulkError(errorMessage);
      setBulkNotice(null);
      return { ok: false, error: errorMessage };
    }
    setBulkNotice(`Created custom group "${name}".`);
    setBulkError(null);
    setPendingGroupName('');
    setShowCreateGroupModal(false);
    load();
    return { ok: true };
  }

  async function handleRenameSharedGroup(groupId: number, name: string) {
    const result = await renameCustomAlertGroup(groupId, name);
    if (!result.ok || !result.group) {
      const errorMessage = result.error || 'Failed to rename custom group';
      setBulkError(errorMessage);
      setBulkNotice(null);
      return { ok: false, error: errorMessage };
    }
    setBulkNotice(`Renamed custom group to "${result.group.name}".`);
    setBulkError(null);
    load();
    return { ok: true };
  }

  async function handleAddAlertsToSharedGroup(groupId: number, fingerprints: string[]) {
    const result = await addAlertsToCustomAlertGroup(groupId, fingerprints);
    if (!result.ok || !result.group) {
      const errorMessage = result.error || 'Failed to update custom group';
      setBulkError(errorMessage);
      setBulkNotice(null);
      return { ok: false, error: errorMessage };
    }
    setBulkNotice(`Added alerts to custom group "${result.group.name}".`);
    setBulkError(null);
    load();
    return { ok: true };
  }

  async function handleCustomGroupSubmit() {
    if (selectedGroupMode === 'existing') {
      if (!selectedExistingGroupId) {
        return { ok: false, error: 'Select an existing group.' };
      }
      return handleAddAlertsToSharedGroup(
        selectedExistingGroupId,
        selectedAlerts.map(alert => alert.fingerprint),
      );
    }
    return handleCreateSharedGroup(pendingGroupName, selectedAlerts.map(alert => alert.fingerprint));
  }

  async function handleBulkTicketSubmit(data: {
    summary: string;
    description: string;
    classId: string;
    operationalServiceId?: string;
    createGroup: boolean;
    groupName: string;
  }) {
    const fingerprints = selectedAlerts.map(alert => alert.fingerprint);
    if (data.createGroup) {
      const created = await handleCreateSharedGroup(data.groupName, fingerprints);
      if (!created.ok) return { ok: false, error: created.error || 'Failed to create custom group' };
    }

    const result = await createJiraIncident({
      summary: data.summary,
      description: data.description,
      classId: data.classId,
      operationalServiceId: data.operationalServiceId,
      alertLink: 'http://10.177.154.196/command-center',
    });
    if (!result.ok || !result.issueKey) {
      return { ok: false, error: result.error || 'Failed to create incident ticket' };
    }

    const firingStarts = Object.fromEntries(
      selectedAlerts.map(alert => [alert.fingerprint, alert.firingStartTime || alert.startedAt || '']),
    );
    const stateResult = await storeIncidentStateBulk(fingerprints, result.issueKey, result.issueUrl || '', firingStarts);
    if (!stateResult.ok) {
      return { ok: false, error: stateResult.error || 'Ticket created, but not every alert was updated' };
    }

    setBulkNotice(`Created ${result.issueKey} for ${fingerprints.length} selected alert${fingerprints.length === 1 ? '' : 's'}.`);
    setBulkError(null);
    load();
    return { ok: true, issueKey: result.issueKey, issueUrl: result.issueUrl };
  }

  function handleAlertRefresh() {
    load();
    if (selectedAlert) {
      const fresh = alerts.find(a => a.fingerprint === selectedAlert.fingerprint);
      if (fresh) setSelectedAlert(fresh);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted animate-pulse">Loading alerts...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-text-bright">Command Center</h1>
        <div className="flex items-center gap-3">
          <span className={`inline-block w-2 h-2 rounded-full ${connected ? 'bg-green' : 'bg-red/50'}`} title={connected ? 'Live updates connected' : 'Live updates disconnected'} />
          <RefreshControl
            refreshInterval={refreshInterval}
            onRefreshIntervalChange={setRefreshInterval}
            onRefresh={() => { setRefreshing(true); load().finally(() => setTimeout(() => setRefreshing(false), 500)); }}
            refreshing={refreshing}
          />
          <span className="text-xs text-muted">
            {lastUpdated && `Updated ${lastUpdated.toLocaleTimeString()}`}
          </span>
        </div>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-red text-sm">
          {error}
        </div>
      )}

      {bulkError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-red text-sm flex items-center justify-between gap-3">
          <span>{bulkError}</span>
          <button onClick={() => setBulkError(null)} className="text-xs text-red/80 hover:text-red">Dismiss</button>
        </div>
      )}

      {bulkNotice && (
        <div className="bg-green/10 border border-green/30 rounded-lg px-4 py-3 text-green text-sm flex items-center justify-between gap-3">
          <span>{bulkNotice}</span>
          <button onClick={() => setBulkNotice(null)} className="text-xs text-green/80 hover:text-green">Dismiss</button>
        </div>
      )}

      {/* Tab Bar */}
      <div className="flex gap-1 mb-6 bg-zinc-800/50 p-1 rounded-lg w-fit">
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'dashboard' ? 'bg-zinc-700 text-white' : 'text-zinc-400 hover:text-white'
          }`}
        >
          Dashboard
        </button>
        <button
          onClick={() => setActiveTab('alerts')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'alerts' ? 'bg-zinc-700 text-white' : 'text-zinc-400 hover:text-white'
          }`}
        >
          All Alerts
        </button>
        <button
          onClick={() => setActiveTab('knowledge-base')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'knowledge-base' ? 'bg-zinc-700 text-white' : 'text-zinc-400 hover:text-white'
          }`}
        >
          Knowledge Base
        </button>
      </div>

      {(activeTab === 'dashboard' || activeTab === 'alerts') && selectedAlerts.length > 0 && (
        <div className="bg-surface border border-accent/20 rounded-xl px-4 py-3 flex flex-wrap items-center gap-2">
          <span className="text-sm text-text-bright font-medium">{selectedAlerts.length} alerts selected</span>
          <button
            onClick={() => setShowBulkTicketModal(true)}
            className="px-3 py-1.5 rounded-md bg-accent text-bg text-xs font-medium hover:bg-accent-hover transition-colors"
          >
            Create Shared Ticket
          </button>
            <button
              onClick={() => {
                setPendingGroupName(buildSuggestedGroupName(selectedAlerts));
                setSelectedGroupMode('create');
                setSelectedExistingGroupId(customGroups[0]?.id ?? null);
                setShowCreateGroupModal(true);
              }}
            className="px-3 py-1.5 rounded-md border border-border text-xs text-text hover:bg-surface-hover transition-colors"
          >
            Create Custom Group
          </button>
          <button
            onClick={handleBulkAcknowledge}
            className="px-3 py-1.5 rounded-md border border-border text-xs text-green hover:border-green/40 hover:bg-green/10 transition-colors"
          >
            Acknowledge
          </button>
          <button
            onClick={handleBulkResolve}
            className="px-3 py-1.5 rounded-md border border-border text-xs text-orange hover:border-orange/40 hover:bg-orange/10 transition-colors"
          >
            Resolve
          </button>
          <button
            onClick={clearAlertSelection}
            className="ml-auto px-3 py-1.5 rounded-md border border-border text-xs text-muted hover:text-text transition-colors"
          >
            Clear Selection
          </button>
        </div>
      )}

      {/* Tab Content */}
      {activeTab === 'dashboard' && (
        <DashboardView
          alerts={alerts}
          alertStates={alertStates}
          customGroups={customGroups}
          selectedFingerprints={selectedFingerprints}
          loading={false}
          onAlertClick={setSelectedAlert}
          onToggleSelectAlert={toggleAlertSelection}
          onSetSelectedAlerts={setAlertSelection}
          onInvestigate={handleInvestigate}
          onAcknowledge={handleAcknowledge}
          onUnacknowledge={handleUnacknowledge}
          onGroupAcknowledge={handleGroupAcknowledge}
          onGroupResolve={handleGroupResolve}
          onGroupUnresolve={handleGroupUnresolve}
          onForceEnrich={async (fp: string) => { await forceEnrich(fp); load(); }}
          onRefresh={load}
          sseUpdateTrigger={situationTrigger}
          silenceRules={silenceRules}
          onSilenceGroup={async (alertNamePattern, durationSeconds, hostnamePattern) => {
            await createSilenceRule(alertNamePattern, durationSeconds, hostnamePattern);
            load();
          }}
          onCancelSilence={async (ruleId) => {
            await cancelSilenceRule(ruleId);
            load();
          }}
          onRenameCustomGroup={handleRenameSharedGroup}
          onAddSelectedAlertsToCustomGroup={handleAddAlertsToSharedGroup}
        />
      )}
      {activeTab === 'alerts' && (
        <AlertsTableView
          alerts={alerts}
          alertStates={alertStates}
          customGroupByFingerprint={customGroupNameByFingerprint}
          selectedFingerprints={selectedFingerprints}
          loading={false}
          onAlertClick={setSelectedAlert}
          onToggleSelectAlert={toggleAlertSelection}
          onSetSelectedAlerts={setAlertSelection}
        />
      )}
      {activeTab === 'knowledge-base' && <KnowledgeBasePage />}

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onRefresh={handleAlertRefresh}
          alertState={alertStates.get(selectedAlert.fingerprint)}
          onInvestigate={() => handleInvestigate(selectedAlert)}
          onAcknowledge={() => handleAcknowledge(selectedAlert)}
          maintenanceEvents={maintenanceEvents}
        />
      )}

      {showBulkTicketModal && selectedAlerts.length > 0 && (
        <BulkIncidentTicketModal
          alerts={selectedAlerts}
          shouldOfferGrouping={shouldOfferGroupingForSelection}
          defaultGroupName={buildSuggestedGroupName(selectedAlerts)}
          onSubmit={handleBulkTicketSubmit}
          onClose={() => setShowBulkTicketModal(false)}
        />
      )}

        {showCreateGroupModal && selectedAlerts.length > 0 && (
          <CreateCustomGroupModal
            name={pendingGroupName}
            alertCount={selectedAlerts.length}
            existingGroups={customGroups}
            selectedGroupMode={selectedGroupMode}
            selectedExistingGroupId={selectedExistingGroupId}
            onChangeName={setPendingGroupName}
            onChangeGroupMode={setSelectedGroupMode}
            onChangeSelectedExistingGroupId={setSelectedExistingGroupId}
            onClose={() => setShowCreateGroupModal(false)}
            onCreate={handleCustomGroupSubmit}
          />
        )}
    </div>
  );
}

function RefreshControl({ refreshInterval, onRefreshIntervalChange, onRefresh, refreshing }: {
  refreshInterval: number;
  onRefreshIntervalChange: (v: number) => void;
  onRefresh: () => void;
  refreshing: boolean;
}) {
  return (
    <div className="flex items-center border border-border rounded overflow-hidden">
      <button
        onClick={onRefresh}
        className="px-2 py-1.5 text-muted hover:text-accent hover:bg-surface-hover transition-colors border-r border-border"
        title="Refresh now"
      >
        <svg
          className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin-once' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h5M20 20v-5h-5M4.49 15A8 8 0 0019.5 9M19.51 9A8 8 0 004.5 15" />
        </svg>
      </button>
      <select
        value={refreshInterval}
        onChange={e => onRefreshIntervalChange(Number(e.target.value))}
        className="bg-surface px-2 py-1 text-xs text-muted focus:outline-none"
      >
        <option value={5}>5s</option>
        <option value={10}>10s</option>
        <option value={30}>30s</option>
        <option value={60}>1m</option>
        <option value={120}>2m</option>
        <option value={300}>5m</option>
        <option value={600}>10m</option>
      </select>
    </div>
  );
}

function CreateCustomGroupModal({ name, alertCount, existingGroups, selectedGroupMode, selectedExistingGroupId, onChangeName, onChangeGroupMode, onChangeSelectedExistingGroupId, onClose, onCreate }: {
  name: string;
  alertCount: number;
  existingGroups: CustomAlertGroup[];
  selectedGroupMode: 'create' | 'existing';
  selectedExistingGroupId: number | null;
  onChangeName: (value: string) => void;
  onChangeGroupMode: (value: 'create' | 'existing') => void;
  onChangeSelectedExistingGroupId: (value: number | null) => void;
  onClose: () => void;
  onCreate: () => Promise<{ ok: boolean; error?: string }>;
}) {
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  async function handleCreate() {
    if (selectedGroupMode === 'create' && !name.trim()) {
      setError('Enter a group name.');
      return;
    }
    if (selectedGroupMode === 'existing' && !selectedExistingGroupId) {
      setError('Select an existing group.');
      return;
    }
    setSubmitting(true);
    setError('');
    const result = await onCreate();
    setSubmitting(false);
    if (!result.ok) {
      setError(result.error || 'Failed to create custom group.');
      return;
    }
    onClose();
  }

  return (
    <div className="fixed inset-0 z-[110] flex items-start justify-center">
      <div className="absolute inset-0 bg-bg/80 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg mt-[10vh] mx-4 bg-surface border border-border rounded-xl shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div>
            <h3 className="text-base font-semibold text-text-bright">Custom Group</h3>
            <p className="text-xs text-muted mt-1">{alertCount} selected alerts can create a new group or join an existing one.</p>
          </div>
          <button onClick={onClose} className="text-muted hover:text-text text-sm">Close</button>
        </div>
        <div className="p-5 space-y-4">
          {error && (
            <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">{error}</div>
          )}
          <div className="space-y-3">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="radio"
                name="custom-group-mode"
                checked={selectedGroupMode === 'create'}
                onChange={() => onChangeGroupMode('create')}
                className="mt-0.5"
              />
              <span>
                <span className="block text-sm text-text-bright">Create a new custom group</span>
                <span className="block text-xs text-muted mt-1">Use a fresh shared name for this temporary alert grouping.</span>
              </span>
            </label>
            <label className={`flex items-start gap-3 ${existingGroups.length > 0 ? 'cursor-pointer' : 'opacity-50 cursor-not-allowed'}`}>
              <input
                type="radio"
                name="custom-group-mode"
                checked={selectedGroupMode === 'existing'}
                onChange={() => existingGroups.length > 0 && onChangeGroupMode('existing')}
                disabled={existingGroups.length === 0}
                className="mt-0.5"
              />
              <span>
                <span className="block text-sm text-text-bright">Add alerts to an existing custom group</span>
                <span className="block text-xs text-muted mt-1">Reuse an existing shared group instead of creating another one.</span>
              </span>
            </label>
          </div>
          {selectedGroupMode === 'create' ? (
            <div>
              <label className="text-[10px] text-muted block mb-1">Group Name</label>
              <input
                value={name}
                onChange={(e) => onChangeName(e.target.value)}
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
                placeholder="Enter a shared temporary group name"
              />
            </div>
          ) : (
            <div>
              <label className="text-[10px] text-muted block mb-1">Existing Groups</label>
              <select
                value={selectedExistingGroupId ?? ''}
                onChange={(e) => onChangeSelectedExistingGroupId(e.target.value ? Number(e.target.value) : null)}
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
              >
                <option value="">Select a group</option>
                {existingGroups.map(group => (
                  <option key={group.id} value={group.id}>
                    {group.name} ({group.active_count})
                  </option>
                ))}
              </select>
            </div>
          )}
          <div className="text-xs text-muted">
            This group will be visible to all users and will be removed automatically once all member alerts clear.
          </div>
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-md border border-border text-sm text-muted hover:text-text transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleCreate}
              disabled={submitting || (selectedGroupMode === 'create' ? !name.trim() : !selectedExistingGroupId)}
              className="px-4 py-2 rounded-md bg-accent text-bg text-sm font-medium hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Saving...' : selectedGroupMode === 'create' ? 'Create Group' : 'Add To Group'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Alert Detail Modal ── */

function AlertDetailModal({ alert, onClose, onRefresh, alertState, onInvestigate, onAcknowledge, maintenanceEvents = [] }: {
  alert: Alert;
  onClose: () => void;
  onRefresh: () => void;
  alertState?: AlertState;
  onInvestigate?: () => void;
  onAcknowledge?: () => void;
  maintenanceEvents?: MaintenanceEvent[];
}) {
  const enrichment = parseAIEnrichment(alert.note);
  const host = alert.hostName || alert.hostname || 'Unknown';
  const source = getSourceLabel(alert);

  // Close on Escape
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, [onClose]);

  // Prevent background scroll
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = ''; };
  }, []);

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-bg/80 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Panel */}
      <div className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto mt-[5vh] mx-4 bg-surface border border-border rounded-xl shadow-2xl">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 z-10 w-8 h-8 flex items-center justify-center rounded-md text-muted hover:text-text hover:bg-surface-hover transition-colors"
        >
          &times;
        </button>

        <div className="p-6 space-y-5">
          {/* Header */}
          <div>
            <h2 className="text-lg font-bold text-text-bright pr-8">{alert.name}</h2>
            <div className="flex flex-wrap gap-3 mt-2 text-xs text-muted">
              <span>Host: <span className="text-text font-mono">{host}</span></span>
              <span>Source: <span className="text-text">{source}</span></span>
              <span>Status: <span className="text-text">{alert.status}</span></span>
              <span>Started: <span className="text-text">{timeAgo(alertStartTime(alert))}</span></span>
              {alert.lastReceived && (
                <span>Received: <span className="text-text">{timeAgo(alert.lastReceived)}</span></span>
              )}
              {alert.fingerprint && (
                <span>FP: <span className="text-text font-mono">{alert.fingerprint.substring(0, 16)}...</span></span>
              )}
            </div>
          </div>

          {/* Actions */}
          <AlertActions alert={alert} enrichment={enrichment} onAlertChanged={onRefresh} alertState={alertState} onInvestigate={onInvestigate} onAcknowledge={onAcknowledge} maintenanceEvents={maintenanceEvents} />

          {/* Description / Metric Values */}
          {alert.description && alert.description !== alert.name && (
            <div className="bg-bg/60 border border-border rounded-lg px-4 py-3">
              <h3 className="text-xs font-medium text-muted mb-1">Alert Details</h3>
              <p className="text-sm text-text-bright font-mono">{alert.description}</p>
            </div>
          )}

          {/* AI Analysis */}
          {enrichment ? (
            <div className="space-y-4">
              <h3 className="text-base font-semibold text-accent">AI Analysis</h3>

              {/* Summary + Metrics */}
              <div className="bg-bg/40 border border-accent/20 rounded-lg px-4 py-3">
                <div className="text-sm text-text-bright mb-3">{enrichment.summary}</div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <ModalMetricBox
                    label="Assessed Severity"
                    value={enrichment.assessed_severity}
                    className={severityColor(enrichment.assessed_severity)}
                  />
                  <ModalMetricBox
                    label="Original Severity"
                    value={alert.severity || 'unknown'}
                    className="text-muted"
                  />
                  <ModalMetricBox
                    label="Noise Score"
                    value={`${enrichment.noise_score}/10`}
                    className={enrichment.noise_score >= 7 ? 'text-muted' : enrichment.noise_score >= 4 ? 'text-yellow' : 'text-green'}
                  />
                  <ModalMetricBox
                    label="Dedup"
                    value={enrichment.dedup_assessment || 'N/A'}
                    className={enrichment.dedup_assessment === 'DUPLICATE' ? 'text-orange' : enrichment.dedup_assessment === 'CORRELATED' ? 'text-yellow' : 'text-green'}
                  />
                </div>
              </div>

              {/* Detail Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <ModalDetailCard title="Likely Cause" content={enrichment.likely_cause} icon="?" />
                <ModalDetailCard title="Remediation" content={enrichment.remediation} icon="!" />
                <ModalDetailCard title="Impact Scope" content={enrichment.impact_scope} icon="~" />
                <ModalDetailCard title="Noise Reason" content={enrichment.noise_reason} icon="#" />
              </div>

              {enrichment.dedup_reason && (
                <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
                  <h4 className="text-xs font-medium text-muted mb-1">Deduplication Reason</h4>
                  <div className="text-sm text-text">{enrichment.dedup_reason}</div>
                </div>
              )}

              {/* Noise Assessment Bar */}
              <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
                <h4 className="text-xs font-medium text-muted mb-2">Noise Assessment</h4>
                <div className="flex items-center gap-4">
                  <div className="flex-1">
                    <div className="w-full bg-border rounded-full h-2.5">
                      <div
                        className={`h-2.5 rounded-full transition-all ${
                          enrichment.noise_score >= 7 ? 'bg-muted' :
                          enrichment.noise_score >= 4 ? 'bg-yellow' : 'bg-green'
                        }`}
                        style={{ width: `${enrichment.noise_score * 10}%` }}
                      />
                    </div>
                    <div className="flex justify-between text-[10px] text-muted mt-1">
                      <span>Actionable</span>
                      <span>Likely Noise</span>
                    </div>
                  </div>
                  <div className={`text-xl font-bold font-mono ${
                    enrichment.noise_score >= 7 ? 'text-muted' :
                    enrichment.noise_score >= 4 ? 'text-yellow' : 'text-green'
                  }`}>
                    {enrichment.noise_score}/10
                  </div>
                </div>
              </div>

              {enrichment.llm_model && (
                <div className="text-xs text-muted">
                  Analyzed by: {enrichment.llm_model}
                </div>
              )}
            </div>
          ) : (
            <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
              <div className="text-muted text-sm">
                AI enrichment not yet available. The enricher processes alerts every 60 seconds.
              </div>
            </div>
          )}

          {/* SRE Feedback */}
          <ModalFeedbackPanel
            fingerprint={alert.fingerprint}
            enrichment={enrichment}
            onFeedbackSubmitted={onRefresh}
            alertName={alert.name || ''}
            hostname={alert.hostName || alert.hostname || ''}
          />

          {/* Runbook & Remediation */}
          <RunbookPanel alert={alert} />

          {/* Tags */}
          {alert.tags && Array.isArray(alert.tags) && alert.tags.length > 0 && (
            <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
              <h4 className="text-xs font-medium text-muted mb-2">Tags</h4>
              <div className="flex flex-wrap gap-2">
                {alert.tags.map((tag, i) => (
                  <span key={i} className="badge bg-accent/10 border-accent/30 text-accent">
                    {tag.tag || tag.name}: {tag.value}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Open full page link */}
          <div className="flex justify-between items-center pt-2 border-t border-border">
            <a
              href={`/portal/alerts/${alert.fingerprint}`}
              className="text-xs text-accent hover:text-accent-hover transition-colors"
            >
              Open full page &rarr;
            </a>
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

function ModalMetricBox({ label, value, className }: { label: string; value: string; className?: string }) {
  return (
    <div>
      <div className="text-[10px] text-muted uppercase tracking-wider mb-0.5">{label}</div>
      <div className={`text-sm font-semibold uppercase ${className || ''}`}>{value}</div>
    </div>
  );
}

function ModalDetailCard({ title, content, icon }: { title: string; content: string; icon: string }) {
  if (!content) return null;
  return (
    <div className="bg-bg/40 border border-border rounded-lg px-4 py-3">
      <div className="flex items-start gap-2">
        <div className="w-6 h-6 rounded bg-accent/10 border border-accent/30 flex items-center justify-center text-accent font-mono text-xs flex-shrink-0">
          {icon}
        </div>
        <div className="min-w-0">
          <h4 className="text-xs font-medium text-muted mb-0.5">{title}</h4>
          <div className="text-sm text-text">{content}</div>
        </div>
      </div>
    </div>
  );
}

function ModalFeedbackPanel({
  fingerprint,
  enrichment,
  onFeedbackSubmitted,
  alertName,
  hostname,
}: {
  fingerprint: string;
  enrichment: { assessed_severity: string; noise_score: number } | null;
  onFeedbackSubmitted?: () => void;
  alertName: string;
  hostname: string;
}) {
  const [rating, setRating] = useState<'positive' | 'negative' | null>(null);
  const [correctedSeverity, setCorrectedSeverity] = useState('');
  const [correctedNoise, setCorrectedNoise] = useState('');
  const [causeCorrection, setCauseCorrection] = useState('');
  const [remediationCorrection, setRemediationCorrection] = useState('');
  const [comment, setComment] = useState('');
  const [sreUser] = useState(() => getClientUsername() || '');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [justSubmitted, setJustSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState(false);

  async function handleSubmit() {
    if (!rating) return;
    setSubmitting(true);
    setSubmitError(false);

    const computedRating = rating === 'negative' && (correctedSeverity || correctedNoise) ? 'correction' : rating;
    const combinedComment = [
      comment,
      causeCorrection ? `Cause correction: ${causeCorrection}` : '',
      remediationCorrection ? `Remediation correction: ${remediationCorrection}` : '',
    ].filter(Boolean).join('\n').slice(0, 2000) || undefined;

    // Submit to new API and structured feedback in parallel
    const [result] = await Promise.all([
      submitSREFeedback({
        fingerprint,
        alert_name: alertName,
        rating: computedRating,
        corrected_severity: correctedSeverity || undefined,
        corrected_noise: correctedNoise ? parseInt(correctedNoise, 10) : undefined,
        comment: combinedComment,
      }),
      submitStructuredFeedback({
        alert_name: alertName,
        hostname: hostname,
        service: '',
        severity_correction: correctedSeverity || '',
        cause_correction: causeCorrection || '',
        remediation_correction: remediationCorrection || '',
        full_text: comment || '',
      }),
    ]);
    setSubmitting(false);
    if (result) {
      setSubmitted(true);
      setJustSubmitted(true);
      setRating(null);
      setCorrectedSeverity('');
      setCorrectedNoise('');
      setCauseCorrection('');
      setRemediationCorrection('');
      setComment('');
      if (onFeedbackSubmitted) {
        setTimeout(onFeedbackSubmitted, 500);
      }
    } else {
      setSubmitError(true);
    }
  }

  return (
    <div className="bg-bg/40 border border-accent/20 rounded-lg px-4 py-3">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-semibold text-accent">SRE Feedback</h4>
        <span className="text-[10px] text-muted">Help improve AI analysis</span>
      </div>

      {justSubmitted && (
        <div className="bg-green/10 border border-green/30 rounded-lg px-3 py-2 mb-3">
          <div className="flex items-start gap-2">
            <span className="text-green text-sm leading-none">{'\u2713'}</span>
            <div>
              <div className="text-xs font-medium text-green">Feedback submitted</div>
              <div className="text-[10px] text-muted mt-0.5">
                Will be ingested on next enricher cycle (~60s).
              </div>
            </div>
          </div>
        </div>
      )}

      {submitError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-3 py-2 mb-3">
          <div className="text-xs text-red">Failed to submit. Please try again.</div>
        </div>
      )}

      <div className="space-y-3">
          <div>
            <div className="text-[10px] text-muted mb-1.5">Is this analysis accurate?</div>
            <div className="flex gap-2">
              <button
                onClick={() => setRating('positive')}
                className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
                  rating === 'positive'
                    ? 'border-green bg-green/10 text-green'
                    : 'border-border text-muted hover:border-green/50 hover:text-green'
                }`}
              >
                &#x2713; Accurate
              </button>
              <button
                onClick={() => setRating('negative')}
                className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
                  rating === 'negative'
                    ? 'border-red bg-red/10 text-red'
                    : 'border-border text-muted hover:border-red/50 hover:text-red'
                }`}
              >
                &#x2717; Needs correction
              </button>
            </div>
          </div>

          {rating === 'negative' && (
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] text-muted block mb-1">Correct severity</label>
                <select
                  value={correctedSeverity}
                  onChange={(e) => setCorrectedSeverity(e.target.value)}
                  className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
                >
                  <option value="">No change ({enrichment?.assessed_severity || 'unknown'})</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="warning">Warning</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted block mb-1">Correct noise score</label>
                <select
                  value={correctedNoise}
                  onChange={(e) => setCorrectedNoise(e.target.value)}
                  className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
                >
                  <option value="">No change ({enrichment?.noise_score ?? '?'}/10)</option>
                  {[1,2,3,4,5,6,7,8,9,10].map(n => (
                    <option key={n} value={n}>{n}/10 {n <= 3 ? '(actionable)' : n >= 7 ? '(noise)' : ''}</option>
                  ))}
                </select>
              </div>
            </div>
          )}

          {rating === 'negative' && (
            <div className="space-y-2">
              <div>
                <label className="text-[10px] text-muted block mb-1">Correct cause (what&apos;s actually wrong?)</label>
                <textarea
                  value={causeCorrection}
                  onChange={(e) => setCauseCorrection(e.target.value)}
                  maxLength={300}
                  rows={2}
                  placeholder='e.g. "This is expected during monthly batch processing"'
                  className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-y"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted block mb-1">Correct remediation (what should be done?)</label>
                <textarea
                  value={remediationCorrection}
                  onChange={(e) => setRemediationCorrection(e.target.value)}
                  maxLength={300}
                  rows={2}
                  placeholder='e.g. "No action needed, auto-resolves after batch completes"'
                  className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-y"
                />
              </div>
            </div>
          )}

          {rating && (
            <div>
              <label className="text-[10px] text-muted block mb-1">
                {rating === 'positive' ? 'Notes (optional)' : 'Additional notes'}
              </label>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                maxLength={500}
                rows={2}
                placeholder={rating === 'positive'
                  ? 'Additional context...'
                  : 'Any other context for future enrichments'
                }
                className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-y"
              />
            </div>
          )}

          {rating && (
            <div className="flex items-end gap-2">
              {sreUser && <span className="text-[10px] text-muted py-1.5">as {sreUser}</span>}
              <button
                onClick={handleSubmit}
                disabled={submitting || !rating}
                className="px-4 py-1.5 rounded-md bg-accent text-bg font-medium text-xs hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? 'Submitting...' : 'Submit'}
              </button>
            </div>
          )}
        </div>
    </div>
  );
}

function AlertActions({ alert, enrichment, onAlertChanged, alertState, onInvestigate, onAcknowledge, maintenanceEvents = [] }: {
  alert: Alert;
  enrichment: AIEnrichment | null;
  onAlertChanged: () => void;
  alertState?: AlertState;
  onInvestigate?: () => void;
  onAcknowledge?: () => void;
  maintenanceEvents?: MaintenanceEvent[];
}) {
  const [resolving, setResolving] = useState(false);
  const [resolved, setResolved] = useState(alert.status === 'resolved' || alert.status === 'ok');
  const [unresolving, setUnresolving] = useState(false);
  const [showSilenceMenu, setShowSilenceMenu] = useState(false);
  const [silencing, setSilencing] = useState(false);
  const [silenced, setSilenced] = useState<string | null>(null);
  const [silenceError, setSilenceError] = useState(false);
  const [showIncidentForm, setShowIncidentForm] = useState(false);
  const [incidentResult, setIncidentResult] = useState<{ key: string; url: string } | null>(null);
  const [showIncidentWizard, setShowIncidentWizard] = useState(false);
  const [showEscalation, setShowEscalation] = useState(false);
  const [escalationType, setEscalationType] = useState<'team' | 'user'>('team');
  const [escalationTarget, setEscalationTarget] = useState('');
  const [escalationMessage, setEscalationMessage] = useState('');
  const [escalating, setEscalating] = useState(false);
  const [escalated, setEscalated] = useState(false);
  const [escalationError, setEscalationError] = useState('');
  const [teams, setTeams] = useState<{id: string; name: string}[]>([]);
  const [users, setUsers] = useState<{id: string; name: string; email: string}[]>([]);

  const host = alert.hostName || alert.hostname || '';
  const registryMatch = detectRegistryFromAlert(alert.name, host, alert.description);
  const registryMailto = registryMatch && registryMatch.operator.contacts[0]
    ? buildRegistryMailto(registryMatch.operator, registryMatch.operator.contacts[0], {
        alertName: alert.name,
        description: alert.description,
        startTime: alertStartTime(alert),
      })
    : null;

  // Find maintenance events matching this alert's registry operator
  const matchedMaintenance = registryMatch
    ? maintenanceEvents.filter(m => {
        const ops = matchMaintenanceToOperators(m.vendor, m.title);
        return ops.includes(registryMatch.operator.id);
      })
    : [];

  async function handleResolve() {
    if (!confirm('Resolve this alert? It will be marked as resolved in Keep.')) return;
    setResolving(true);
    const ok = await resolveAlert(alert.fingerprint);
    setResolving(false);
    if (ok) {
      setResolved(true);
      onAlertChanged();
    }
  }

  async function handleUnresolve() {
    if (!confirm('Unresolve this alert? It will be marked as firing again.')) return;
    setUnresolving(true);
    const ok = await unresolveAlert(alert.fingerprint);
    setUnresolving(false);
    if (ok) {
      setResolved(false);
      onAlertChanged();
    }
  }

  async function handleSilence(seconds: number) {
    setSilencing(true);
    setShowSilenceMenu(false);
    setSilenceError(false);
    const ok = await silenceAlert(alert.name, seconds, host || undefined);
    setSilencing(false);
    if (ok) {
      const label = seconds >= 86400 ? '24h' : seconds >= 28800 ? '8h' : seconds >= 14400 ? '4h' : seconds >= 3600 ? '1h' : '30m';
      setSilenced(label);
    } else {
      setSilenceError(true);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {/* Status Dropdown (Acknowledge, Resolve, Silence, Investigate) */}
        <div className="relative">
          <button
            onClick={() => setShowSilenceMenu(!showSilenceMenu)}
            className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all inline-flex items-center gap-1 ${
              showSilenceMenu
                ? 'border-accent/40 bg-accent/10 text-accent'
                : 'border-border text-muted hover:border-accent/50 hover:text-accent hover:bg-accent/5'
            }`}
          >
            Status
            <svg className="w-3 h-3 opacity-60" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" /></svg>
          </button>
          {showSilenceMenu && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setShowSilenceMenu(false)} />
              <div className="absolute top-full left-0 mt-1 bg-surface border border-border rounded-lg shadow-xl z-20 py-1 min-w-[200px]">
                {/* Acknowledge */}
                {onAcknowledge && !alertState?.acknowledged_by && (
                  <button
                    onClick={() => { onAcknowledge(); setShowSilenceMenu(false); }}
                    className="w-full text-left px-3 py-2 text-xs text-text hover:bg-surface-hover transition-colors flex items-center gap-2"
                  >
                    <svg className="w-3 h-3 text-green" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    Acknowledge
                  </button>
                )}
                {alertState?.acknowledged_by && (
                  <div className="px-3 py-2 text-xs text-green flex items-center gap-2">
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    Acked by {alertState.acknowledged_by}
                  </div>
                )}

                {/* Resolve / Unresolve */}
                {resolved ? (
                  <button
                    onClick={() => { handleUnresolve(); setShowSilenceMenu(false); }}
                    disabled={unresolving}
                    className="w-full text-left px-3 py-2 text-xs text-yellow hover:bg-surface-hover transition-colors flex items-center gap-2 disabled:opacity-60"
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    {unresolving ? 'Unresolving...' : 'Unresolve'}
                  </button>
                ) : (
                  <button
                    onClick={() => { handleResolve(); setShowSilenceMenu(false); }}
                    disabled={resolving}
                    className="w-full text-left px-3 py-2 text-xs text-text hover:bg-surface-hover transition-colors flex items-center gap-2 disabled:opacity-60"
                  >
                    <svg className="w-3 h-3 text-green" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    {resolving ? 'Resolving...' : 'Resolve'}
                  </button>
                )}

                {/* Investigate */}
                {onInvestigate && (
                  <button
                    onClick={() => { onInvestigate(); setShowSilenceMenu(false); }}
                    className={`w-full text-left px-3 py-2 text-xs hover:bg-surface-hover transition-colors flex items-center gap-2 ${
                      alertState?.investigating_user ? 'text-blue' : 'text-text'
                    }`}
                  >
                    <svg className="w-3 h-3 text-blue" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    {alertState?.investigating_user ? `Investigating (${alertState.investigating_user})` : 'Investigate'}
                  </button>
                )}

                {/* Silence durations */}
                <div className="border-t border-border mt-1 pt-1">
                  <div className="px-3 py-1 text-[10px] text-muted uppercase tracking-wider">Silence</div>
                  {silenced ? (
                    <div className="px-3 py-2 text-xs text-yellow flex items-center gap-2">
                      Silenced ({silenced})
                    </div>
                  ) : (
                    [
                      { label: '30 minutes', seconds: 1800 },
                      { label: '1 hour', seconds: 3600 },
                      { label: '4 hours', seconds: 14400 },
                      { label: '8 hours', seconds: 28800 },
                      { label: '24 hours', seconds: 86400 },
                    ].map(opt => (
                      <button
                        key={opt.seconds}
                        onClick={() => { handleSilence(opt.seconds); setShowSilenceMenu(false); }}
                        disabled={silencing}
                        className="w-full text-left px-3 py-1.5 text-xs text-text hover:bg-surface-hover transition-colors pl-6"
                      >
                        {opt.label}
                      </button>
                    ))
                  )}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Create Ticket (Jira) */}
        {incidentResult ? (
          <a
            href={incidentResult.url}
            target="_blank"
            rel="noopener noreferrer"
            className="px-3 py-1.5 rounded-md border border-accent/40 bg-accent/10 text-accent text-xs font-medium hover:bg-accent/20 transition-colors"
          >
            {incidentResult.key} &uarr;
          </a>
        ) : (
          <button
            onClick={() => setShowIncidentForm(!showIncidentForm)}
            className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
              showIncidentForm
                ? 'border-accent/40 bg-accent/10 text-accent'
                : 'border-border text-muted hover:border-accent/50 hover:text-accent hover:bg-accent/5'
            }`}
          >
            Create Ticket
          </button>
        )}

        {/* Create Incident (webhook + statuspage) */}
        <button
          onClick={() => setShowIncidentWizard(!showIncidentWizard)}
          className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
            showIncidentWizard
              ? 'border-orange/40 bg-orange/10 text-orange'
              : 'border-border text-muted hover:border-orange/50 hover:text-orange hover:bg-orange/5'
          }`}
        >
          Create Incident
        </button>

        {/* Escalate (Grafana IRM) */}
        <button
          onClick={() => {
            setShowEscalation(!showEscalation);
            if (!showEscalation && teams.length === 0) {
              fetchEscalationTeams().then(setTeams);
              fetchEscalationUsers().then(setUsers);
            }
          }}
          disabled={escalated}
          className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all inline-flex items-center gap-1 ${
            escalated
              ? 'border-green/40 bg-green/10 text-green cursor-default'
              : showEscalation
                ? 'border-red/40 bg-red/10 text-red'
                : 'border-border text-muted hover:border-red/50 hover:text-red hover:bg-red/5'
          }`}
        >
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          {escalated ? '✓ Escalated' : 'Escalate'}
        </button>

        {/* Contact Registry */}
        {registryMailto && (
          <a
            href={registryMailto}
            className="px-3 py-1.5 rounded-md border border-blue/30 text-blue text-xs font-medium hover:bg-blue/10 hover:border-blue/50 transition-all inline-flex items-center gap-1"
            title={`Email ${registryMatch!.operator.name}`}
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            Contact {registryMatch!.operator.name.length > 20
              ? registryMatch!.operator.name.substring(0, 20) + '...'
              : registryMatch!.operator.name}
          </a>
        )}

        {/* Maintenance Active */}
        {matchedMaintenance.length > 0 && matchedMaintenance.slice(0, 2).map(m => (
          <a
            key={m.id}
            href={m.permalink}
            target="_blank"
            rel="noopener noreferrer"
            className="px-3 py-1.5 rounded-md border border-yellow/30 bg-yellow/10 text-yellow text-xs font-medium hover:bg-yellow/20 transition-all inline-flex items-center gap-1"
            title={m.title}
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Maint: {m.title.length > 30 ? m.title.substring(0, 30) + '...' : m.title}
            {m.end_time && ` until ${new Date(m.end_time).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })}`}
          </a>
        ))}

      </div>

      {silenceError && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">
          Failed to create silence rule. Check Keep maintenance API.
        </div>
      )}

      {/* Incident Form */}
      {showIncidentForm && !incidentResult && (
        <IncidentForm
          alert={alert}
          enrichment={enrichment}
          onCreated={(key, url) => {
            setIncidentResult({ key, url });
            setShowIncidentForm(false);
          }}
          onCancel={() => setShowIncidentForm(false)}
        />
      )}

      {/* Incident Wizard (webhook + statuspage) */}
      {showIncidentWizard && (
        <IncidentWizard
          alert={alert}
          onClose={() => setShowIncidentWizard(false)}
        />
      )}

      {/* Escalation Form */}
      {showEscalation && !escalated && (
        <div className="bg-surface border border-red/20 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium text-red">Escalate via Grafana IRM</h4>
            <button onClick={() => setShowEscalation(false)} className="text-muted hover:text-text text-xs">✕</button>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => { setEscalationType('team'); setEscalationTarget(''); }}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                escalationType === 'team' ? 'bg-red/10 text-red border border-red/30' : 'text-muted border border-border hover:text-text'
              }`}
            >Team</button>
            <button
              onClick={() => { setEscalationType('user'); setEscalationTarget(''); }}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                escalationType === 'user' ? 'bg-red/10 text-red border border-red/30' : 'text-muted border border-border hover:text-text'
              }`}
            >User</button>
          </div>
          <select
            value={escalationTarget}
            onChange={e => setEscalationTarget(e.target.value)}
            className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text focus:outline-none focus:ring-1 focus:ring-red/50"
          >
            <option value="">Select {escalationType}...</option>
            {escalationType === 'team'
              ? teams.map(t => <option key={t.id} value={t.id}>{t.name}</option>)
              : users.map(u => <option key={u.id} value={u.id}>{u.name} ({u.email})</option>)
            }
          </select>
          <textarea
            value={escalationMessage}
            onChange={e => setEscalationMessage(e.target.value)}
            placeholder="Additional context (optional)"
            rows={2}
            className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-red/50 resize-none"
          />
          {escalationError && (
            <div className="text-xs text-red bg-red/10 border border-red/20 rounded px-2 py-1">{escalationError}</div>
          )}
          <button
            onClick={async () => {
              if (!escalationTarget) return;
              setEscalating(true);
              setEscalationError('');
              const host = alert.hostName || alert.hostname || '';
              const result = await escalateAlert({
                team_id: escalationType === 'team' ? escalationTarget : undefined,
                user_ids: escalationType === 'user' ? [escalationTarget] : undefined,
                alert_name: alert.name || 'Unknown',
                severity: alert.severity || 'unknown',
                hostname: host,
                message: escalationMessage,
              });
              setEscalating(false);
              if (result.success) {
                const escalatedToName = escalationType === 'team'
                  ? (teams.find(t => t.id === escalationTarget)?.name || escalationTarget)
                  : (users.find(u => u.id === escalationTarget)?.name || escalationTarget);
                try {
                  await storeEscalationState(alert.fingerprint, escalatedToName);
                } catch {
                  // Best-effort — escalation was already sent
                }
                setEscalated(true);
                setShowEscalation(false);
              } else {
                setEscalationError(result.error || 'Escalation failed');
              }
            }}
            disabled={!escalationTarget || escalating}
            className="w-full px-3 py-2 rounded-md bg-red/80 hover:bg-red text-white text-xs font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {escalating ? 'Sending...' : 'Send Escalation'}
          </button>
        </div>
      )}
    </div>
  );
}

const SEVERITY_CLASS_MAP: Record<string, string> = {
  critical: '11227',
  high: '11228',
  warning: '11229',
  low: '11230',
  info: '11230',
};

function detectService(alertName: string, hostname: string): string {
  const text = `${alertName} ${hostname}`.toLowerCase();
  if (text.includes('ascio')) return '11231';
  if (text.includes('enom')) return '11232';
  if (text.includes('opensrs')) return '11233';
  if (text.includes('hover')) return '11234';
  if (text.includes('hosted') && text.includes('email')) return '11235';
  if (text.includes('exacthosting')) return '11236';
  if (text.includes('trs')) return '11239';
  return '11237';
}

function IncidentForm({ alert, enrichment, onCreated, onCancel }: {
  alert: Alert;
  enrichment: AIEnrichment | null;
  onCreated: (key: string, url: string) => void;
  onCancel: () => void;
}) {
  const host = alert.hostName || alert.hostname || '';
  const sev = enrichment?.assessed_severity || 'unknown';

  const defaultDesc = [
    enrichment?.summary,
    enrichment?.likely_cause ? `Likely Cause: ${enrichment.likely_cause}` : null,
    enrichment?.impact_scope ? `Impact: ${enrichment.impact_scope}` : null,
    `Host: ${host}`,
    `Source: ${getSourceLabel(alert)}`,
    alert.description && alert.description !== alert.name ? `Details: ${alert.description}` : null,
  ].filter(Boolean).join('\n\n');

  const [summary, setSummary] = useState(host ? `${host} | ${alert.name}` : alert.name || 'Unknown Alert');
  const [description, setDescription] = useState(defaultDesc);
  const [classId, setClassId] = useState('11230');
  const [serviceId, setServiceId] = useState(detectService(alert.name, host));
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [pastedImages, setPastedImages] = useState<{ data: string; filename: string; preview: string }[]>([]);

  function handlePaste(e: React.ClipboardEvent) {
    const items = e.clipboardData?.items;
    if (!items) return;
    for (let i = 0; i < items.length; i++) {
      if (items[i].type.startsWith('image/')) {
        e.preventDefault();
        const file = items[i].getAsFile();
        if (!file) continue;
        const reader = new FileReader();
        reader.onload = () => {
          const dataUrl = reader.result as string;
          const base64 = dataUrl.split(',')[1];
          const ext = file.type.split('/')[1] || 'png';
          const filename = `screenshot_${Date.now()}.${ext}`;
          setPastedImages(prev => [...prev, { data: base64, filename, preview: dataUrl }]);
        };
        reader.readAsDataURL(file);
        break;
      }
    }
  }

  function removeImage(idx: number) {
    setPastedImages(prev => prev.filter((_, i) => i !== idx));
  }

  async function handleSubmit() {
    if (!summary.trim()) return;
    setSubmitting(true);
    setError('');

    const result = await createJiraIncident({
      summary: summary.trim(),
      description: description.trim(),
      classId,
      operationalServiceId: serviceId || undefined,
      alertLink: `http://10.177.154.196/portal/alerts/${alert.fingerprint}`,
      attachments: pastedImages.map(({ data, filename }) => ({ data, filename })),
    });

    setSubmitting(false);
    if (result.ok && result.issueKey) {
      try {
        await storeIncidentState(
          alert.fingerprint,
          result.issueKey,
          result.issueUrl || '',
          alert.firingStartTime || alert.startedAt || '',
        );
      } catch {
        // Best-effort — incident was already created in Jira
      }
      try {
        await fetch('/api/alert-states/investigate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fingerprint: alert.fingerprint }),
        });
      } catch {}
      onCreated(result.issueKey, result.issueUrl || '');
    } else {
      setError(result.error || 'Failed to create incident');
    }
  }

  return (
    <div className="bg-bg/60 border border-accent/20 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-accent">Create Ticket (OCCIR)</h4>
        <button onClick={onCancel} className="text-muted hover:text-text text-xs transition-colors">Cancel</button>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">{error}</div>
      )}

      <div>
        <label className="text-[10px] text-muted block mb-1">Summary</label>
        <input
          value={summary}
          onChange={(e) => setSummary(e.target.value)}
          className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
        />
      </div>

      <div>
        <label className="text-[10px] text-muted block mb-1">Description <span className="text-muted/60">(paste screenshots here)</span></label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          onPaste={handlePaste}
          rows={4}
          className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none resize-y"
        />
        {pastedImages.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-2">
            {pastedImages.map((img, idx) => (
              <div key={idx} className="relative group">
                <img
                  src={img.preview}
                  alt={img.filename}
                  className="h-16 w-auto rounded border border-border object-cover"
                />
                <button
                  onClick={() => removeImage(idx)}
                  className="absolute -top-1.5 -right-1.5 w-4 h-4 bg-red text-bg rounded-full text-[10px] leading-none flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  x
                </button>
                <div className="text-[9px] text-muted truncate max-w-[80px] mt-0.5">{img.filename}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-[10px] text-muted block mb-1">Class</label>
          <select
            value={classId}
            onChange={(e) => setClassId(e.target.value)}
            className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
          >
            <option value="11230">Class IV - Informational</option>
            <option value="11229">Class III - Minor</option>
            <option value="11228">Class II - Major</option>
            <option value="11227">Class I - Critical</option>
          </select>
        </div>
        <div>
          <label className="text-[10px] text-muted block mb-1">Operational Service</label>
          <select
            value={serviceId}
            onChange={(e) => setServiceId(e.target.value)}
            className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text focus:border-accent focus:outline-none"
          >
            <option value="11231">Ascio</option>
            <option value="11232">Enom</option>
            <option value="11233">OpenSRS</option>
            <option value="11234">Hover</option>
            <option value="11235">Hosted Email</option>
            <option value="11236">ExactHosting</option>
            <option value="11237">Infrastructure</option>
            <option value="11239">TRS</option>
          </select>
        </div>
      </div>

      <div className="flex justify-end gap-2">
        <button
          onClick={onCancel}
          className="px-3 py-1.5 rounded-md border border-border text-muted text-xs hover:text-text transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={handleSubmit}
          disabled={submitting || !summary.trim()}
          className="px-4 py-1.5 rounded-md bg-accent text-bg font-medium text-xs hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {submitting ? (pastedImages.length > 0 ? 'Creating & uploading...' : 'Creating...') : 'Create Ticket'}
        </button>
      </div>
    </div>
  );
}

function RunbookPanel({ alert }: { alert: Alert }) {
  const [matches, setMatches] = useState<RunbookEntry[]>([]);
  const [loadingMatches, setLoadingMatches] = useState(true);
  const [remediation, setRemediation] = useState('');
  const [sreUser] = useState(() => getClientUsername() || '');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState(false);
  const [votes, setVotes] = useState<Map<string, 'up' | 'down'>>(new Map());
  const [showAttachPicker, setShowAttachPicker] = useState(false);
  const [attachQuery, setAttachQuery] = useState(() => alert.name || '');
  const [attachResults, setAttachResults] = useState<RunbookEntry[]>([]);
  const [loadingAttachResults, setLoadingAttachResults] = useState(false);
  const [attachingEntryId, setAttachingEntryId] = useState<number | null>(null);
  const [attachError, setAttachError] = useState('');
  const [attachSuccess, setAttachSuccess] = useState('');

  const host = alert.hostName || alert.hostname || '';

  const loadMatches = useCallback(async () => {
    setLoadingMatches(true);
    const entries = await fetchRunbookMatches(alert.name, host || undefined);
    setMatches(entries);
    const entryIds = entries.map((e: RunbookEntry) => e.id).filter(Boolean) as number[];
    if (entryIds.length > 0) {
      const feedback = await fetchRunbookFeedback(entryIds, alert.fingerprint);
      const voteMap = new Map<string, 'up' | 'down'>();
      for (const fb of feedback) {
        voteMap.set(`${fb.runbook_entry_id}`, fb.vote);
      }
      setVotes(voteMap);
    } else {
      setVotes(new Map());
    }
    setLoadingMatches(false);
  }, [alert.fingerprint, alert.name, host]);

  useEffect(() => {
    loadMatches();
  }, [loadMatches]);

  const handleSearchAttach = useCallback(async () => {
    setLoadingAttachResults(true);
    setAttachError('');
    const results = await searchRunbookEntries(attachQuery || alert.name, 20);
    setAttachResults(results);
    setLoadingAttachResults(false);
  }, [alert.name, attachQuery]);

  useEffect(() => {
    if (!showAttachPicker) return;
    handleSearchAttach();
  }, [showAttachPicker, handleSearchAttach]);

  useEffect(() => {
    setAttachQuery(alert.name || '');
  }, [alert.name]);

  const handleVote = async (entryId: number, vote: 'up' | 'down') => {
    const key = `${entryId}`;
    const currentVote = votes.get(key);
    const newVote = currentVote === vote ? 'none' : vote;

    setVotes(prev => {
      const next = new Map(prev);
      if (newVote === 'none') next.delete(key);
      else next.set(key, newVote as 'up' | 'down');
      return next;
    });

    try {
      await submitRunbookFeedback(alert.fingerprint, alert.name, entryId, newVote as 'up' | 'down' | 'none');
    } catch {
      setVotes(prev => {
        const next = new Map(prev);
        if (currentVote) next.set(key, currentVote);
        else next.delete(key);
        return next;
      });
    }
  };

  async function handleSubmit() {
    if (!remediation.trim()) return;
    setSubmitting(true);
    setSubmitError(false);

    const enrichment = parseAIEnrichment(alert.note);
    const ok = await submitRunbookEntry({
      alert_name: alert.name,
      alert_fingerprint: alert.fingerprint,
      hostname: host || undefined,
      severity: enrichment?.assessed_severity || alert.severity,
      remediation: remediation.trim(),
      sre_user: sreUser || undefined,
    });

    setSubmitting(false);
    if (ok) {
      setSubmitted(true);
      setRemediation('');
      loadMatches();
    } else {
      setSubmitError(true);
    }
  }

  async function handleAttach(entry: RunbookEntry) {
    if (!entry.id) return;
    setAttachingEntryId(entry.id);
    setAttachError('');
    setAttachSuccess('');
    const result = await attachRunbookEntry(entry.id, {
      alert_name: alert.name,
      hostname: host || undefined,
    });
    if (result.ok) {
      await submitRunbookFeedback(alert.fingerprint, alert.name, entry.id, 'up');
      await loadMatches();
      setAttachSuccess('Runbook attached and saved as a future match for similar alerts.');
      setShowAttachPicker(false);
    } else {
      setAttachError(result.error || 'Failed to attach runbook');
    }
    setAttachingEntryId(null);
  }

  return (
    <div className="bg-bg/40 border border-accent/20 rounded-lg px-4 py-3">
      <div className="flex items-center justify-between mb-3">
        <h4 className="text-sm font-semibold text-accent">Runbook &amp; Remediation</h4>
        <span className="text-[10px] text-muted">Build institutional knowledge</span>
      </div>

      {loadingMatches ? (
        <div className="text-xs text-muted animate-pulse mb-3">Loading runbook entries...</div>
      ) : matches.length > 0 ? (
        <div className="space-y-2 mb-4">
          <div className="text-[10px] text-muted uppercase tracking-wider">
            Past remediations for similar alerts ({matches.length})
          </div>
          {matches.map((entry) => (
            <div key={entry.id} className={`${votes.get(`${entry.id}`) === 'down' ? 'opacity-50' : ''} transition-opacity`}>
              <div className="bg-bg rounded-md p-2.5 border border-border">
                <div className="flex items-center gap-2 text-[10px] text-muted mb-1">
                  <span>{entry.created_at?.substring(0, 10)}</span>
                  {entry.sre_user && <span>by {entry.sre_user}</span>}
                  {entry.hostname && <span className="font-mono">{entry.hostname}</span>}
                  {entry.score != null && <span className="text-accent">relevance: {entry.score}</span>}
                  {entry.id != null && (
                    <div className="inline-flex items-center gap-1 ml-2">
                      <button
                        onClick={() => handleVote(entry.id!, 'up')}
                        className={`p-0.5 rounded transition-colors ${
                          votes.get(`${entry.id}`) === 'up'
                            ? 'text-green'
                            : 'text-muted/30 hover:text-green/70'
                        }`}
                        title="Useful remediation"
                      >
                        <svg className="w-3.5 h-3.5" fill={votes.get(`${entry.id}`) === 'up' ? 'currentColor' : 'none'} viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M14 9V5a3 3 0 00-3-3l-4 9v11h11.28a2 2 0 002-1.7l1.38-9a2 2 0 00-2-2.3H14z" />
                        </svg>
                      </button>
                      <button
                        onClick={() => handleVote(entry.id!, 'down')}
                        className={`p-0.5 rounded transition-colors ${
                          votes.get(`${entry.id}`) === 'down'
                            ? 'text-red'
                            : 'text-muted/30 hover:text-red/70'
                        }`}
                        title="Irrelevant remediation"
                      >
                        <svg className="w-3.5 h-3.5" fill={votes.get(`${entry.id}`) === 'down' ? 'currentColor' : 'none'} viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M10 15v4a3 3 0 003 3l4-9V2H5.72a2 2 0 00-2 1.7l-1.38 9a2 2 0 002 2.3H10z" />
                        </svg>
                      </button>
                    </div>
                  )}
                </div>
                <div className="text-[10px] text-muted mb-0.5 truncate">
                  Alert: {entry.alert_name?.substring(0, 80)}
                </div>
                <div className="text-xs text-text whitespace-pre-wrap">{entry.remediation}</div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-xs text-muted mb-3">
          No past remediations found for similar alerts. Be the first to document one.
        </div>
      )}

      {submitted && (
        <div className="bg-green/10 border border-green/30 rounded-lg px-3 py-2 mb-3">
          <div className="text-xs text-green">Remediation saved to runbook. It will be used to improve future AI analysis.</div>
        </div>
      )}

      {submitError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-3 py-2 mb-3">
          <div className="text-xs text-red">Failed to save. Please try again.</div>
        </div>
      )}

      {attachSuccess && (
        <div className="bg-green/10 border border-green/30 rounded-lg px-3 py-2 mb-3">
          <div className="text-xs text-green">{attachSuccess}</div>
        </div>
      )}

      {attachError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-3 py-2 mb-3">
          <div className="text-xs text-red">{attachError}</div>
        </div>
      )}

      <div className="mb-4 border border-border rounded-md p-3 bg-bg">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-[10px] text-muted uppercase tracking-wider">Missing the right runbook?</div>
            <div className="text-xs text-text">Search and attach an existing entry. Your choice will improve future matching.</div>
          </div>
          <button
            onClick={() => {
              setShowAttachPicker(prev => !prev);
              setAttachError('');
              setAttachSuccess('');
            }}
            className="px-3 py-1.5 rounded-md border border-accent/40 text-xs text-accent hover:bg-accent/10 transition-colors"
          >
            {showAttachPicker ? 'Hide Search' : 'Attach Existing'}
          </button>
        </div>

        {showAttachPicker && (
          <div className="mt-3 space-y-3">
            <div className="flex gap-2">
              <input
                type="text"
                value={attachQuery}
                onChange={(e) => setAttachQuery(e.target.value)}
                placeholder="Search runbook entries by alert name, hostname, or remediation"
                className="flex-1 bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-text placeholder-muted/50 focus:border-accent focus:outline-none"
              />
              <button
                onClick={handleSearchAttach}
                disabled={loadingAttachResults}
                className="px-3 py-1.5 rounded-md border border-border text-xs text-text hover:border-accent transition-colors disabled:opacity-50"
              >
                {loadingAttachResults ? 'Searching...' : 'Search'}
              </button>
            </div>

            {loadingAttachResults ? (
              <div className="text-xs text-muted animate-pulse">Searching runbook entries...</div>
            ) : attachResults.length > 0 ? (
              <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                {attachResults.map((entry) => (
                  <div key={entry.id} className="border border-border rounded-md p-2.5 bg-surface">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-xs text-text-bright">{entry.alert_name}</div>
                        <div className="text-[10px] text-muted mt-1">
                          {entry.hostname || 'Any host'}{entry.sre_user ? ` • by ${entry.sre_user}` : ''}
                        </div>
                        <div className="text-xs text-text mt-2 whitespace-pre-wrap">
                          {entry.remediation?.substring(0, 220)}
                          {(entry.remediation?.length ?? 0) > 220 ? '...' : ''}
                        </div>
                      </div>
                      <button
                        onClick={() => handleAttach(entry)}
                        disabled={attachingEntryId === entry.id}
                        className="shrink-0 px-3 py-1.5 rounded-md bg-accent text-bg text-xs font-medium hover:bg-accent-hover transition-colors disabled:opacity-50"
                      >
                        {attachingEntryId === entry.id ? 'Attaching...' : 'Attach'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-muted">No matching runbook entries found for that search.</div>
            )}
          </div>
        )}
      </div>

      <div className="space-y-2">
        <label className="text-[10px] text-muted block">
          What was the remediation? (Steps taken or needed to resolve this alert)
        </label>
        <textarea
          value={remediation}
          onChange={(e) => { setRemediation(e.target.value); setSubmitted(false); }}
          maxLength={5000}
          rows={3}
          placeholder="e.g. Restarted the bind9 service on prod-dns01. Root cause was recursive query loop from partner traffic spike. Applied rate limiting rule."
          className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-y"
        />
        <div className="flex items-end gap-2">
          {sreUser && <span className="text-[10px] text-muted py-1.5">as {sreUser}</span>}
          <button
            onClick={handleSubmit}
            disabled={submitting || !remediation.trim()}
            className="ml-auto px-4 py-1.5 rounded-md bg-accent text-bg font-medium text-xs hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitting ? 'Saving...' : 'Save to Runbook'}
          </button>
        </div>
      </div>
    </div>
  );
}
