'use client';

import { useEffect, useState, useCallback } from 'react';
import { Alert, AIEnrichment, SREFeedback, RunbookEntry, AlertState } from '@/lib/types';
import {
  fetchAlerts,
  parseAIEnrichment,
  parseSREFeedback,
  submitFeedback,
  submitStructuredFeedback,
  severityColor,
  severityBg,
  timeAgo,
  alertStartTime,
  fetchRunbookMatches,
  submitRunbookEntry,
  resolveAlert,
  resolveAlerts,
  silenceAlert,
  createJiraIncident,
  fetchAlertStates,
  toggleInvestigating,
  acknowledgeAlerts,
  unacknowledgeAlerts,
  markAlertsUpdated,
  getSourceLabel,
  forceEnrich,
  fetchEscalationTeams,
  fetchEscalationUsers,
  escalateAlert,
} from '@/lib/keep-api';
import { getClientUsername } from '@/lib/auth';
import { detectRegistryFromAlert, buildRegistryMailto } from '@/lib/registry';
import DashboardView from './DashboardView';
import AlertsTableView from './AlertsTableView';

export default function CommandCenter() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [refreshInterval, setRefreshInterval] = useState(30);
  const [refreshing, setRefreshing] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [alertStates, setAlertStates] = useState<Map<string, AlertState>>(new Map());
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts'>('dashboard');

  const load = useCallback(async () => {
    try {
      const [data, states] = await Promise.all([fetchAlerts(250), fetchAlertStates()]);

      // Build states map
      let stateMap = new Map<string, AlertState>();
      for (const s of states) stateMap.set(s.alert_fingerprint, s);

      // Re-fire detection: check acked alerts for new firingStartTime
      const refired: string[] = [];
      for (const alert of data) {
        const st = stateMap.get(alert.fingerprint);
        if (st?.acknowledged_by && st.ack_firing_start) {
          const cur = alert.firingStartTime || alert.startedAt || '';
          if (cur && cur !== st.ack_firing_start) refired.push(alert.fingerprint);
        }
      }
      if (refired.length > 0) {
        await markAlertsUpdated(refired);
        const fresh = await fetchAlertStates();
        stateMap = new Map<string, AlertState>();
        for (const s of fresh) stateMap.set(s.alert_fingerprint, s);
      }

      setAlerts(data);
      setAlertStates(stateMap);
      setLastUpdated(new Date());
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, refreshInterval * 1000);
    return () => clearInterval(interval);
  }, [load, refreshInterval]);

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
      </div>

      {/* Tab Content */}
      {activeTab === 'dashboard' ? (
        <DashboardView
          alerts={alerts}
          alertStates={alertStates}
          loading={false}
          onAlertClick={setSelectedAlert}
          onInvestigate={handleInvestigate}
          onAcknowledge={handleAcknowledge}
          onUnacknowledge={handleUnacknowledge}
          onGroupAcknowledge={handleGroupAcknowledge}
          onGroupResolve={handleGroupResolve}
          onForceEnrich={async (fp: string) => { await forceEnrich(fp); load(); }}
          onRefresh={load}
        />
      ) : (
        <AlertsTableView
          alerts={alerts}
          loading={false}
          onAlertClick={setSelectedAlert}
        />
      )}

      {/* Alert Detail Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onRefresh={handleAlertRefresh}
          alertState={alertStates.get(selectedAlert.fingerprint)}
          onInvestigate={() => handleInvestigate(selectedAlert)}
          onAcknowledge={() => handleAcknowledge(selectedAlert)}
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

/* ── Alert Detail Modal ── */

function AlertDetailModal({ alert, onClose, onRefresh, alertState, onInvestigate, onAcknowledge }: {
  alert: Alert;
  onClose: () => void;
  onRefresh: () => void;
  alertState?: AlertState;
  onInvestigate?: () => void;
  onAcknowledge?: () => void;
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
              {alert.fingerprint && (
                <span>FP: <span className="text-text font-mono">{alert.fingerprint.substring(0, 16)}...</span></span>
              )}
            </div>
          </div>

          {/* Actions */}
          <AlertActions alert={alert} enrichment={enrichment} onAlertChanged={onRefresh} alertState={alertState} onInvestigate={onInvestigate} onAcknowledge={onAcknowledge} />

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
          {enrichment && (
            <ModalFeedbackPanel
              fingerprint={alert.fingerprint}
              currentNote={alert.note}
              existingFeedback={parseSREFeedback(alert.note)}
              enrichment={enrichment}
              onFeedbackSubmitted={onRefresh}
              alertName={alert.name}
              hostname={alert.hostName || alert.hostname || ''}
            />
          )}

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
  currentNote,
  existingFeedback,
  enrichment,
  onFeedbackSubmitted,
  alertName,
  hostname,
}: {
  fingerprint: string;
  currentNote: string | undefined | null;
  existingFeedback: SREFeedback | null;
  enrichment: { assessed_severity: string; noise_score: number };
  onFeedbackSubmitted?: () => void;
  alertName: string;
  hostname: string;
}) {
  const [rating, setRating] = useState<'positive' | 'negative' | null>(
    existingFeedback?.rating === 'positive' ? 'positive' :
    existingFeedback?.rating ? 'negative' : null
  );
  const [correctedSeverity, setCorrectedSeverity] = useState(existingFeedback?.corrected_severity ?? '');
  const [correctedNoise, setCorrectedNoise] = useState(existingFeedback?.corrected_noise?.toString() ?? '');
  const [causeCorrection, setCauseCorrection] = useState('');
  const [remediationCorrection, setRemediationCorrection] = useState('');
  const [comment, setComment] = useState(existingFeedback?.comment ?? '');
  const [sreUser] = useState(() => existingFeedback?.sre_user || getClientUsername() || '');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(!!existingFeedback);
  const [editing, setEditing] = useState(false);
  const [justSubmitted, setJustSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState(false);

  async function handleSubmit() {
    if (!rating) return;
    setSubmitting(true);
    setSubmitError(false);

    const feedback: SREFeedback = {
      rating: rating === 'negative' && !correctedSeverity && !correctedNoise ? 'negative' :
              rating === 'negative' ? 'correction' : 'positive',
      corrected_severity: correctedSeverity || undefined,
      corrected_noise: correctedNoise ? parseInt(correctedNoise, 10) : undefined,
      comment: comment.slice(0, 500) || undefined,
      sre_user: sreUser || undefined,
    };

    // Submit both legacy (note-based) and structured feedback in parallel
    const [ok] = await Promise.all([
      submitFeedback(fingerprint, currentNote, feedback),
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
    if (ok) {
      setSubmitted(true);
      setEditing(false);
      setJustSubmitted(true);
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

      {submitted && !editing ? (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-sm">
            <span className={`text-base ${rating === 'positive' ? 'text-green' : 'text-red'}`}>
              {rating === 'positive' ? '\u2713' : '\u2717'}
            </span>
            <span className="text-text text-xs">
              {rating === 'positive' ? 'Confirmed accurate' : 'Needs correction'}
            </span>
            {sreUser && <span className="text-muted text-[10px]">by {sreUser}</span>}
          </div>
          {(correctedSeverity || correctedNoise) && (
            <div className="flex gap-3 text-[10px] text-muted">
              {correctedSeverity && (
                <span>Severity: <span className={`font-medium ${severityColor(correctedSeverity)}`}>{correctedSeverity}</span></span>
              )}
              {correctedNoise && (
                <span>Noise: <span className="font-medium text-text">{correctedNoise}/10</span></span>
              )}
            </div>
          )}
          {comment && (
            <div className="text-xs text-text bg-bg rounded-md p-2 border border-border">{comment}</div>
          )}
          <button
            onClick={() => { setEditing(true); setJustSubmitted(false); }}
            className="text-[10px] text-accent hover:text-accent-hover transition-colors"
          >
            Update feedback
          </button>
        </div>
      ) : (
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
                  <option value="">No change ({enrichment.assessed_severity})</option>
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
                  <option value="">No change ({enrichment.noise_score}/10)</option>
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
              {editing && (
                <button
                  onClick={() => setEditing(false)}
                  className="px-3 py-1.5 rounded-md border border-border text-muted text-xs hover:text-text transition-colors"
                >
                  Cancel
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AlertActions({ alert, enrichment, onAlertChanged, alertState, onInvestigate, onAcknowledge }: {
  alert: Alert;
  enrichment: AIEnrichment | null;
  onAlertChanged: () => void;
  alertState?: AlertState;
  onInvestigate?: () => void;
  onAcknowledge?: () => void;
}) {
  const [resolving, setResolving] = useState(false);
  const [resolved, setResolved] = useState(false);
  const [showSilenceMenu, setShowSilenceMenu] = useState(false);
  const [silencing, setSilencing] = useState(false);
  const [silenced, setSilenced] = useState<string | null>(null);
  const [silenceError, setSilenceError] = useState(false);
  const [showIncidentForm, setShowIncidentForm] = useState(false);
  const [incidentResult, setIncidentResult] = useState<{ key: string; url: string } | null>(null);
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
        {/* Resolve */}
        <button
          onClick={handleResolve}
          disabled={resolving || resolved}
          className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
            resolved
              ? 'border-green/40 bg-green/10 text-green cursor-default'
              : 'border-border text-muted hover:border-green/50 hover:text-green hover:bg-green/5'
          } disabled:opacity-60`}
        >
          {resolved ? '\u2713 Resolved' : resolving ? 'Resolving...' : 'Resolve'}
        </button>

        {/* Silence */}
        <div className="relative">
          <button
            onClick={() => setShowSilenceMenu(!showSilenceMenu)}
            disabled={silencing || !!silenced}
            className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all ${
              silenced
                ? 'border-yellow/40 bg-yellow/10 text-yellow cursor-default'
                : 'border-border text-muted hover:border-yellow/50 hover:text-yellow hover:bg-yellow/5'
            } disabled:opacity-60`}
          >
            {silenced ? `Silenced (${silenced})` : silencing ? 'Silencing...' : 'Silence'}
          </button>
          {showSilenceMenu && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setShowSilenceMenu(false)} />
              <div className="absolute top-full left-0 mt-1 bg-surface border border-border rounded-lg shadow-xl z-20 py-1 min-w-[140px]">
                {[
                  { label: '30 minutes', seconds: 1800 },
                  { label: '1 hour', seconds: 3600 },
                  { label: '4 hours', seconds: 14400 },
                  { label: '8 hours', seconds: 28800 },
                  { label: '24 hours', seconds: 86400 },
                ].map(opt => (
                  <button
                    key={opt.seconds}
                    onClick={() => handleSilence(opt.seconds)}
                    className="w-full text-left px-3 py-1.5 text-xs text-text hover:bg-surface-hover transition-colors"
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Create Incident */}
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
            Create Incident
          </button>
        )}

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

        {/* Investigate Toggle */}
        {onInvestigate && (
          <button
            onClick={onInvestigate}
            className={`px-3 py-1.5 rounded-md border text-xs font-medium transition-all inline-flex items-center gap-1 ${
              alertState?.investigating_user
                ? 'border-blue/40 bg-blue/10 text-blue'
                : 'border-border text-muted hover:border-blue/50 hover:text-blue hover:bg-blue/5'
            }`}
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
            {alertState?.investigating_user ? `Investigating (${alertState.investigating_user})` : 'Investigate'}
          </button>
        )}

        {/* Acknowledge */}
        {onAcknowledge && !alertState?.acknowledged_by && (
          <button
            onClick={onAcknowledge}
            className="px-3 py-1.5 rounded-md border border-border text-muted text-xs font-medium hover:border-green/50 hover:text-green hover:bg-green/5 transition-all inline-flex items-center gap-1"
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            Acknowledge
          </button>
        )}
        {alertState?.acknowledged_by && (
          <span className="px-3 py-1.5 rounded-md border border-green/40 bg-green/10 text-green text-xs font-medium inline-flex items-center gap-1">
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            Acked by {alertState.acknowledged_by}
          </span>
        )}
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
              const result = await escalateAlert({
                team_id: escalationType === 'team' ? escalationTarget : undefined,
                user_ids: escalationType === 'user' ? [escalationTarget] : undefined,
                alert_name: alert.name || 'Unknown',
                severity: enrichment?.assessed_severity || alert.severity || 'unknown',
                summary: enrichment?.summary || alert.description || '',
                message: escalationMessage,
                uip_link: typeof window !== 'undefined' ? window.location.href : '',
              });
              setEscalating(false);
              if (result.success) {
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
      onCreated(result.issueKey, result.issueUrl || '');
    } else {
      setError(result.error || 'Failed to create incident');
    }
  }

  return (
    <div className="bg-bg/60 border border-accent/20 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-accent">Create Jira Incident (OCCIR)</h4>
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
          {submitting ? (pastedImages.length > 0 ? 'Creating & uploading...' : 'Creating...') : 'Create Incident'}
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

  const host = alert.hostName || alert.hostname || '';

  useEffect(() => {
    setLoadingMatches(true);
    fetchRunbookMatches(alert.name, host || undefined)
      .then(setMatches)
      .finally(() => setLoadingMatches(false));
  }, [alert.name, host]);

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
      fetchRunbookMatches(alert.name, host || undefined).then(setMatches);
    } else {
      setSubmitError(true);
    }
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
            <div key={entry.id} className="bg-bg rounded-md p-2.5 border border-border">
              <div className="flex items-center gap-2 text-[10px] text-muted mb-1">
                <span>{entry.created_at?.substring(0, 10)}</span>
                {entry.sre_user && <span>by {entry.sre_user}</span>}
                {entry.hostname && <span className="font-mono">{entry.hostname}</span>}
                {entry.score != null && <span className="text-accent">relevance: {entry.score}</span>}
              </div>
              <div className="text-[10px] text-muted mb-0.5 truncate">
                Alert: {entry.alert_name?.substring(0, 80)}
              </div>
              <div className="text-xs text-text whitespace-pre-wrap">{entry.remediation}</div>
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
