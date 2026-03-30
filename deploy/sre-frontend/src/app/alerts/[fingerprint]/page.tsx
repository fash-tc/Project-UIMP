'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { Alert, AIEnrichment, RunbookEntry, AlertState, SREFeedbackEntry, RunbookExclusion } from '@/lib/types';
import {
  fetchAlertByFingerprint,
  parseAIEnrichment,
  severityColor,
  severityBg,
  timeAgo,
  alertStartTime,
  fetchRunbookMatches,
  submitRunbookEntry,
  resolveAlert,
  silenceAlert,
  createJiraIncident,
  fetchAlertStates,
  toggleInvestigating,
  acknowledgeAlerts,
  unacknowledgeAlerts,
  getSourceLabel,
  storeIncidentState,
  submitRunbookFeedback,
  fetchRunbookFeedback,
  fetchSREFeedback,
  submitSREFeedback,
  updateSREFeedback,
  deleteSREFeedback,
  voteSREFeedback,
  fetchRunbookExclusions,
  createRunbookExclusion,
  deleteRunbookExclusion,
  deleteRunbookEntry,
  MaintenanceEvent,
  fetchMaintenanceEvents,
} from '@/lib/keep-api';
import { detectRegistryFromAlert, matchMaintenanceToOperators } from '@/lib/registry';
import { RunbookFeedback } from '@/lib/types';
import { getClientUsername } from '@/lib/auth';

export default function AlertDetail() {
  const params = useParams();
  const fingerprint = params.fingerprint as string;
  const [alert, setAlert] = useState<Alert | null>(null);
  const [alertState, setAlertState] = useState<AlertState | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [maintenanceEvents, setMaintenanceEvents] = useState<MaintenanceEvent[]>([]);

  const loadAlert = () => {
    if (!fingerprint) return;
    Promise.all([
      fetchAlertByFingerprint(fingerprint),
      fetchAlertStates(),
    ]).then(([a, states]) => {
      setAlert(a);
      const st = states.find((s: AlertState) => s.alert_fingerprint === fingerprint);
      setAlertState(st);
    }).catch(() => {}).finally(() => setLoading(false));
  };

  async function handleInvestigate() {
    if (!alert) return;
    await toggleInvestigating(alert.fingerprint, alert.name || '');
    const states = await fetchAlertStates();
    const st = states.find((s: AlertState) => s.alert_fingerprint === fingerprint);
    setAlertState(st);
  }

  async function handleAcknowledge() {
    if (!alert) return;
    const names: Record<string, string> = { [alert.fingerprint]: alert.name || '' };
    const starts: Record<string, string> = { [alert.fingerprint]: alertStartTime(alert) };
    await acknowledgeAlerts([alert.fingerprint], names, starts);
    const states = await fetchAlertStates();
    const st = states.find((s: AlertState) => s.alert_fingerprint === fingerprint);
    setAlertState(st);
  }

  async function handleUnacknowledge() {
    if (!alert) return;
    await unacknowledgeAlerts([alert.fingerprint]);
    const states = await fetchAlertStates();
    const st = states.find((s: AlertState) => s.alert_fingerprint === fingerprint);
    setAlertState(st);
  }

  useEffect(() => {
    loadAlert();
  }, [fingerprint]);

  useEffect(() => {
    fetchMaintenanceEvents().then(setMaintenanceEvents);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted animate-pulse">Loading alert...</div>
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="text-center py-16">
        <div className="text-muted text-lg mb-2">Alert not found</div>
        <a href="/portal/alerts" className="text-accent hover:text-accent-hover text-sm">
          &larr; Back to alerts
        </a>
      </div>
    );
  }

  const enrichment = parseAIEnrichment(alert.note);
  const host = alert.hostName || alert.hostname || 'Unknown';
  const registryMatch = detectRegistryFromAlert(alert.name, host, alert.description);
  const matchedMaintenance = registryMatch
    ? maintenanceEvents.filter(m => {
        const ops = matchMaintenanceToOperators(m.vendor, m.title);
        return ops.includes(registryMatch.operator.id);
      })
    : [];
  const source = getSourceLabel(alert);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <a href="/portal/alerts" className="text-xs text-accent hover:text-accent-hover mb-2 inline-block">
          &larr; Back to alerts
        </a>
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-text-bright">{alert.name}</h1>
          {alertState?.investigating_user && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue/10 border border-blue/30 text-blue inline-flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              Investigating: {alertState.investigating_user}
            </span>
          )}
          {alertState?.acknowledged_by && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-green/10 border border-green/30 text-green">
              Acked by {alertState.acknowledged_by}
            </span>
          )}
          {alertState?.is_updated === 1 && (
            <span className="px-2 py-0.5 rounded-full text-[10px] font-medium bg-orange/10 border border-orange/30 text-orange">
              Updated
            </span>
          )}
        </div>
        <div className="flex flex-wrap gap-3 mt-2 text-xs text-muted">
          <span>Host: <span className="text-text font-mono">{host}</span></span>
          <span>Source: <span className="text-text">{source}</span></span>
          <span>Status: <span className="text-text">{alert.status}</span></span>
          <span>Started: <span className="text-text">{timeAgo(alertStartTime(alert))}</span></span>
          {alert.fingerprint && <span>FP: <span className="text-text font-mono">{alert.fingerprint.substring(0, 16)}...</span></span>}
        </div>
      </div>

      {/* Actions */}
      <AlertActions alert={alert} enrichment={enrichment} onAlertChanged={loadAlert} alertState={alertState} onInvestigate={handleInvestigate} onAcknowledge={handleAcknowledge} onUnacknowledge={handleUnacknowledge} />

      {/* Alert Details / Metric Values */}
      {alert.description && alert.description !== alert.name && (
        <div className="stat-card border-accent/20">
          <h3 className="text-sm font-medium text-muted mb-2">Alert Details</h3>
          <p className="text-sm text-text-bright font-mono">{alert.description}</p>
        </div>
      )}

      {/* Active Maintenance Window */}
      {matchedMaintenance.length > 0 && (
        <div className="bg-yellow/5 border border-yellow/30 rounded-lg px-5 py-4 space-y-2">
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-yellow" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <h3 className="text-sm font-medium text-yellow">Active Maintenance Window</h3>
            <span className="text-xs text-muted">This alert may be related to scheduled maintenance</span>
          </div>
          {matchedMaintenance.map(m => (
            <div key={m.id} className="flex items-center gap-3 bg-bg/40 rounded-md px-3 py-2">
              <div className="flex-1 min-w-0">
                <a
                  href={m.permalink}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-text-bright hover:text-accent transition-colors"
                >
                  {m.title}
                </a>
                <div className="text-xs text-muted mt-0.5">
                  {m.vendor}
                  {m.end_time && ` — ends ${new Date(m.end_time).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false })}`}
                </div>
              </div>
              <a
                href={m.permalink}
                target="_blank"
                rel="noopener noreferrer"
                className="px-2.5 py-1 rounded-md border border-yellow/30 text-yellow text-[10px] font-medium hover:bg-yellow/10 transition-colors flex-shrink-0"
              >
                View
              </a>
            </div>
          ))}
        </div>
      )}

      {/* AI Analysis Panel */}
      {enrichment ? (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-accent">AI Analysis</h2>

          {/* Summary + Key metrics */}
          <div className="stat-card border-accent/30">
            <div className="text-text-bright mb-3">{enrichment.summary}</div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <MetricBox
                label="Assessed Severity"
                value={enrichment.assessed_severity}
                className={severityColor(enrichment.assessed_severity)}
              />
              <MetricBox
                label="Original Severity"
                value={alert.severity || 'unknown'}
                className="text-muted"
              />
              <MetricBox
                label="Noise Score"
                value={`${enrichment.noise_score}/10`}
                className={enrichment.noise_score >= 7 ? 'text-muted' : enrichment.noise_score >= 4 ? 'text-yellow' : 'text-green'}
              />
              <MetricBox
                label="Dedup"
                value={enrichment.dedup_assessment || 'N/A'}
                className={enrichment.dedup_assessment === 'DUPLICATE' ? 'text-orange' : enrichment.dedup_assessment === 'CORRELATED' ? 'text-yellow' : 'text-green'}
              />
            </div>
          </div>

          {/* Detail Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <DetailCard title="Likely Cause" content={enrichment.likely_cause} icon="?" />
            <DetailCard title="Remediation" content={enrichment.remediation} icon="!" />
            <DetailCard title="Impact Scope" content={enrichment.impact_scope} icon="~" />
            <DetailCard title="Noise Reason" content={enrichment.noise_reason} icon="#" />
          </div>

          {enrichment.dedup_reason && (
            <div className="stat-card">
              <h3 className="text-sm font-medium text-muted mb-2">Deduplication Reason</h3>
              <div className="text-sm text-text">{enrichment.dedup_reason}</div>
            </div>
          )}

          {/* Noise Score Visual */}
          <div className="stat-card">
            <h3 className="text-sm font-medium text-muted mb-3">Noise Assessment</h3>
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <div className="w-full bg-border rounded-full h-3">
                  <div
                    className={`h-3 rounded-full transition-all ${
                      enrichment.noise_score >= 7 ? 'bg-muted' :
                      enrichment.noise_score >= 4 ? 'bg-yellow' : 'bg-green'
                    }`}
                    style={{ width: `${enrichment.noise_score * 10}%` }}
                  />
                </div>
                <div className="flex justify-between text-xs text-muted mt-1">
                  <span>Actionable</span>
                  <span>Likely Noise</span>
                </div>
              </div>
              <div className={`text-2xl font-bold font-mono ${
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
        <div className="stat-card border-border">
          <div className="text-muted text-sm">
            AI enrichment not yet available for this alert. The enricher processes alerts every 60 seconds.
          </div>
        </div>
      )}

      {/* SRE Feedback Panel */}
      <FeedbackPanel
        fingerprint={fingerprint}
        alertName={alert.name || ''}
        enrichment={enrichment}
        onFeedbackSubmitted={loadAlert}
      />

      {/* Runbook & Remediation */}
      <RunbookPanel alert={alert} />

      {/* Tags */}
      {alert.tags && Array.isArray(alert.tags) && alert.tags.length > 0 && (
        <div className="stat-card">
          <h3 className="text-sm font-medium text-muted mb-3">Tags</h3>
          <div className="flex flex-wrap gap-2">
            {alert.tags.map((tag, i) => (
              <span key={i} className="badge bg-accent/10 border-accent/30 text-accent">
                {tag.tag || tag.name}: {tag.value}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Raw Data */}
      <details className="stat-card">
        <summary className="text-sm font-medium text-muted cursor-pointer hover:text-text transition-colors">
          Raw Alert Data
        </summary>
        <pre className="mt-3 text-xs text-muted overflow-x-auto bg-bg rounded-md p-3 border border-border">
          {JSON.stringify(alert, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function MetricBox({ label, value, className }: { label: string; value: string; className?: string }) {
  return (
    <div>
      <div className="text-xs text-muted uppercase tracking-wider mb-1">{label}</div>
      <div className={`text-lg font-semibold uppercase ${className || ''}`}>{value}</div>
    </div>
  );
}

function DetailCard({ title, content, icon }: { title: string; content: string; icon: string }) {
  if (!content) return null;
  return (
    <div className="stat-card">
      <div className="flex items-start gap-3">
        <div className="w-8 h-8 rounded-md bg-accent/10 border border-accent/30 flex items-center justify-center text-accent font-mono text-sm flex-shrink-0">
          {icon}
        </div>
        <div>
          <h3 className="text-sm font-medium text-muted mb-1">{title}</h3>
          <div className="text-sm text-text">{content}</div>
        </div>
      </div>
    </div>
  );
}

function FeedbackPanel({
  fingerprint,
  alertName,
  enrichment,
  onFeedbackSubmitted,
}: {
  fingerprint: string;
  alertName: string;
  enrichment: { assessed_severity: string; noise_score: number } | null;
  onFeedbackSubmitted?: () => void;
}) {
  const [entries, setEntries] = useState<SREFeedbackEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [rating, setRating] = useState<'positive' | 'negative' | null>(null);
  const [correctedSeverity, setCorrectedSeverity] = useState('');
  const [correctedNoise, setCorrectedNoise] = useState('');
  const [comment, setComment] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editRating, setEditRating] = useState<string>('');
  const [editSeverity, setEditSeverity] = useState('');
  const [editNoise, setEditNoise] = useState('');
  const [editComment, setEditComment] = useState('');
  const [currentUser] = useState(() => getClientUsername() || '');

  const loadEntries = () => {
    fetchSREFeedback(fingerprint).then(data => {
      setEntries(data);
      setLoading(false);
    });
  };

  useEffect(() => { loadEntries(); }, [fingerprint]);

  async function handleSubmit() {
    if (!rating) return;
    setSubmitting(true);
    setSubmitError(false);
    const result = await submitSREFeedback({
      fingerprint,
      alert_name: alertName,
      rating: rating === 'negative' && (correctedSeverity || correctedNoise) ? 'correction' : rating,
      corrected_severity: correctedSeverity || undefined,
      corrected_noise: correctedNoise ? parseInt(correctedNoise, 10) : undefined,
      comment: comment.slice(0, 2000) || undefined,
    });
    setSubmitting(false);
    if (result) {
      setRating(null);
      setCorrectedSeverity('');
      setCorrectedNoise('');
      setComment('');
      loadEntries();
      if (onFeedbackSubmitted) setTimeout(onFeedbackSubmitted, 500);
    } else {
      setSubmitError(true);
    }
  }

  async function handleVote(id: number, vote: 'up' | 'down') {
    const entry = entries.find(e => e.id === id);
    if (!entry) return;
    const newVote = entry.user_vote === vote ? 'none' : vote;
    // Optimistic update
    setEntries(prev => prev.map(e => {
      if (e.id !== id) return e;
      const scoreDelta = (newVote === 'none' ? 0 : (newVote === 'up' ? 1 : -1))
        - (e.user_vote === 'up' ? 1 : e.user_vote === 'down' ? -1 : 0);
      return { ...e, user_vote: newVote === 'none' ? null : newVote as 'up' | 'down', vote_score: e.vote_score + scoreDelta };
    }));
    const ok = await voteSREFeedback(id, newVote as 'up' | 'down' | 'none');
    if (!ok) loadEntries(); // Revert on failure
  }

  async function handleDelete(id: number, user: string) {
    if (!confirm(`Delete this feedback from ${user}?`)) return;
    const ok = await deleteSREFeedback(id);
    if (ok) {
      setEntries(prev => prev.filter(e => e.id !== id));
    }
  }

  function startEdit(entry: SREFeedbackEntry) {
    setEditingId(entry.id);
    setEditRating(entry.rating || '');
    setEditSeverity(entry.corrected_severity || '');
    setEditNoise(entry.corrected_noise?.toString() || '');
    setEditComment(entry.comment || '');
  }

  async function handleEditSave() {
    if (!editingId) return;
    const ok = await updateSREFeedback(editingId, {
      rating: editRating || undefined,
      corrected_severity: editSeverity || undefined,
      corrected_noise: editNoise ? parseInt(editNoise, 10) : undefined,
      comment: editComment || undefined,
    });
    if (ok) {
      setEditingId(null);
      loadEntries();
    }
  }

  const ratingBadge = (r: string) => {
    if (r === 'positive') return <span className="px-1.5 py-0.5 rounded text-[10px] bg-green/10 border border-green/30 text-green">Accurate</span>;
    if (r === 'correction') return <span className="px-1.5 py-0.5 rounded text-[10px] bg-orange/10 border border-orange/30 text-orange">Correction</span>;
    return <span className="px-1.5 py-0.5 rounded text-[10px] bg-red/10 border border-red/30 text-red">Needs Fix</span>;
  };

  return (
    <div className="stat-card border-accent/20">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-accent">SRE Feedback</h3>
        <span className="text-xs text-muted">Help improve AI analysis</span>
      </div>

      {/* Existing feedback entries */}
      {loading ? (
        <div className="text-xs text-muted animate-pulse mb-3">Loading feedback...</div>
      ) : entries.length > 0 ? (
        <div className="space-y-2 mb-4">
          <div className="text-[10px] text-muted uppercase tracking-wider">
            Feedback from SRE team ({entries.length})
          </div>
          {entries.map(entry => (
            <div key={entry.id} className="bg-bg rounded-md p-2.5 border border-border">
              {editingId === entry.id ? (
                /* Inline edit form */
                <div className="space-y-2">
                  <div className="grid grid-cols-2 gap-2">
                    <select value={editRating} onChange={e => setEditRating(e.target.value)}
                      className="bg-surface border border-border rounded px-2 py-1 text-xs text-text">
                      <option value="positive">Accurate</option>
                      <option value="negative">Needs correction</option>
                      <option value="correction">Correction</option>
                    </select>
                    <select value={editSeverity} onChange={e => setEditSeverity(e.target.value)}
                      className="bg-surface border border-border rounded px-2 py-1 text-xs text-text">
                      <option value="">No severity correction</option>
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="warning">Warning</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>
                  </div>
                  <textarea value={editComment} onChange={e => setEditComment(e.target.value)}
                    maxLength={2000} rows={2}
                    className="w-full bg-surface border border-border rounded px-2 py-1 text-xs text-text resize-none" />
                  <div className="flex gap-2">
                    <button onClick={handleEditSave}
                      className="px-2 py-1 rounded bg-accent text-bg text-[10px] font-medium hover:bg-accent-hover">Save</button>
                    <button onClick={() => setEditingId(null)}
                      className="px-2 py-1 rounded border border-border text-muted text-[10px] hover:text-text">Cancel</button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="flex items-center gap-2 text-[10px] text-muted mb-1.5 flex-wrap">
                    {ratingBadge(entry.rating)}
                    <span>by {entry.user}</span>
                    <span>{entry.created_at?.substring(0, 16).replace('T', ' ')}</span>
                    {entry.corrected_severity && (
                      <span className="text-orange">sev: {entry.corrected_severity}</span>
                    )}
                    {entry.corrected_noise != null && (
                      <span className="text-orange">noise: {entry.corrected_noise}/10</span>
                    )}

                    {/* Vote buttons */}
                    <div className="inline-flex items-center gap-0.5 ml-auto">
                      <button
                        onClick={() => handleVote(entry.id, 'up')}
                        className={`p-0.5 rounded transition-colors ${
                          entry.user_vote === 'up' ? 'text-green' : 'text-muted/30 hover:text-green/70'
                        }`}
                        title="Useful feedback"
                      >
                        <svg className="w-3.5 h-3.5" fill={entry.user_vote === 'up' ? 'currentColor' : 'none'} viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M14 9V5a3 3 0 00-3-3l-4 9v11h11.28a2 2 0 002-1.7l1.38-9a2 2 0 00-2-2.3H14z" />
                        </svg>
                      </button>
                      <span className={`text-[10px] min-w-[16px] text-center ${
                        entry.vote_score > 0 ? 'text-green' : entry.vote_score < 0 ? 'text-red' : 'text-muted/50'
                      }`}>
                        {entry.vote_score > 0 ? `+${entry.vote_score}` : entry.vote_score}
                      </span>
                      <button
                        onClick={() => handleVote(entry.id, 'down')}
                        className={`p-0.5 rounded transition-colors ${
                          entry.user_vote === 'down' ? 'text-red' : 'text-muted/30 hover:text-red/70'
                        }`}
                        title="Not useful"
                      >
                        <svg className="w-3.5 h-3.5" fill={entry.user_vote === 'down' ? 'currentColor' : 'none'} viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M10 15v4a3 3 0 003 3l4-9V2H5.72a2 2 0 00-2 1.7l-1.38 9a2 2 0 002 2.3H10z" />
                        </svg>
                      </button>
                    </div>

                    {/* Edit (author only) */}
                    {entry.user === currentUser && (
                      <button onClick={() => startEdit(entry)}
                        className="text-muted/30 hover:text-accent transition-colors" title="Edit">
                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                        </svg>
                      </button>
                    )}

                    {/* Delete (any SRE) */}
                    <button onClick={() => handleDelete(entry.id, entry.user)}
                      className="text-muted/30 hover:text-red transition-colors" title="Delete">
                      <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                  {entry.comment && (
                    <div className="text-xs text-text whitespace-pre-wrap">{entry.comment}</div>
                  )}
                </>
              )}
            </div>
          ))}
        </div>
      ) : null}

      {/* Submit error */}
      {submitError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 mb-4">
          <div className="text-sm text-red">Failed to submit feedback. Please try again.</div>
        </div>
      )}

      {/* Add new feedback form */}
      <div className="space-y-3">
        <div className="text-[10px] text-muted uppercase tracking-wider">Add your feedback</div>

        {/* Quick rating */}
        <div className="flex gap-2">
          <button
            onClick={() => setRating(rating === 'positive' ? null : 'positive')}
            className={`px-4 py-2 rounded-md border text-sm font-medium transition-all ${
              rating === 'positive'
                ? 'border-green bg-green/10 text-green'
                : 'border-border text-muted hover:border-green/50 hover:text-green'
            }`}
          >
            &#x2713; Accurate
          </button>
          <button
            onClick={() => setRating(rating === 'negative' ? null : 'negative')}
            className={`px-4 py-2 rounded-md border text-sm font-medium transition-all ${
              rating === 'negative'
                ? 'border-red bg-red/10 text-red'
                : 'border-border text-muted hover:border-red/50 hover:text-red'
            }`}
          >
            &#x2717; Needs correction
          </button>
        </div>

        {/* Correction fields */}
        {rating === 'negative' && enrichment && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted block mb-1">Correct severity</label>
              <select
                value={correctedSeverity}
                onChange={(e) => setCorrectedSeverity(e.target.value)}
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
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
              <label className="text-xs text-muted block mb-1">Correct noise score</label>
              <select
                value={correctedNoise}
                onChange={(e) => setCorrectedNoise(e.target.value)}
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
              >
                <option value="">No change ({enrichment.noise_score}/10)</option>
                {[1,2,3,4,5,6,7,8,9,10].map(n => (
                  <option key={n} value={n}>{n}/10 {n <= 3 ? '(actionable)' : n >= 7 ? '(noise)' : ''}</option>
                ))}
              </select>
            </div>
          </div>
        )}

        {/* Comment */}
        {rating && (
          <div>
            <label className="text-xs text-muted block mb-1">
              {rating === 'positive' ? 'Additional notes (optional)' : 'What should the AI learn from this?'}
            </label>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              maxLength={2000}
              rows={2}
              placeholder={rating === 'positive'
                ? 'Any additional context...'
                : 'e.g. "This is a known maintenance window alert, noise score should be higher"'
              }
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-none"
            />
            <div className="text-xs text-muted text-right mt-1">{comment.length}/2000</div>
          </div>
        )}

        {/* Submit */}
        {rating && (
          <div className="flex items-end gap-3">
            {currentUser && <span className="text-xs text-muted py-2">as {currentUser}</span>}
            <button
              onClick={handleSubmit}
              disabled={submitting || !rating}
              className="px-5 py-2 rounded-md bg-accent text-bg font-medium text-sm hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Submitting...' : 'Submit Feedback'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function AlertActions({ alert, enrichment, onAlertChanged, alertState, onInvestigate, onAcknowledge, onUnacknowledge }: {
  alert: Alert;
  enrichment: AIEnrichment | null;
  onAlertChanged: () => void;
  alertState?: AlertState;
  onInvestigate?: () => void;
  onAcknowledge?: () => void;
  onUnacknowledge?: () => void;
}) {
  const [resolving, setResolving] = useState(false);
  const [resolved, setResolved] = useState(false);
  const [showSilenceMenu, setShowSilenceMenu] = useState(false);
  const [silencing, setSilencing] = useState(false);
  const [silenced, setSilenced] = useState<string | null>(null);
  const [silenceError, setSilenceError] = useState(false);
  const [showIncidentForm, setShowIncidentForm] = useState(false);
  const [incidentResult, setIncidentResult] = useState<{ key: string; url: string } | null>(null);

  const host = alert.hostName || alert.hostname || '';

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
    <div className="stat-card space-y-3">
      <div className="flex flex-wrap gap-2">
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

        {/* Acknowledge / Unacknowledge */}
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
          <>
            <span className="px-3 py-1.5 rounded-md border border-green/40 bg-green/10 text-green text-xs font-medium inline-flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              Acked by {alertState.acknowledged_by}
            </span>
            {onUnacknowledge && (
              <button
                onClick={onUnacknowledge}
                className="px-3 py-1.5 rounded-md border border-border text-muted text-xs font-medium hover:border-orange/50 hover:text-orange hover:bg-orange/5 transition-all"
              >
                Unacknowledge
              </button>
            )}
          </>
        )}
      </div>

      {silenceError && (
        <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">
          Failed to create silence rule. Check Keep maintenance API.
        </div>
      )}

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
    `Source: ${Array.isArray(alert.source) ? alert.source.join(', ') : alert.source}`,
    alert.description && alert.description !== alert.name ? `Details: ${alert.description}` : null,
  ].filter(Boolean).join('\n\n');

  const [summary, setSummary] = useState(`[Alert] ${alert.name}`);
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
        await storeIncidentState(alert.fingerprint, result.issueKey, result.issueUrl || '');
      } catch {
        // Best-effort — incident was already created in Jira
      }
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
  const [votes, setVotes] = useState<Map<string, 'up' | 'down'>>(new Map());
  const [exclusions, setExclusions] = useState<RunbookExclusion[]>([]);
  const [showExcluded, setShowExcluded] = useState(false);

  const host = alert.hostName || alert.hostname || '';

  useEffect(() => {
    setLoadingMatches(true);
    fetchRunbookMatches(alert.name, host || undefined)
      .then((entries) => {
        setMatches(entries);
        const entryIds = entries.map((e: RunbookEntry) => e.id).filter(Boolean) as number[];
        if (entryIds.length > 0) {
          fetchRunbookFeedback(entryIds, alert.fingerprint).then((feedback: RunbookFeedback[]) => {
            const voteMap = new Map<string, 'up' | 'down'>();
            for (const fb of feedback) {
              voteMap.set(`${fb.runbook_entry_id}`, fb.vote);
            }
            setVotes(voteMap);
          });
        }
      })
      .finally(() => setLoadingMatches(false));
    fetchRunbookExclusions(alert.name).then(setExclusions);
  }, [alert.name, host]);

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
      fetchRunbookMatches(alert.name, host || undefined).then((entries) => {
        setMatches(entries);
        const entryIds = entries.map((e: RunbookEntry) => e.id).filter(Boolean) as number[];
        if (entryIds.length > 0) {
          fetchRunbookFeedback(entryIds, alert.fingerprint).then((feedback: RunbookFeedback[]) => {
            const voteMap = new Map<string, 'up' | 'down'>();
            for (const fb of feedback) {
              voteMap.set(`${fb.runbook_entry_id}`, fb.vote);
            }
            setVotes(voteMap);
          });
        }
      });
    } else {
      setSubmitError(true);
    }
  }

  const excludedEntryIds = new Set(exclusions.map(e => e.runbook_entry_id));
  const visibleMatches = matches.filter(m => m.id != null && !excludedEntryIds.has(m.id));
  const excludedMatches = matches.filter(m => m.id != null && excludedEntryIds.has(m.id));

  return (
    <div className="stat-card border-accent/20">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-accent">Runbook &amp; Remediation</h3>
        <span className="text-[10px] text-muted">Build institutional knowledge</span>
      </div>

      {loadingMatches ? (
        <div className="text-xs text-muted animate-pulse mb-3">Loading runbook entries...</div>
      ) : visibleMatches.length > 0 ? (
        <div className="space-y-2 mb-4">
          <div className="text-[10px] text-muted uppercase tracking-wider">
            Past remediations for similar alerts ({visibleMatches.length})
          </div>
          {visibleMatches.map((entry) => (
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
                      <button
                        onClick={async () => {
                          if (!confirm(`Permanently exclude this runbook from all "${alert.name}" alerts?`)) return;
                          const ok = await createRunbookExclusion(alert.name, entry.id!);
                          if (ok) {
                            fetchRunbookExclusions(alert.name).then(setExclusions);
                          }
                        }}
                        className="p-0.5 rounded transition-colors text-muted/30 hover:text-red/70"
                        title="Permanently exclude from this alert type"
                      >
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
                        </svg>
                      </button>
                      <button
                        onClick={async () => {
                          if (!confirm('Delete this runbook entry permanently?')) return;
                          const ok = await deleteRunbookEntry(entry.id!);
                          if (ok) {
                            fetchRunbookMatches(alert.name, host || undefined).then(setMatches);
                          }
                        }}
                        className="p-0.5 rounded transition-colors text-muted/30 hover:text-red/70"
                        title="Delete this runbook entry"
                      >
                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
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

      {/* Excluded runbooks indicator */}
      {excludedMatches.length > 0 && (
        <div className="mb-3">
          <button
            onClick={() => setShowExcluded(!showExcluded)}
            className="text-[10px] text-muted hover:text-text transition-colors"
          >
            {excludedMatches.length} runbook{excludedMatches.length > 1 ? 's' : ''} excluded
            {showExcluded ? ' \u25B2' : ' \u25BC'}
          </button>
          {showExcluded && (
            <div className="space-y-1.5 mt-2">
              {excludedMatches.map(entry => {
                const excl = exclusions.find(e => e.runbook_entry_id === entry.id);
                return (
                  <div key={entry.id} className="bg-bg/50 rounded-md p-2 border border-border/50 opacity-60">
                    <div className="flex items-center gap-2 text-[10px] text-muted">
                      <span className="text-red">Excluded</span>
                      {excl && <span>by {excl.excluded_by}</span>}
                      <button
                        onClick={async () => {
                          if (!excl) return;
                          const ok = await deleteRunbookExclusion(excl.id);
                          if (ok) fetchRunbookExclusions(alert.name).then(setExclusions);
                        }}
                        className="ml-auto text-muted/50 hover:text-accent text-[10px] transition-colors"
                      >
                        Unblock
                      </button>
                    </div>
                    <div className="text-[10px] text-muted truncate mt-0.5">{entry.remediation?.substring(0, 100)}</div>
                  </div>
                );
              })}
            </div>
          )}
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
          className="w-full bg-bg border border-border rounded-md px-2 py-1.5 text-xs text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-none"
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
