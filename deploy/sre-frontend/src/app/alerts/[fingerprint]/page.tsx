'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { Alert, AIEnrichment, SREFeedback, RunbookEntry, AlertState } from '@/lib/types';
import {
  fetchAlertByFingerprint,
  parseAIEnrichment,
  parseSREFeedback,
  submitFeedback,
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
} from '@/lib/keep-api';
import { getClientUsername } from '@/lib/auth';

export default function AlertDetail() {
  const params = useParams();
  const fingerprint = params.fingerprint as string;
  const [alert, setAlert] = useState<Alert | null>(null);
  const [alertState, setAlertState] = useState<AlertState | undefined>(undefined);
  const [loading, setLoading] = useState(true);

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
      {enrichment && (
        <FeedbackPanel
          fingerprint={fingerprint}
          currentNote={alert.note}
          existingFeedback={parseSREFeedback(alert.note)}
          enrichment={enrichment}
          onFeedbackSubmitted={loadAlert}
        />
      )}

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
  currentNote,
  existingFeedback,
  enrichment,
  onFeedbackSubmitted,
}: {
  fingerprint: string;
  currentNote: string | undefined | null;
  existingFeedback: SREFeedback | null;
  enrichment: { assessed_severity: string; noise_score: number };
  onFeedbackSubmitted?: () => void;
}) {
  const [rating, setRating] = useState<'positive' | 'negative' | null>(
    existingFeedback?.rating === 'positive' ? 'positive' :
    existingFeedback?.rating ? 'negative' : null
  );
  const [correctedSeverity, setCorrectedSeverity] = useState(
    existingFeedback?.corrected_severity ?? ''
  );
  const [correctedNoise, setCorrectedNoise] = useState(
    existingFeedback?.corrected_noise?.toString() ?? ''
  );
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

    const ok = await submitFeedback(fingerprint, currentNote, feedback);
    setSubmitting(false);
    if (ok) {
      setSubmitted(true);
      setEditing(false);
      setJustSubmitted(true);
      // Refresh the alert data to reflect the stored feedback
      if (onFeedbackSubmitted) {
        setTimeout(onFeedbackSubmitted, 500);
      }
    } else {
      setSubmitError(true);
    }
  }

  return (
    <div className="stat-card border-accent/20">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-accent">SRE Feedback</h3>
        <span className="text-xs text-muted">Help improve AI analysis</span>
      </div>

      {/* Confirmation banner */}
      {justSubmitted && (
        <div className="bg-green/10 border border-green/30 rounded-lg px-4 py-3 mb-4">
          <div className="flex items-start gap-3">
            <span className="text-green text-lg leading-none">{'\u2713'}</span>
            <div>
              <div className="text-sm font-medium text-green">Feedback submitted successfully</div>
              <div className="text-xs text-muted mt-1">
                Your feedback has been saved and will be ingested by the AI enricher on the next analysis cycle (~60s).
                {rating === 'negative' && ' The AI will apply your corrections when analyzing similar alerts in the future.'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Error banner */}
      {submitError && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 mb-4">
          <div className="text-sm text-red">Failed to submit feedback. Please try again.</div>
        </div>
      )}

      {submitted && !editing ? (
        <div className="space-y-3">
          <div className="flex items-center gap-3 text-sm">
            <span className={`text-lg ${rating === 'positive' ? 'text-green' : 'text-red'}`}>
              {rating === 'positive' ? '\u2713' : '\u2717'}
            </span>
            <span className="text-text">
              {rating === 'positive' ? 'Analysis confirmed as accurate' : 'Analysis needs correction'}
            </span>
            {sreUser && (
              <span className="text-muted text-xs">by {sreUser}</span>
            )}
          </div>
          {(correctedSeverity || correctedNoise) && (
            <div className="flex gap-4 text-xs text-muted">
              {correctedSeverity && (
                <span>Corrected severity: <span className={`font-medium ${severityColor(correctedSeverity)}`}>{correctedSeverity}</span></span>
              )}
              {correctedNoise && (
                <span>Corrected noise: <span className="font-medium text-text">{correctedNoise}/10</span></span>
              )}
            </div>
          )}
          {comment && (
            <div className="text-sm text-text bg-bg rounded-md p-2 border border-border">
              {comment}
            </div>
          )}
          <button
            onClick={() => { setEditing(true); setJustSubmitted(false); }}
            className="text-xs text-accent hover:text-accent-hover transition-colors"
          >
            Update feedback
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Quick rating */}
          <div>
            <div className="text-xs text-muted mb-2">Is this analysis accurate?</div>
            <div className="flex gap-2">
              <button
                onClick={() => setRating('positive')}
                className={`px-4 py-2 rounded-md border text-sm font-medium transition-all ${
                  rating === 'positive'
                    ? 'border-green bg-green/10 text-green'
                    : 'border-border text-muted hover:border-green/50 hover:text-green'
                }`}
              >
                &#x2713; Accurate
              </button>
              <button
                onClick={() => setRating('negative')}
                className={`px-4 py-2 rounded-md border text-sm font-medium transition-all ${
                  rating === 'negative'
                    ? 'border-red bg-red/10 text-red'
                    : 'border-border text-muted hover:border-red/50 hover:text-red'
                }`}
              >
                &#x2717; Needs correction
              </button>
            </div>
          </div>

          {/* Correction fields — shown when negative */}
          {rating === 'negative' && (
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
                maxLength={500}
                rows={2}
                placeholder={rating === 'positive'
                  ? 'Any additional context...'
                  : 'e.g. "This is a known maintenance window alert, noise score should be higher"'
                }
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text placeholder-muted/50 focus:border-accent focus:outline-none resize-none"
              />
              <div className="text-xs text-muted text-right mt-1">{comment.length}/500</div>
            </div>
          )}

          {/* Submit */}
          {rating && (
            <div className="flex items-end gap-3">
              {sreUser && <span className="text-xs text-muted py-2">as {sreUser}</span>}
              <button
                onClick={handleSubmit}
                disabled={submitting || !rating}
                className="px-5 py-2 rounded-md bg-accent text-bg font-medium text-sm hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? 'Submitting...' : 'Submit Feedback'}
              </button>
              {editing && (
                <button
                  onClick={() => setEditing(false)}
                  className="px-3 py-2 rounded-md border border-border text-muted text-sm hover:text-text transition-colors"
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
    <div className="stat-card border-accent/20">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-accent">Runbook &amp; Remediation</h3>
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
