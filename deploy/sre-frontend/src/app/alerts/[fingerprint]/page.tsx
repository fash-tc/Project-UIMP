'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { Alert, SREFeedback } from '@/lib/types';
import {
  fetchAlertByFingerprint,
  parseAIEnrichment,
  parseSREFeedback,
  submitFeedback,
  severityColor,
  severityBg,
  timeAgo,
} from '@/lib/keep-api';

export default function AlertDetail() {
  const params = useParams();
  const fingerprint = params.fingerprint as string;
  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);

  const loadAlert = () => {
    if (!fingerprint) return;
    fetchAlertByFingerprint(fingerprint)
      .then(setAlert)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

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
  const source = Array.isArray(alert.source) ? alert.source.join(', ') : String(alert.source || '');

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <a href="/portal/alerts" className="text-xs text-accent hover:text-accent-hover mb-2 inline-block">
          &larr; Back to alerts
        </a>
        <h1 className="text-xl font-bold text-text-bright">{alert.name}</h1>
        <div className="flex flex-wrap gap-3 mt-2 text-xs text-muted">
          <span>Host: <span className="text-text font-mono">{host}</span></span>
          <span>Source: <span className="text-text">{source}</span></span>
          <span>Status: <span className="text-text">{alert.status}</span></span>
          <span>Time: <span className="text-text">{timeAgo(alert.lastReceived)}</span></span>
          {alert.fingerprint && <span>FP: <span className="text-text font-mono">{alert.fingerprint.substring(0, 16)}...</span></span>}
        </div>
      </div>

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
  const [sreUser, setSreUser] = useState(existingFeedback?.sre_user ?? '');
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(!!existingFeedback);
  const [editing, setEditing] = useState(false);
  const [justSubmitted, setJustSubmitted] = useState(false);
  const [submitError, setSubmitError] = useState(false);

  useEffect(() => {
    if (!sreUser) {
      const stored = typeof window !== 'undefined' ? localStorage.getItem('uip-sre-user') : null;
      if (stored) setSreUser(stored);
    }
  }, []);

  async function handleSubmit() {
    if (!rating) return;
    setSubmitting(true);
    setSubmitError(false);
    if (sreUser && typeof window !== 'undefined') {
      localStorage.setItem('uip-sre-user', sreUser);
    }

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

          {/* SRE name + submit */}
          {rating && (
            <div className="flex items-end gap-3">
              <div className="flex-1">
                <label className="text-xs text-muted block mb-1">Your name</label>
                <input
                  type="text"
                  value={sreUser}
                  onChange={(e) => setSreUser(e.target.value)}
                  placeholder="e.g. jsmith"
                  className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text placeholder-muted/50 focus:border-accent focus:outline-none"
                />
              </div>
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
