'use client';

import { useState } from 'react';
import { Alert, IncidentAssessment, StatuspageComponent } from '@/lib/types';
import {
  assessIncidentDescription,
  sendIncidentWebhook,
  fetchStatuspageComponents,
  createStatuspageIncident,
} from '@/lib/keep-api';

interface Props {
  alert?: Alert;
  onClose: () => void;
}

const GRADE_COLORS: Record<string, string> = {
  A: 'text-green border-green/40 bg-green/10',
  B: 'text-green border-green/30 bg-green/5',
  C: 'text-yellow border-yellow/40 bg-yellow/10',
  D: 'text-orange border-orange/40 bg-orange/10',
  F: 'text-red border-red/40 bg-red/10',
  '?': 'text-muted border-border bg-surface',
};

export default function IncidentWizard({ alert, onClose }: Props) {
  const [step, setStep] = useState<1 | 2 | 3 | 'done'>(1);

  // Step 1: Incident details
  const host = alert?.hostName || alert?.hostname || '';
  const [title, setTitle] = useState(alert?.name || 'Service Disruption');
  const [description, setDescription] = useState('');
  const [assessing, setAssessing] = useState(false);
  const [assessment, setAssessment] = useState<IncidentAssessment | null>(null);

  // Step 2: Webhook
  const [sending, setSending] = useState(false);
  const [webhookResult, setWebhookResult] = useState<{ ok: boolean; error?: string } | null>(null);

  // Step 3: Statuspage
  const [showStatuspage, setShowStatuspage] = useState<boolean | null>(null);
  const [components, setComponents] = useState<StatuspageComponent[]>([]);
  const [loadingComponents, setLoadingComponents] = useState(false);
  const [selectedComponents, setSelectedComponents] = useState<string[]>([]);
  const [spStatus, setSpStatus] = useState('investigating');
  const [spImpact, setSpImpact] = useState('minor');
  const [spTitle, setSpTitle] = useState('');
  const [spBody, setSpBody] = useState('');
  const [creatingStatuspage, setCreatingStatuspage] = useState(false);
  const [statuspageResult, setStatuspageResult] = useState<{ shortlink?: string; error?: string } | null>(null);

  async function handleAssess() {
    setAssessing(true);
    const result = await assessIncidentDescription(title, description);
    setAssessment(result);
    setAssessing(false);
  }

  async function handleSendWebhook() {
    setSending(true);
    const started = alert?.firingStartTime || alert?.startedAt || new Date().toISOString();
    const result = await sendIncidentWebhook(title, description, started);
    setWebhookResult(result);
    setSending(false);
  }

  async function handleLoadComponents() {
    setLoadingComponents(true);
    const comps = await fetchStatuspageComponents();
    setComponents(comps);
    setSpTitle(title);
    setSpBody(description);
    setLoadingComponents(false);
  }

  async function handleCreateStatuspage() {
    setCreatingStatuspage(true);
    const { result, error } = await createStatuspageIncident({
      name: spTitle,
      body: spBody,
      component_ids: selectedComponents,
      status: spStatus,
      impact_override: spImpact,
    });
    if (error) {
      setStatuspageResult({ error });
    } else if (result) {
      setStatuspageResult({ shortlink: result.shortlink });
    }
    setCreatingStatuspage(false);
  }

  function toggleComponent(id: string) {
    setSelectedComponents(prev =>
      prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id]
    );
  }

  const stepLabels = ['Details', 'Notify', 'Statuspage'];

  return (
    <div className="bg-surface border border-orange/20 rounded-lg p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-orange">Create Incident</h4>
        <button onClick={onClose} className="text-muted hover:text-text text-xs">Cancel</button>
      </div>

      {/* Step indicator */}
      <div className="flex items-center gap-2">
        {stepLabels.map((label, i) => {
          const num = i + 1;
          const isCurrent = step === num;
          const isDone = step === 'done' || (typeof step === 'number' && num < step);
          return (
            <div key={label} className="flex items-center gap-1.5">
              {i > 0 && <div className={`w-6 h-px ${isDone ? 'bg-green' : 'bg-border'}`} />}
              <div className={`flex items-center gap-1 text-xs font-medium ${
                isCurrent ? 'text-orange' : isDone ? 'text-green' : 'text-muted'
              }`}>
                <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] border ${
                  isCurrent ? 'border-orange bg-orange/10' : isDone ? 'border-green bg-green/10' : 'border-border'
                }`}>
                  {isDone ? '✓' : num}
                </span>
                {label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Step 1: Incident Details + AI Assessment */}
      {step === 1 && (
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-muted mb-1">Incident Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
              placeholder="Brief incident title for customers"
            />
          </div>

          <div>
            <label className="block text-xs text-muted mb-1">
              Description <span className="text-orange">(customer-facing — do not include internal details)</span>
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={4}
              className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text focus:outline-none focus:border-accent resize-y"
              placeholder="Describe the incident in customer-appropriate language. Avoid hostnames, IPs, internal ticket numbers, or technical jargon."
            />
          </div>

          {/* AI Assessment */}
          <div className="flex items-center gap-2">
            <button
              onClick={handleAssess}
              disabled={assessing || !description.trim()}
              className="px-3 py-1.5 rounded border border-accent/40 text-xs font-medium text-accent hover:bg-accent/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {assessing ? 'Assessing...' : assessment ? 'Re-assess' : 'AI Assess'}
            </button>
            {assessment && (
              <div className={`inline-flex items-center gap-2 px-3 py-1 rounded border text-xs font-bold ${GRADE_COLORS[assessment.grade] || GRADE_COLORS['?']}`}>
                Grade: {assessment.grade}
              </div>
            )}
          </div>

          {assessment && (
            <div className={`text-xs p-3 rounded border ${GRADE_COLORS[assessment.grade] || GRADE_COLORS['?']}`}>
              {assessment.feedback}
            </div>
          )}

          <div className="flex justify-end">
            <button
              onClick={() => setStep(2)}
              disabled={!title.trim()}
              className="px-4 py-1.5 rounded bg-orange/20 border border-orange/40 text-xs font-medium text-orange hover:bg-orange/30 disabled:opacity-50 transition-colors"
            >
              Next: Send Notification →
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Webhook Notification */}
      {step === 2 && (
        <div className="space-y-3">
          <div className="text-xs text-muted">
            The following incident notification will be sent to all active webhook subscribers:
          </div>

          {/* Payload preview */}
          <div className="bg-bg border border-border rounded p-3 text-xs font-mono text-muted overflow-x-auto">
            <pre>{JSON.stringify({
              event_type: 'incident',
              incident: {
                title,
                description,
                source: 'uip_sre',
                started_at: alert?.firingStartTime || alert?.startedAt || new Date().toISOString(),
              },
            }, null, 2)}</pre>
          </div>

          {!webhookResult ? (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setStep(1)}
                className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
              >
                ← Back
              </button>
              <button
                onClick={handleSendWebhook}
                disabled={sending}
                className="px-4 py-1.5 rounded bg-orange/20 border border-orange/40 text-xs font-medium text-orange hover:bg-orange/30 disabled:opacity-50 transition-colors"
              >
                {sending ? 'Sending...' : 'Send Notification'}
              </button>
            </div>
          ) : webhookResult.ok ? (
            <div className="space-y-2">
              <div className="bg-green/10 border border-green/30 rounded px-3 py-2 text-xs text-green">
                Incident notification sent to all active subscribers.
              </div>
              <button
                onClick={() => setStep(3)}
                className="px-4 py-1.5 rounded bg-orange/20 border border-orange/40 text-xs font-medium text-orange hover:bg-orange/30 transition-colors"
              >
                Next: Statuspage →
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">
                Failed to send: {webhookResult.error}
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => { setWebhookResult(null); }}
                  className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
                >
                  Retry
                </button>
                <button
                  onClick={() => setStep(3)}
                  className="px-3 py-1.5 rounded border border-orange/40 text-xs text-orange hover:bg-orange/10 transition-colors"
                >
                  Skip to Statuspage →
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Step 3: Statuspage Incident */}
      {step === 3 && (
        <div className="space-y-3">
          {showStatuspage === null && (
            <div className="space-y-3">
              <div className="text-xs text-muted">Would you also like to create a Statuspage incident?</div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setShowStatuspage(true);
                    handleLoadComponents();
                  }}
                  className="px-4 py-1.5 rounded bg-accent/20 border border-accent/40 text-xs font-medium text-accent hover:bg-accent/30 transition-colors"
                >
                  Yes, create Statuspage incident
                </button>
                <button
                  onClick={() => setStep('done')}
                  className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
                >
                  Skip
                </button>
              </div>
            </div>
          )}

          {showStatuspage === true && !statuspageResult && (
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-muted mb-1">Statuspage Title</label>
                <input
                  type="text"
                  value={spTitle}
                  onChange={(e) => setSpTitle(e.target.value)}
                  className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
                />
              </div>

              <div>
                <label className="block text-xs text-muted mb-1">Statuspage Body</label>
                <textarea
                  value={spBody}
                  onChange={(e) => setSpBody(e.target.value)}
                  rows={3}
                  className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text focus:outline-none focus:border-accent resize-y"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-muted mb-1">Impact</label>
                  <select
                    value={spImpact}
                    onChange={(e) => setSpImpact(e.target.value)}
                    className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text"
                  >
                    <option value="none">None</option>
                    <option value="minor">Minor</option>
                    <option value="major">Major</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-muted mb-1">Status</label>
                  <select
                    value={spStatus}
                    onChange={(e) => setSpStatus(e.target.value)}
                    className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text"
                  >
                    <option value="investigating">Investigating</option>
                    <option value="identified">Identified</option>
                    <option value="monitoring">Monitoring</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </div>
              </div>

              {/* Component picker */}
              <div>
                <label className="block text-xs text-muted mb-1">Affected Components</label>
                {loadingComponents ? (
                  <div className="text-xs text-muted animate-pulse">Loading components...</div>
                ) : components.length === 0 ? (
                  <div className="text-xs text-muted">No components available (check Statuspage API key)</div>
                ) : (
                  <div className="grid grid-cols-2 gap-1 max-h-40 overflow-y-auto">
                    {components.map(c => (
                      <label
                        key={c.id}
                        className={`flex items-center gap-2 px-2 py-1.5 rounded border text-xs cursor-pointer transition-colors ${
                          selectedComponents.includes(c.id)
                            ? 'border-accent/40 bg-accent/10 text-accent'
                            : 'border-border text-muted hover:border-border hover:text-text'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={selectedComponents.includes(c.id)}
                          onChange={() => toggleComponent(c.id)}
                          className="accent-[#6c5ce7]"
                        />
                        {c.name}
                      </label>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowStatuspage(null)}
                  className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
                >
                  ← Back
                </button>
                <button
                  onClick={handleCreateStatuspage}
                  disabled={creatingStatuspage || !spTitle.trim()}
                  className="px-4 py-1.5 rounded bg-accent/20 border border-accent/40 text-xs font-medium text-accent hover:bg-accent/30 disabled:opacity-50 transition-colors"
                >
                  {creatingStatuspage ? 'Creating...' : 'Create Statuspage Incident'}
                </button>
              </div>
            </div>
          )}

          {statuspageResult && (
            <div className="space-y-2">
              {statuspageResult.shortlink ? (
                <div className="bg-green/10 border border-green/30 rounded px-3 py-2 text-xs text-green">
                  Statuspage incident created:{' '}
                  <a href={statuspageResult.shortlink} target="_blank" rel="noreferrer" className="underline">
                    {statuspageResult.shortlink}
                  </a>
                </div>
              ) : (
                <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">
                  Failed: {statuspageResult.error}
                </div>
              )}
              <button
                onClick={() => setStep('done')}
                className="px-3 py-1.5 rounded border border-green/40 text-xs text-green hover:bg-green/10 transition-colors"
              >
                Done
              </button>
            </div>
          )}
        </div>
      )}

      {/* Done */}
      {step === 'done' && (
        <div className="space-y-2">
          <div className="bg-green/10 border border-green/30 rounded px-3 py-2 text-xs text-green">
            Incident process complete.
          </div>
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded border border-border text-xs text-muted hover:text-text transition-colors"
          >
            Close
          </button>
        </div>
      )}
    </div>
  );
}
