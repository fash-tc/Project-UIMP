'use client';

import { useMemo, useState } from 'react';
import { Alert } from '@/lib/types';
import { getSourceLabel, parseAIEnrichment } from '@/lib/keep-api';

interface BulkIncidentTicketModalProps {
  alerts: Alert[];
  shouldOfferGrouping: boolean;
  defaultGroupName: string;
  onSubmit: (data: {
    summary: string;
    description: string;
    classId: string;
    operationalServiceId?: string;
    createGroup: boolean;
    groupName: string;
  }) => Promise<{ ok: boolean; issueKey?: string; issueUrl?: string; error?: string }>;
  onClose: () => void;
}

const SEVERITY_CLASS_MAP: Record<string, string> = {
  critical: '11227',
  high: '11228',
  warning: '11229',
  low: '11230',
  info: '11230',
  unknown: '11230',
};

function detectServiceId(alerts: Alert[]): string {
  const text = alerts.map(alert => `${alert.name || ''} ${alert.hostName || alert.hostname || ''}`.toLowerCase()).join(' ');
  if (text.includes('ascio')) return '11231';
  if (text.includes('enom')) return '11232';
  if (text.includes('opensrs')) return '11233';
  if (text.includes('hover')) return '11234';
  if (text.includes('hosted') && text.includes('email')) return '11235';
  if (text.includes('exacthosting')) return '11236';
  if (text.includes('trs')) return '11239';
  return '11237';
}

function deriveDefaultDescription(alerts: Alert[]): string {
  return alerts.map((alert, index) => {
    const host = alert.hostName || alert.hostname || 'Unknown host';
    const details = [
      `${index + 1}. ${alert.name || 'Unknown alert'}`,
      `Host: ${host}`,
      `Source: ${getSourceLabel(alert)}`,
      alert.description && alert.description !== alert.name ? `Details: ${alert.description}` : null,
    ].filter(Boolean);
    return details.join('\n');
  }).join('\n\n');
}

export default function BulkIncidentTicketModal({
  alerts,
  shouldOfferGrouping,
  defaultGroupName,
  onSubmit,
  onClose,
}: BulkIncidentTicketModalProps) {
  const [summary, setSummary] = useState(() => alerts.length === 1 ? (alerts[0].name || 'Incident') : `${alerts.length} selected alerts incident`);
  const [description, setDescription] = useState(() => deriveDefaultDescription(alerts));
  const [classId, setClassId] = useState(() => {
    const severities = alerts.map(alert => parseAIEnrichment(alert.note)?.assessed_severity || alert.severity || 'unknown');
    const selected = severities.includes('critical')
      ? 'critical'
      : severities.includes('high')
        ? 'high'
        : severities.includes('warning')
          ? 'warning'
          : severities.includes('low')
            ? 'low'
            : 'info';
    return SEVERITY_CLASS_MAP[selected] || '11230';
  });
  const [serviceId, setServiceId] = useState(() => detectServiceId(alerts));
  const [createGroup, setCreateGroup] = useState(false);
  const [groupName, setGroupName] = useState(defaultGroupName);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  const alertPreview = useMemo(() => alerts.slice(0, 5), [alerts]);

  async function handleSubmit() {
    if (!summary.trim()) return;
    if (createGroup && !groupName.trim()) {
      setError('Enter a custom group name or turn off grouping.');
      return;
    }
    setSubmitting(true);
    setError('');
    const result = await onSubmit({
      summary: summary.trim(),
      description: description.trim(),
      classId,
      operationalServiceId: serviceId || undefined,
      createGroup,
      groupName: groupName.trim(),
    });
    setSubmitting(false);
    if (!result.ok) {
      setError(result.error || 'Failed to create ticket');
      return;
    }
    onClose();
  }

  return (
    <div className="fixed inset-0 z-[110] flex items-start justify-center">
      <div className="absolute inset-0 bg-bg/80 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-3xl mt-[6vh] mx-4 bg-surface border border-border rounded-xl shadow-2xl max-h-[88vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div>
            <h3 className="text-base font-semibold text-text-bright">Create Ticket For Selected Alerts</h3>
            <p className="text-xs text-muted mt-1">{alerts.length} alerts will share the same Jira ticket.</p>
          </div>
          <button onClick={onClose} className="text-muted hover:text-text text-sm">Close</button>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto">
          {error && (
            <div className="bg-red/10 border border-red/30 rounded px-3 py-2 text-xs text-red">{error}</div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="md:col-span-2">
              <label className="text-[10px] text-muted block mb-1">Ticket Title</label>
              <input
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
              />
            </div>

            <div>
              <label className="text-[10px] text-muted block mb-1">Class</label>
              <select
                value={classId}
                onChange={(e) => setClassId(e.target.value)}
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
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
                className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
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

          <div>
            <label className="text-[10px] text-muted block mb-1">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={10}
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none resize-y"
            />
          </div>

          {shouldOfferGrouping && (
            <div className="bg-bg/50 border border-border rounded-lg p-4 space-y-3">
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={createGroup}
                  onChange={(e) => setCreateGroup(e.target.checked)}
                  className="mt-0.5"
                />
                <span>
                  <span className="block text-sm text-text-bright">Also create a temporary custom group for these alerts</span>
                  <span className="block text-xs text-muted mt-1">This group will be shared with all users and disappear once all member alerts clear.</span>
                </span>
              </label>
              {createGroup && (
                <div>
                  <label className="text-[10px] text-muted block mb-1">Custom Group Name</label>
                  <input
                    value={groupName}
                    onChange={(e) => setGroupName(e.target.value)}
                    className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text focus:border-accent focus:outline-none"
                    placeholder="Enter a shared temporary group name"
                  />
                </div>
              )}
            </div>
          )}

          <div className="bg-bg/50 border border-border rounded-lg p-4">
            <div className="text-[10px] uppercase tracking-wide text-muted mb-2">Selected Alerts Preview</div>
            <div className="space-y-2">
              {alertPreview.map((alert) => (
                <div key={alert.fingerprint} className="text-xs text-text-bright">
                  <span className="font-medium">{alert.name || 'Unknown alert'}</span>
                  <span className="text-muted"> on {alert.hostName || alert.hostname || 'Unknown host'}</span>
                </div>
              ))}
              {alerts.length > alertPreview.length && (
                <div className="text-xs text-muted">+ {alerts.length - alertPreview.length} more alerts</div>
              )}
            </div>
          </div>

        </div>
        <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-border bg-surface">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-md border border-border text-sm text-muted hover:text-text transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting || !summary.trim()}
            className="px-4 py-2 rounded-md bg-accent text-bg text-sm font-medium hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {submitting ? 'Creating Ticket...' : 'Create Shared Ticket'}
          </button>
        </div>
      </div>
    </div>
  );
}
