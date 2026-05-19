'use client';

import { StatuspageComponent, StatuspageComponentUpdate } from '@/lib/types';
import StatuspageComponentStatusPicker from './StatuspageComponentStatusPicker';

export default function StatuspageIncidentEditor({
  title,
  body,
  status,
  impact,
  components,
  componentUpdates,
  loadingComponents = false,
  resolving = false,
  submitting = false,
  submitLabel,
  onChangeTitle,
  onChangeBody,
  onChangeStatus,
  onChangeImpact,
  onChangeComponents,
  onSubmit,
}: {
  title: string;
  body: string;
  status: string;
  impact: string;
  components: StatuspageComponent[];
  componentUpdates: StatuspageComponentUpdate[];
  loadingComponents?: boolean;
  resolving?: boolean;
  submitting?: boolean;
  submitLabel: string;
  onChangeTitle: (value: string) => void;
  onChangeBody: (value: string) => void;
  onChangeStatus: (value: string) => void;
  onChangeImpact: (value: string) => void;
  onChangeComponents: (value: StatuspageComponentUpdate[]) => void;
  onSubmit: () => void;
}) {
  return (
    <div className="space-y-3">
      {resolving && (
        <div className="bg-yellow/10 border border-yellow/30 rounded px-3 py-2 text-xs text-yellow">
          If service is restored, reset affected components to Operational as well.
        </div>
      )}

      <div>
        <label className="block text-xs text-muted mb-1">Statuspage Title</label>
        <input
          type="text"
          value={title}
          onChange={(e) => onChangeTitle(e.target.value)}
          className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text focus:outline-none focus:border-accent"
        />
      </div>

      <div>
        <label className="block text-xs text-muted mb-1">Statuspage Body</label>
        <textarea
          value={body}
          onChange={(e) => onChangeBody(e.target.value)}
          rows={3}
          className="w-full bg-bg border border-border rounded px-3 py-2 text-sm text-text focus:outline-none focus:border-accent resize-y"
        />
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-muted mb-1">Impact</label>
          <select
            value={impact}
            onChange={(e) => onChangeImpact(e.target.value)}
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
            value={status}
            onChange={(e) => onChangeStatus(e.target.value)}
            className="w-full bg-bg border border-border rounded px-3 py-1.5 text-sm text-text"
          >
            <option value="investigating">Investigating</option>
            <option value="identified">Identified</option>
            <option value="monitoring">Monitoring</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-xs text-muted mb-1">Affected Components</label>
        {loadingComponents ? (
          <div className="text-xs text-muted animate-pulse">Loading components...</div>
        ) : (
          <StatuspageComponentStatusPicker
            components={components}
            value={componentUpdates}
            onChange={onChangeComponents}
          />
        )}
      </div>

      <button
        onClick={onSubmit}
        disabled={submitting || !title.trim()}
        className="px-4 py-1.5 rounded bg-accent/20 border border-accent/40 text-xs font-medium text-accent hover:bg-accent/30 disabled:opacity-50 transition-colors"
      >
        {submitting ? 'Saving...' : submitLabel}
      </button>
    </div>
  );
}
