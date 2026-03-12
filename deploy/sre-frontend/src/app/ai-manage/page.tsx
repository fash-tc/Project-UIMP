'use client';

import { useEffect, useState, useCallback } from 'react';
import { AIInstruction, AIFeedbackSummary, RunbookEntry } from '@/lib/types';
import {
  fetchAIInstructions,
  createAIInstruction,
  deleteAIInstruction,
  fetchAIFeedbackSummary,
} from '@/lib/keep-api';
import { getClientUsername } from '@/lib/auth';

export default function AIManagePage() {
  const [summary, setSummary] = useState<AIFeedbackSummary | null>(null);
  const [instructions, setInstructions] = useState<AIInstruction[]>([]);
  const [newInstruction, setNewInstruction] = useState('');
  const [sreName] = useState(() => getClientUsername() || '');
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    const [sum, instr] = await Promise.all([
      fetchAIFeedbackSummary(),
      fetchAIInstructions(),
    ]);
    setSummary(sum);
    setInstructions(instr);
    setLoading(false);
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  async function handleSubmit() {
    if (!newInstruction.trim()) return;
    setSubmitting(true);
    const ok = await createAIInstruction(newInstruction.trim(), sreName || undefined);
    setSubmitting(false);
    if (ok) {
      setNewInstruction('');
      setSuccess('Instruction added');
      setTimeout(() => setSuccess(''), 3000);
      loadData();
    }
  }

  async function handleDelete(id: number) {
    const ok = await deleteAIInstruction(id);
    if (ok) loadData();
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-muted animate-pulse">Loading AI management...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-bright">AI Enricher Management</h1>
          <p className="text-sm text-muted mt-1">Configure instructions and review what the AI has learned</p>
        </div>
        <a
          href="/portal/health"
          className="text-xs text-accent hover:text-accent-hover transition-colors"
        >
          &larr; Back to Health
        </a>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <div className="stat-card">
          <div className="text-xs text-muted uppercase tracking-wider mb-1">Runbook Entries</div>
          <div className="text-3xl font-bold text-text-bright">{summary?.total_runbook_entries ?? 0}</div>
        </div>
        <div className="stat-card">
          <div className="text-xs text-muted uppercase tracking-wider mb-1">Active Instructions</div>
          <div className="text-3xl font-bold text-accent">{instructions.length}</div>
        </div>
        <div className="stat-card">
          <div className="text-xs text-muted uppercase tracking-wider mb-1">Recent Entries</div>
          <div className="text-3xl font-bold text-text-bright">{summary?.recent_entries?.length ?? 0}</div>
        </div>
      </div>

      {/* Global AI Instructions */}
      <div className="stat-card space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-text-bright">Global AI Instructions</h3>
          <span className="text-[10px] text-muted">{instructions.length} active</span>
        </div>

        <p className="text-xs text-muted">
          These instructions are injected into every AI enrichment prompt. Use them to guide the LLM on how to assess alerts for your environment.
        </p>

        {instructions.length > 0 ? (
          <div className="space-y-2">
            {instructions.map(instr => (
              <div key={instr.id} className="border border-accent/20 rounded-md px-4 py-3 bg-accent/5">
                <div className="flex items-start justify-between gap-3">
                  <div className="text-sm text-text flex-1">&ldquo;{instr.instruction}&rdquo;</div>
                  <button
                    onClick={() => handleDelete(instr.id)}
                    className="text-xs text-red hover:text-red/80 flex-shrink-0 px-2 py-1 rounded hover:bg-red/10 transition-colors"
                  >
                    Delete
                  </button>
                </div>
                <div className="text-[10px] text-muted mt-2">
                  {instr.sre_user && `by ${instr.sre_user} — `}
                  {instr.created_at?.split('T')[0] || instr.created_at?.split(' ')[0]}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-muted bg-bg/40 border border-border rounded-md px-4 py-3">
            No instructions set. Add instructions below to guide the AI enricher.
          </div>
        )}

        {/* Add Instruction Form */}
        <div className="border-t border-border pt-4">
          <div className="text-xs text-muted mb-2">Add new instruction:</div>
          <textarea
            value={newInstruction}
            onChange={e => setNewInstruction(e.target.value)}
            placeholder="e.g., Always suggest checking DNS recursion first for DNS-related alerts"
            className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text placeholder:text-muted/50 focus:outline-none focus:ring-1 focus:ring-accent resize-none"
            rows={3}
            maxLength={2000}
          />
          <div className="flex items-center gap-3 mt-2">
            {sreName && <span className="text-xs text-muted">as {sreName}</span>}
            <button
              onClick={handleSubmit}
              disabled={submitting || !newInstruction.trim()}
              className="px-4 py-1.5 bg-accent text-bg font-medium text-xs rounded-md hover:bg-accent-hover transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? 'Saving...' : 'Add Instruction'}
            </button>
            {success && <span className="text-xs text-green">{success}</span>}
          </div>
        </div>
      </div>

      {/* Recent Runbook Entries */}
      <div className="stat-card space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-medium text-text-bright">Recent Runbook Entries</h3>
          <span className="text-[10px] text-muted">What the AI has learned from SRE feedback</span>
        </div>

        {summary?.recent_entries && summary.recent_entries.length > 0 ? (
          <div className="space-y-2">
            {summary.recent_entries.map((entry: RunbookEntry) => (
              <div key={entry.id} className="border border-border/50 rounded-md px-4 py-3 bg-bg/50">
                <div className="flex items-center gap-2 text-[11px] text-muted mb-1.5">
                  <span>{entry.created_at?.split('T')[0] || entry.created_at?.split(' ')[0]}</span>
                  {entry.sre_user && <span>by <span className="text-text">{entry.sre_user}</span></span>}
                  {entry.hostname && <span className="font-mono text-accent">{entry.hostname}</span>}
                  {entry.severity && <span className="badge bg-muted/10 border-muted/30 text-[10px]">{entry.severity}</span>}
                </div>
                <div className="text-sm text-text-bright mb-1">{entry.alert_name}</div>
                <div className="text-xs text-muted">{entry.remediation}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-sm text-muted bg-bg/40 border border-border rounded-md px-4 py-3">
            No runbook entries yet. SRE remediation notes submitted on alert detail pages will appear here.
          </div>
        )}
      </div>
    </div>
  );
}
