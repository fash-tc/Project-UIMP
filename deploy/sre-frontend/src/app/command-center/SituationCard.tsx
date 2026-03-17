'use client';

import { useState, useEffect, useCallback } from 'react';
import { SituationSummary } from '@/lib/types';
import { fetchSituationSummary, severityColor, timeAgo } from '@/lib/keep-api';

interface SituationCardProps {
  onClusterClick?: (fingerprints: string[]) => void;
  sseUpdateTrigger?: number;
}

export default function SituationCard({ onClusterClick, sseUpdateTrigger }: SituationCardProps) {
  const [summary, setSummary] = useState<SituationSummary | null>(null);
  const [expanded, setExpanded] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('situation-card-expanded') === 'true';
    }
    return false;
  });

  const loadSummary = useCallback(async () => {
    const data = await fetchSituationSummary();
    if (data) setSummary(data);
  }, []);

  useEffect(() => {
    loadSummary();
  }, [loadSummary, sseUpdateTrigger]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      localStorage.setItem('situation-card-expanded', String(expanded));
    }
  }, [expanded]);

  if (!summary) return null;

  const severityDotColor = (sev: string) => {
    switch (sev) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'warning': return 'bg-yellow-500';
      case 'info': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const worstSeverity = summary.clusters.reduce((worst, c) => {
    const order: Record<string, number> = { critical: 0, high: 1, warning: 2, low: 3, info: 4 };
    const cSev = c.top_severity || 'info';
    return (order[cSev] ?? 5) < (order[worst] ?? 5) ? cSev : worst;
  }, 'info');

  const trendIcon = summary.shift_context?.trend === 'improving' ? '↓' :
                    summary.shift_context?.trend === 'worsening' ? '↑' : '→';
  const trendColor = summary.shift_context?.trend === 'improving' ? 'text-green-400' :
                     summary.shift_context?.trend === 'worsening' ? 'text-red-400' : 'text-yellow-400';

  return (
    <div className="mb-4">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-4 py-2 bg-surface border border-border rounded-lg hover:bg-surface-hover transition-colors text-left"
      >
        <span className={`w-2.5 h-2.5 rounded-full ${severityDotColor(worstSeverity)} shrink-0`} />
        <span className="text-sm text-text-bright flex-1 truncate">
          {summary.one_liner || 'Generating situation summary...'}
        </span>
        <span className="text-xs text-muted shrink-0">
          {summary.generated_at ? timeAgo(summary.generated_at) : ''}
        </span>
        <svg
          className={`w-4 h-4 text-muted transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="mt-2 p-4 bg-surface border border-border rounded-lg space-y-4">
          {summary.clusters.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-2">Clusters</h4>
              <div className="flex gap-2 overflow-x-auto pb-1">
                {summary.clusters
                  .sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99))
                  .map((cluster) => (
                  <button
                    key={cluster.cluster_id}
                    onClick={() => onClusterClick?.(cluster.fingerprints || [])}
                    className="flex-shrink-0 p-2 bg-background border border-border rounded-md hover:border-accent transition-colors text-left max-w-[280px]"
                  >
                    <div className="flex items-center gap-1.5 mb-1">
                      <span className={`w-2 h-2 rounded-full ${severityDotColor(cluster.top_severity || 'info')}`} />
                      <span className="text-xs font-medium text-text-bright truncate">{cluster.label}</span>
                      <span className="text-xs text-muted ml-auto">{cluster.count}</span>
                    </div>
                    <p className="text-xs text-muted line-clamp-2">{cluster.assessment || ''}</p>
                  </button>
                ))}
              </div>
            </div>
          )}

          {summary.shift_context && (
            <div className="flex items-center gap-3 text-xs text-muted">
              <span>↑{summary.shift_context.new_since_last ?? 0} new</span>
              <span>↓{summary.shift_context.resolved_since_last ?? 0} resolved</span>
              <span className={trendColor}>{trendIcon} {summary.shift_context.trend}</span>
              {summary.shift_context.recurring?.length > 0 && (
                <span className="text-yellow-400">
                  ⟳ {summary.shift_context.recurring[0]}
                </span>
              )}
            </div>
          )}

          {summary.recommended_actions?.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-1">Recommended Actions</h4>
              <ol className="space-y-1">
                {summary.recommended_actions.map((action, i) => (
                  <li key={i} className="text-sm text-text flex gap-2">
                    <span className="text-accent font-medium shrink-0">{i + 1}.</span>
                    <span>{action}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
