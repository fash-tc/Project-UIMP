'use client';

import { useState, useEffect, useCallback } from 'react';
import { SituationSummary } from '@/lib/types';
import { fetchSituationSummary, severityColor, timeAgo } from '@/lib/keep-api';

interface SituationCardProps {
  onClusterClick?: (fingerprints: string[]) => void;
  sseUpdateTrigger?: number;
  firingCount?: number;
}

export default function SituationCard({ onClusterClick, sseUpdateTrigger, firingCount = 0 }: SituationCardProps) {
  const [summary, setSummary] = useState<SituationSummary | null>(null);
  const [expanded, setExpanded] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('situation-card-expanded') === 'true';
    }
    return false;
  });
  const [expandedCluster, setExpandedCluster] = useState<string | null>(null);

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

  // No firing alerts — show a clean "all clear" message
  if (firingCount === 0) {
    return (
      <div className="mb-4">
        <div className="w-full flex items-center gap-2 px-4 py-2.5 bg-surface border border-border rounded-lg">
          <span className="w-2.5 h-2.5 rounded-full bg-green-500 shrink-0" />
          <span className="text-xs font-medium text-accent shrink-0">✦ AI Summary</span>
          <span className="text-sm text-green-400 flex-1">No issues currently ongoing</span>
        </div>
      </div>
    );
  }

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
  const generatedAt = summary.generated_at ? new Date(summary.generated_at) : null;
  const isStale = Boolean(
    generatedAt &&
    !Number.isNaN(generatedAt.getTime()) &&
    (Date.now() - generatedAt.getTime()) > 15 * 60 * 1000,
  );

  return (
    <div className="mb-4">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-start gap-2 px-4 py-2.5 bg-surface border border-border rounded-lg hover:bg-surface-hover transition-colors text-left"
      >
        <span className={`w-2.5 h-2.5 rounded-full ${severityDotColor(worstSeverity)} shrink-0 mt-1`} />
        <span className="text-xs font-medium text-accent shrink-0 mt-0.5">✦ AI Summary</span>
        <span className="text-sm text-text-bright flex-1">
          {summary.one_liner || 'Generating situation summary...'}
        </span>
        {isStale && (
          <span className="text-[10px] uppercase tracking-wide text-orange-300 border border-orange-400/40 rounded px-1.5 py-0.5 shrink-0 mt-0.5">
            Stale
          </span>
        )}
        <span className="text-xs text-muted shrink-0 mt-0.5">
          {summary.generated_at ? timeAgo(summary.generated_at) : ''}
        </span>
        <svg
          className={`w-4 h-4 text-muted transition-transform shrink-0 mt-0.5 ${expanded ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="mt-2 p-4 bg-surface border border-border rounded-lg space-y-4">
          {isStale && (
            <div className="text-xs text-orange-300 bg-orange-500/10 border border-orange-400/20 rounded-md px-3 py-2">
              The AI backend has not refreshed this summary recently. The live alert state below may be newer than this summary.
            </div>
          )}
          {summary.clusters.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted uppercase tracking-wide mb-2">Clusters</h4>
              <div className="flex gap-2 overflow-x-auto pb-1">
                {summary.clusters
                  .sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99))
                  .map((cluster) => (
                  <button
                    key={cluster.cluster_id}
                    onClick={() => {
                      if (expandedCluster === cluster.cluster_id) {
                        setExpandedCluster(null);
                      } else {
                        setExpandedCluster(cluster.cluster_id);
                      }
                    }}
                    className="flex-shrink-0 p-2.5 bg-background border border-border rounded-md hover:border-accent transition-colors text-left min-w-[200px] max-w-[300px]"
                  >
                    <div className="flex items-center gap-1.5 mb-1">
                      <span className={`w-2 h-2 rounded-full ${severityDotColor(cluster.top_severity || 'info')} shrink-0`} />
                      <span className="text-xs font-medium text-text-bright truncate flex-1">{cluster.label}</span>
                      <span className="text-xs text-muted bg-surface px-1.5 py-0.5 rounded-full">{cluster.count}</span>
                    </div>
                    <p className="text-xs text-muted line-clamp-2">{cluster.assessment || 'Analyzing...'}</p>
                  </button>
                ))}
              </div>

              {expandedCluster && (() => {
                const cluster = summary.clusters.find(c => c.cluster_id === expandedCluster);
                if (!cluster) return null;
                return (
                  <div className="mt-2 p-3 bg-background border border-border rounded-md">
                    <div className="flex items-center justify-between mb-2">
                      <h5 className="text-xs font-medium text-text-bright">{cluster.label} — {cluster.count} alerts</h5>
                      <button
                        onClick={() => {
                          onClusterClick?.(cluster.fingerprints || []);
                          setExpandedCluster(null);
                        }}
                        className="text-xs px-2 py-0.5 bg-accent/20 text-accent rounded hover:bg-accent/30 transition-colors"
                      >
                        Filter alerts
                      </button>
                    </div>
                    {cluster.assessment && (
                      <p className="text-xs text-muted mb-2">{cluster.assessment}</p>
                    )}
                    {cluster.hosts && cluster.hosts.length > 0 && (
                      <p className="text-xs text-muted mb-2">Hosts: {cluster.hosts.join(', ')}</p>
                    )}
                    <ul className="space-y-0.5">
                      {cluster.alert_names?.map((name, i) => (
                        <li key={i} className="text-xs text-text pl-2 border-l border-border">{name}</li>
                      ))}
                    </ul>
                  </div>
                );
              })()}
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

          {summary.suggested_merges && summary.suggested_merges.length > 0 && (
            <div className="pt-2 border-t border-border">
              <p className="text-xs text-muted italic">
                AI suggests these clusters may be related: {summary.suggested_merges.map(m => m.reason).join('; ')}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
