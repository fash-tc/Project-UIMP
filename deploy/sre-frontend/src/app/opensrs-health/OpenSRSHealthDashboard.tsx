'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  fetchOpenSRSHealthReport,
  fetchOpenSRSHealthReports,
  runOpenSRSHealthReport,
} from '@/lib/keep-api';
import { OpenSRSHealthLane, OpenSRSHealthReport, OpenSRSHealthReportSummary } from '@/lib/types';

const WINDOWS = [
  { label: '15m', seconds: 900 },
  { label: '1h', seconds: 3600 },
  { label: '6h', seconds: 21600 },
  { label: '24h', seconds: 86400 },
];

const LANE_DEFS = [
  { id: 'synthetic', label: 'Customer-like checks' },
  { id: 'api', label: 'API/request health' },
  { id: 'registry', label: 'Registry/EPP health' },
  { id: 'events', label: 'Platform events' },
];

function statusClass(status: string): string {
  if (status === 'healthy') return 'text-green';
  if (status === 'degraded') return 'text-orange';
  if (status === 'unknown') return 'text-muted';
  return 'text-text-bright';
}

function statusPanelClass(status: string): string {
  if (status === 'healthy') return 'bg-green/5 border-green/30';
  if (status === 'degraded') return 'bg-orange/5 border-orange/30';
  if (status === 'unknown') return 'bg-muted/10 border-muted/30';
  return 'bg-surface border-border';
}

function formatTime(value?: string): string {
  if (!value) return 'unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

function formatWindow(seconds: number): string {
  const option = WINDOWS.find(item => item.seconds === seconds);
  return option?.label ?? `${Math.round(seconds / 60)}m`;
}

function normalizeFindings(lane: OpenSRSHealthLane): string[] {
  if (lane.error) return [lane.error];
  if (lane.status === 'healthy') return ['No degraded signals found in this window.'];
  if (lane.status === 'unknown') return ['No usable evidence was returned for this lane.'];
  return [
    `${lane.failures} failure${lane.failures === 1 ? '' : 's'}, ${lane.timeouts} timeout${lane.timeouts === 1 ? '' : 's'}, and ${lane.slow ?? 0} slow event${lane.slow === 1 ? '' : 's'} found in ${lane.events} event${lane.events === 1 ? '' : 's'}.`,
  ];
}

export function OpenSRSHealthDashboard() {
  const [history, setHistory] = useState<OpenSRSHealthReportSummary[]>([]);
  const [report, setReport] = useState<OpenSRSHealthReport | null>(null);
  const [windowSeconds, setWindowSeconds] = useState(900);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedEvidence, setExpandedEvidence] = useState<Set<string>>(new Set());

  const loadHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const reports = await fetchOpenSRSHealthReports();
      setHistory(reports);
      if (reports.length > 0) {
        const latest = await fetchOpenSRSHealthReport(reports[0].run_id);
        setReport(latest);
      } else {
        setReport(null);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load OpenSRS health reports');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const runReport = async () => {
    setRunning(true);
    setError(null);
    try {
      const nextReport = await runOpenSRSHealthReport(windowSeconds);
      setReport(nextReport);
      const reports = await fetchOpenSRSHealthReports();
      setHistory(reports);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'OpenSRS health report failed');
    } finally {
      setRunning(false);
    }
  };

  const selectHistory = async (summary: OpenSRSHealthReportSummary) => {
    setLoading(true);
    setError(null);
    try {
      setReport(await fetchOpenSRSHealthReport(summary.run_id));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load selected report');
    } finally {
      setLoading(false);
    }
  };

  const lanes = Array.isArray(report?.lanes) ? report.lanes : [];
  const timeline = Array.isArray(report?.timeline) ? report.timeline : [];
  const correlations = Array.isArray(report?.correlations) ? report.correlations : [];
  const issueSummary = report?.issue_summary;
  const degradedCount = lanes.filter(lane => lane.status === 'degraded').length;

  const toggleLaneEvidence = (laneId: string) => {
    setExpandedEvidence(prev => {
      const next = new Set(prev);
      if (next.has(laneId)) next.delete(laneId);
      else next.add(laneId);
      return next;
    });
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-bright">OpenSRS E2E Health</h1>
          <p className="text-sm text-muted mt-1">Customer-path health from synthetic, API, EPP, and platform event evidence.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 rounded-md border border-border bg-surface p-1">
            {WINDOWS.map(option => (
              <button
                key={option.seconds}
                onClick={() => setWindowSeconds(option.seconds)}
                className={`px-2.5 py-1 text-xs rounded transition-colors ${
                  windowSeconds === option.seconds
                    ? 'bg-accent text-bg'
                    : 'text-muted hover:text-text-bright hover:bg-surface-hover'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
          <button
            onClick={runReport}
            disabled={running}
            className="px-4 py-2 text-sm font-medium rounded-md bg-accent text-bg hover:bg-accent-hover disabled:opacity-50 transition-colors"
          >
            {running ? 'Running...' : 'Run OpenSRS E2E Health Report'}
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-sm text-red">
          {error}
        </div>
      )}

      {loading && (
        <div className="bg-surface border border-border rounded-lg px-5 py-8 text-center text-sm text-muted">
          Loading OpenSRS health history...
        </div>
      )}

      {!loading && !report && (
        <div className="bg-surface border border-border rounded-lg px-5 py-8 text-center">
          <div className="text-sm font-medium text-text-bright">No report has been run yet.</div>
          <div className="text-xs text-muted mt-1">Choose a window and run a report when you need fresh evidence.</div>
        </div>
      )}

      {report && (
        <>
          <section className={`border rounded-lg px-5 py-4 ${statusPanelClass(report.overall)}`}>
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <div className="text-xs text-muted uppercase tracking-wider">Executive health</div>
                <div className={`text-2xl font-bold capitalize ${statusClass(report.overall)}`}>{report.overall}</div>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                <SummaryStat label="Window" value={formatWindow(report.window_seconds)} />
                <SummaryStat label="Lanes" value={`${lanes.length}`} />
                <SummaryStat label="Degraded" value={`${degradedCount}`} />
                <SummaryStat label="Completed" value={formatTime(report.completed_at)} />
              </div>
            </div>
          </section>

          <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {LANE_DEFS.map(laneDef => (
              <LaneCard key={laneDef.id} label={laneDef.label} lane={lanes.find(lane => lane.id === laneDef.id) ?? null} />
            ))}
          </section>

          <Panel title="Operational findings">
            <IssueSummaryPanel summary={issueSummary} />
          </Panel>

          <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Panel title="Timeline">
              {timeline.length === 0 ? (
                <EmptyLine text="No timestamped samples were available." />
              ) : (
                <div className="space-y-2">
                  {timeline.slice(0, 8).map(item => (
                    <div key={item.bucket} className="flex items-center justify-between gap-3 text-xs border-b border-border/40 pb-2">
                      <span className="font-mono text-muted">{formatTime(item.bucket)}</span>
                      <span className="text-text-bright">{item.lanes.join(', ')}</span>
                    </div>
                  ))}
                </div>
              )}
            </Panel>

            <Panel title="Correlation">
              {correlations.length === 0 ? (
                <EmptyLine text="No same-window lane correlations were detected." />
              ) : (
                <div className="space-y-2">
                  {correlations.slice(0, 8).map(item => (
                    <div key={item.bucket} className="rounded-md border border-orange/30 bg-orange/5 px-3 py-2 text-xs">
                      <div className="text-orange font-medium">{formatTime(item.bucket)}</div>
                      <div className="text-muted mt-1">{item.lanes.join(' + ')}</div>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          </section>

          <Panel title="AI analysis">
            <AIAnalysis analysis={report.ai_analysis} />
          </Panel>

          <Panel title="Evidence">
            <div className="space-y-3">
              {lanes.length === 0 ? (
                <EmptyLine text="No lane evidence returned." />
              ) : lanes.map(lane => {
                const laneSamples = Array.isArray(lane.samples) ? lane.samples : [];
                const isExpanded = expandedEvidence.has(lane.id);
                return (
                  <div key={lane.id} className="rounded-md border border-border/50 bg-bg/30 px-3 py-2">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-xs font-medium text-text-bright">{lane.label}</div>
                      <button
                        onClick={() => toggleLaneEvidence(lane.id)}
                        className="px-2.5 py-1 text-xs rounded-md border border-border text-muted hover:text-text-bright hover:bg-surface-hover transition-colors"
                      >
                        {isExpanded ? 'Hide' : 'Show'}
                      </button>
                    </div>
                    {isExpanded && (
                      laneSamples.length === 0 ? (
                        <EmptyLine text="No samples retained for this lane." />
                      ) : (
                        <div className="space-y-2 mt-3">
                          {laneSamples.map((sample, idx) => (
                            <div key={`${lane.id}-${idx}`} className="rounded-md bg-bg/50 border border-border/50 px-3 py-2">
                              <div className="text-[10px] text-muted font-mono">{formatTime(sample.timestamp)}</div>
                              <div className="text-xs text-text-bright font-mono break-all mt-1">{sample.message}</div>
                            </div>
                          ))}
                        </div>
                      )
                    )}
                  </div>
                );
              })}
            </div>
          </Panel>
        </>
      )}

      <section className="bg-surface border border-border rounded-lg px-5 py-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-text-bright">History</h2>
          <button
            onClick={loadHistory}
            disabled={loading}
            className="px-2.5 py-1 text-xs rounded-md border border-border text-muted hover:text-text-bright hover:bg-surface-hover disabled:opacity-50 transition-colors"
          >
            Refresh
          </button>
        </div>
        {history.length === 0 ? (
          <EmptyLine text="No historical reports found." />
        ) : (
          <div className="space-y-2">
            {history.slice(0, 8).map(item => (
              <button
                key={item.run_id}
                onClick={() => selectHistory(item)}
                className={`w-full flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-left text-xs transition-colors ${
                  report?.run_id === item.run_id
                    ? 'border-accent/40 bg-accent/10'
                    : 'border-border hover:bg-surface-hover'
                }`}
              >
                <span className="min-w-0">
                  <span className={`font-semibold capitalize ${statusClass(item.overall)}`}>{item.overall}</span>
                  <span className="text-muted ml-2">{formatWindow(item.window_seconds)}</span>
                </span>
                <span className="text-muted shrink-0">{formatTime(item.completed_at)}</span>
              </button>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

export default function OpenSRSHealthPage() {
  return <OpenSRSHealthDashboard />;
}

function SummaryStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-bg/40 border border-border/50 rounded-lg px-3 py-2">
      <div className="text-[10px] text-muted uppercase tracking-wider">{label}</div>
      <div className="text-sm font-semibold text-text-bright mt-0.5">{value}</div>
    </div>
  );
}

function LaneCard({ label, lane }: { label: string; lane: OpenSRSHealthLane | null }) {
  if (!lane) {
    return (
      <div className="bg-surface border border-border rounded-lg px-5 py-4">
        <h2 className="text-sm font-semibold text-text-bright">{label}</h2>
        <EmptyLine text="No lane data returned." />
      </div>
    );
  }

  const metrics: Array<[string, number | string]> = [
    ['events', lane.events],
    ['errors', lane.errors],
    ['failures', lane.failures],
    ['timeouts', lane.timeouts],
    ['slow', lane.slow ?? 0],
    ['avg latency', lane.avg_latency_ms === null ? '--' : `${lane.avg_latency_ms}ms`],
    ['p95 latency', lane.p95_latency_ms === null ? '--' : `${lane.p95_latency_ms}ms`],
  ];
  const findings = normalizeFindings(lane);
  const hotspots = Array.isArray(lane.hotspots) ? lane.hotspots : [];
  const problemSamples = Array.isArray(lane.problem_samples) ? lane.problem_samples : [];

  return (
    <div className={`border rounded-lg px-5 py-4 ${statusPanelClass(lane.status)}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-text-bright">{label}</h2>
          <div className={`text-xs capitalize mt-1 ${statusClass(lane.status)}`}>{lane.status}</div>
        </div>
        <span className="text-[10px] text-muted font-mono">{lane.id}</span>
      </div>
      {metrics.length > 0 && (
        <div className="grid grid-cols-2 gap-2 mt-4">
          {metrics.map(([key, value]) => (
            <div key={key} className="bg-bg/40 border border-border/50 rounded-md px-3 py-2">
              <div className="text-[10px] text-muted uppercase">{key}</div>
              <div className="text-sm font-semibold text-text-bright">{String(value)}</div>
            </div>
          ))}
        </div>
      )}
      <div className="mt-4 space-y-1.5">
        {findings.slice(0, 3).map((finding, idx) => (
          <div key={idx} className="text-xs text-muted">{finding}</div>
        ))}
      </div>
      {hotspots.length > 0 && (
        <div className="mt-4 border-t border-border/50 pt-3">
          <div className="text-[10px] text-muted uppercase mb-2">Hotspots</div>
          <div className="space-y-1.5">
            {hotspots.slice(0, 3).map((hotspot) => (
              <div key={hotspot.key} className="rounded-md bg-bg/40 border border-border/50 px-2.5 py-2">
                <div className="text-xs font-mono text-text-bright break-all">{hotspot.key}</div>
                <div className="text-[10px] text-muted mt-1">
                  {hotspot.events} events · {hotspot.failures} failures · {hotspot.timeouts} timeouts · {hotspot.slow} slow · p95 {hotspot.p95_latency_ms ?? '--'}ms
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {problemSamples.length > 0 && (
        <div className="mt-3 text-[10px] text-muted">
          {problemSamples.length} problem sample{problemSamples.length === 1 ? '' : 's'} retained in Evidence.
        </div>
      )}
    </div>
  );
}

function Panel({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <section className="bg-surface border border-border rounded-lg px-5 py-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <h2 className="text-sm font-semibold text-text-bright">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function EmptyLine({ text }: { text: string }) {
  return <div className="text-xs text-muted py-2">{text}</div>;
}

function IssueSummaryPanel({ summary }: { summary?: OpenSRSHealthReport['issue_summary'] }) {
  if (!summary) {
    return <EmptyLine text="No issue summary was returned for this report." />;
  }
  const issues = Array.isArray(summary.issues) ? summary.issues : [];
  if (!summary.has_issue || issues.length === 0) {
    return (
      <div className="rounded-md border border-green/30 bg-green/5 px-4 py-3">
        <div className="text-sm font-semibold text-green">No customer-path issue detected</div>
        <div className="text-xs text-muted mt-1">Synthetic, API, registry, and event evidence did not show active failure, timeout, or latency hotspots.</div>
      </div>
    );
  }
  return (
    <div className="space-y-4">
      {summary.primary_issue && <PrimaryIssueCard issue={summary.primary_issue} />}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {issues.slice(0, 6).map((issue, idx) => (
          <IssueCard key={`${issue.where}-${idx}`} issue={issue} />
        ))}
      </div>
    </div>
  );
}

function PrimaryIssueCard({ issue }: { issue: NonNullable<OpenSRSHealthReport['issue_summary']>['issues'][number] }) {
  return (
    <div className="rounded-lg border border-orange/40 bg-orange/5 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] uppercase tracking-wide text-orange font-semibold">{issue.severity}</span>
        <span className="text-xs text-muted">Primary issue</span>
      </div>
      <div className="mt-2 text-base font-semibold text-text-bright">
        {issue.type === 'latency' ? 'Latency degradation' : issue.type === 'timeout' ? 'Timeout/read failure cluster' : 'Error cluster'}
      </div>
      <div className="mt-1 text-sm text-muted">{issue.description}</div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-3">
        <IssueMetric label="Where" value={issue.host || issue.where} />
        <IssueMetric label="Action" value={issue.action || 'unknown'} />
        <IssueMetric label="Impact" value={issue.impact} />
        <IssueMetric label="Trending" value={issue.trend} />
      </div>
    </div>
  );
}

function IssueCard({ issue }: { issue: NonNullable<OpenSRSHealthReport['issue_summary']>['issues'][number] }) {
  const evidence = Array.isArray(issue.evidence) ? issue.evidence[0] : null;
  return (
    <div className="rounded-md border border-border/50 bg-bg/35 px-3 py-3">
      <div className="flex items-center justify-between gap-2">
        <div className="text-sm font-semibold text-text-bright">{issue.lane_label}</div>
        <div className={`text-[10px] uppercase ${issue.severity === 'critical' ? 'text-red' : 'text-orange'}`}>{issue.type}</div>
      </div>
      <div className="mt-2 grid grid-cols-2 gap-2">
        <IssueMetric label="Host" value={issue.host} />
        <IssueMetric label="Trend" value={issue.trend} />
        <IssueMetric label="Impact" value={issue.impact} />
        <IssueMetric label="P95" value={issue.p95_latency_ms === null ? '--' : `${issue.p95_latency_ms}ms`} />
      </div>
      <div className="mt-2 text-xs text-muted break-words">{issue.action}</div>
      {evidence && (
        <div className="mt-2 rounded bg-bg/60 border border-border/40 px-2 py-1.5 text-[11px] text-muted break-words">
          {evidence.message}
        </div>
      )}
    </div>
  );
}

function IssueMetric({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
      <div className="text-xs font-medium text-text-bright break-words">{value ?? '--'}</div>
    </div>
  );
}

function AIAnalysis({ analysis }: { analysis: Record<string, unknown> }) {
  if (!analysis || Object.keys(analysis).length === 0) {
    return <EmptyLine text="No AI analysis was returned for this report." />;
  }

  if (typeof analysis.summary === 'string') {
    return (
      <div className="space-y-3">
        <FormattedAIText text={analysis.summary} />
        <AnalysisList title="Likely causes" value={analysis.likely_causes} />
        <AnalysisList title="Recommended actions" value={analysis.recommended_sre_actions} />
      </div>
    );
  }

  return (
    <pre className="text-xs text-muted bg-bg/50 border border-border/50 rounded-md p-3 overflow-x-auto">
      {JSON.stringify(analysis, null, 2)}
    </pre>
  );
}

type AISection = {
  title: string;
  items: string[];
};

function stripAIInlineMarkup(text: string) {
  return text
    .replace(/\*\*/g, '')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/^\s*[-*]\s+/, '')
    .trim();
}

function normalizeAIText(text: string) {
  return text
    .replace(/\*\*(OpenSRS Health Summary)\*\*/g, '\n$1\n')
    .replace(/\*\*(\d+\.\s+[^*]+)\*\*/g, '\n$1\n')
    .replace(/\*\*([A-Z][A-Za-z /-]{2,48}:)\*\*/g, '\n$1 ')
    .replace(/\s+\*\s+/g, '\n* ')
    .replace(/\s+(Synthetic|API|Registry|Events):\s+/g, '\n$1: ')
    .replace(/\s+(Confirmed Errors and Timeouts|Lane Status Breakdown|Latency Observations|Recommended Checks):\s+/g, '\n$1:\n');
}

function parseAISections(text: string): AISection[] {
  const sections: AISection[] = [];
  let current: AISection = { title: 'Summary', items: [] };
  const parts = normalizeAIText(text)
    .split(/\n+/)
    .map(part => part.trim())
    .filter(Boolean);

  for (const part of parts) {
    const clean = stripAIInlineMarkup(part);
    if (!clean) continue;
    const heading = clean.replace(/^\d+\.\s+/, '').replace(/:$/, '');
    const isHeading = /^OpenSRS Health Summary$/.test(heading)
      || /^(Lane Status Breakdown|Confirmed Errors and Timeouts|Latency Observations|Recommended Checks)$/i.test(heading)
      || (/Lane|Hotspots|Observations|Checks|Summary$/i.test(heading) && clean.length < 70 && !clean.includes(','));
    if (isHeading) {
      if (current.items.length > 0) sections.push(current);
      current = { title: heading, items: [] };
    } else {
      current.items.push(clean);
    }
  }
  if (current.items.length > 0) sections.push(current);
  return sections;
}

function FormattedAIText({ text }: { text: string }) {
  const sections = parseAISections(text);
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      {sections.map((section, idx) => <AISectionCard key={`${section.title}-${idx}`} section={section} />)}
    </div>
  );
}

function AISectionCard({ section }: { section: AISection }) {
  return (
    <div className="rounded-md border border-border/50 bg-bg/35 p-3">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted mb-2">{section.title}</h3>
      <div className="space-y-2">
        {section.items.slice(0, 12).map((item, idx) => <AIKeyValueLine key={idx} text={item} />)}
      </div>
    </div>
  );
}

function AIKeyValueLine({ text }: { text: string }) {
  const match = text.match(/^([^:]{2,40}):\s*(.+)$/);
  if (match) {
    return (
      <div className="grid gap-1 sm:grid-cols-[145px_1fr] text-xs leading-5">
        <div className="font-medium text-muted">{match[1]}</div>
        <div className="text-text-bright break-words">{match[2]}</div>
      </div>
    );
  }
  return (
    <div className="flex gap-2 text-xs leading-5 text-text-bright">
      <span className="text-accent">-</span>
      <span className="break-words">{text}</span>
    </div>
  );
}

function AnalysisList({ title, value }: { title: string; value: unknown }) {
  const items = Array.isArray(value)
    ? value.map(item => typeof item === 'string' ? item : JSON.stringify(item)).filter(Boolean)
    : [];
  if (items.length === 0) return null;
  return (
    <div>
      <div className="text-xs font-medium text-muted mb-1">{title}</div>
      <div className="space-y-1">
        {items.map((item, idx) => (
          <div key={idx} className="text-xs text-text-bright">{item}</div>
        ))}
      </div>
    </div>
  );
}
