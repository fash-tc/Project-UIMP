'use client';

import { useState, useCallback, useRef } from 'react';
import { analyzeOpenSRSLogs, queryLokiLogs, LogEntry } from '@/lib/keep-api';
import { OpenSRSHealthDashboard } from '@/app/opensrs-health/OpenSRSHealthDashboard';
import { OpenSRSLogAnalysisResult } from '@/lib/types';

const PRESETS = [
  { label: 'Registry Timing', query: '{app="ra"} |~ "total="' },
  { label: 'EPP Result Codes', query: '{app="ra"} |~ "result code"' },
  { label: 'All Registry Logs', query: '{app="ra"}' },
  { label: 'Errors & Failures', query: '{app="ra"} |~ "error|Error|fail|Fail|timeout|Timeout"' },
];

const TIME_RANGES = [
  { label: '15m', seconds: 900 },
  { label: '1h', seconds: 3600 },
  { label: '6h', seconds: 21600 },
  { label: '24h', seconds: 86400 },
];

const LIMITS = [100, 200, 500, 1000];

function formatTs(ts: string): string {
  try {
    const d = new Date(ts);
    const hh = String(d.getUTCHours()).padStart(2, '0');
    const mm = String(d.getUTCMinutes()).padStart(2, '0');
    const ss = String(d.getUTCSeconds()).padStart(2, '0');
    const ms = String(d.getUTCMilliseconds()).padStart(3, '0');
    return `${hh}:${mm}:${ss}.${ms}`;
  } catch {
    return ts;
  }
}

function formatRangeSeconds(seconds: number): string {
  const known = TIME_RANGES.find((item) => item.seconds === seconds);
  if (known) return known.label;
  if (seconds >= 3600) return `${Math.round(seconds / 3600)}h`;
  if (seconds >= 60) return `${Math.round(seconds / 60)}m`;
  return `${seconds}s`;
}

function classifyLine(message: string): 'error' | 'slow' | 'normal' {
  if (/with\s+resp\s+[45]\d{2}/.test(message)) return 'error';
  if (/result code="[2-9]\d{3}"/.test(message)) return 'error';
  if (/error|fail|timeout/i.test(message)) return 'error';
  const totalMatch = message.match(/total=(\d+)\s+ms/);
  if (totalMatch && parseInt(totalMatch[1], 10) > 5000) return 'slow';
  return 'normal';
}

export default function LogsPage() {
  const [activeTab, setActiveTab] = useState<'logs' | 'opensrs-health'>('logs');
  const [query, setQuery] = useState(PRESETS[0].query);
  const [activePreset, setActivePreset] = useState(0);
  const [range, setRange] = useState(3600);
  const [limit, setLimit] = useState(200);
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasQueried, setHasQueried] = useState(false);
  const [filter, setFilter] = useState('');
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set());
  const [aiQuestion, setAiQuestion] = useState('where are errors or slowness?');
  const [aiLogAnalysis, setAiLogAnalysis] = useState<OpenSRSLogAnalysisResult | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const runQuery = useCallback(async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setExpandedRows(new Set());
    try {
      const data = await queryLokiLogs(query.trim(), limit, range);
      setEntries(data.entries);
      setTotal(data.total);
      setHasQueried(true);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Query failed';
      setError(msg);
      setEntries([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [query, limit, range]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        runQuery();
      }
    },
    [runQuery],
  );

  const selectPreset = (idx: number) => {
    setActivePreset(idx);
    setQuery(PRESETS[idx].query);
  };

  const toggleRow = (idx: number) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const askAI = useCallback(async () => {
    setAiLoading(true);
    setAiError(null);
    try {
      const result = await analyzeOpenSRSLogs({
        query: '',
        rangeSeconds: range,
        limit,
        question: aiQuestion.trim() || 'where are errors or slowness?',
      });
      setAiLogAnalysis(result);
    } catch (e: unknown) {
      setAiError(e instanceof Error ? e.message : 'AI log analysis failed');
      setAiLogAnalysis(null);
    } finally {
      setAiLoading(false);
    }
  }, [aiQuestion, limit, range]);

  // No auto-run — user clicks "Run Query" to start

  const filtered = filter
    ? entries.filter(
        (e) =>
          e.message.toLowerCase().includes(filter.toLowerCase()) ||
          Object.values(e.labels).some((v) => v.toLowerCase().includes(filter.toLowerCase())),
      )
    : entries;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text-bright">Logs Explorer</h1>
          <p className="text-xs text-muted mt-0.5">Query OpenSRS production logs via Loki</p>
        </div>
      </div>

      <div className="flex gap-1 bg-zinc-800/50 p-1 rounded-lg w-fit">
        <button
          onClick={() => setActiveTab('logs')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'logs' ? 'bg-zinc-700 text-white' : 'text-zinc-400 hover:text-white'
          }`}
        >
          Logs Explorer
        </button>
        <button
          onClick={() => setActiveTab('opensrs-health')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            activeTab === 'opensrs-health' ? 'bg-zinc-700 text-white' : 'text-zinc-400 hover:text-white'
          }`}
        >
          OpenSRS Health
        </button>
      </div>

      {activeTab === 'logs' ? (
        <>
      {/* Query controls */}
      <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
        {/* Presets row */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-muted font-medium w-14 shrink-0">Presets</span>
          {PRESETS.map((p, i) => (
            <button
              key={i}
              onClick={() => selectPreset(i)}
              className={`px-2.5 py-1 text-xs rounded-md border transition-colors ${
                activePreset === i
                  ? 'bg-accent/15 border-accent/40 text-accent'
                  : 'border-border text-muted hover:text-text-bright hover:border-border'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Query input row */}
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <input
              ref={inputRef}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setActivePreset(-1);
              }}
              onKeyDown={handleKeyDown}
              placeholder='LogQL query, e.g. {app="ra"} |~ "total="'
              className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright font-mono placeholder:text-muted/50 focus:outline-none focus:border-accent/50"
            />
            <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-muted/40">
              Ctrl+Enter
            </span>
          </div>
        </div>

        {/* Controls row */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted">Range:</span>
            {TIME_RANGES.map((t) => (
              <button
                key={t.seconds}
                onClick={() => setRange(t.seconds)}
                className={`px-2 py-0.5 text-xs rounded border transition-colors ${
                  range === t.seconds
                    ? 'bg-accent/15 border-accent/40 text-accent'
                    : 'border-border text-muted hover:text-text-bright'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-muted">Limit:</span>
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="bg-bg border border-border text-text-bright text-xs rounded px-1.5 py-0.5 focus:outline-none"
            >
              {LIMITS.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={runQuery}
            disabled={loading || !query.trim()}
            className="ml-auto px-4 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-40 transition-colors"
          >
            {loading ? 'Querying...' : 'Run Query'}
          </button>
        </div>
      </div>

      <div className="bg-surface border border-border rounded-lg p-4 space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-text-bright">AI log analysis</h2>
            <div className="text-xs text-muted mt-0.5">Uses current LogQL, range, and capped read-only samples.</div>
          </div>
          <button
            onClick={askAI}
            disabled={aiLoading || !query.trim()}
            className="px-4 py-1.5 text-xs font-medium rounded-md bg-accent text-white hover:bg-accent/90 disabled:opacity-40 transition-colors"
          >
            {aiLoading ? 'Analyzing...' : 'Ask AI'}
          </button>
        </div>
        <input
          value={aiQuestion}
          onChange={(e) => setAiQuestion(e.target.value)}
          placeholder="Ask about slowness, errors, hosts, registry agents, actions..."
          className="w-full bg-bg border border-border rounded-md px-3 py-2 text-sm text-text-bright placeholder:text-muted/50 focus:outline-none focus:border-accent/50"
        />
        {aiError && (
          <div className="bg-red/10 border border-red/30 rounded-md px-3 py-2 text-xs text-red">{aiError}</div>
        )}
        {aiLogAnalysis && <LogAIAnalysis result={aiLogAnalysis} />}
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red/10 border border-red/30 rounded-lg px-4 py-3 text-sm text-red">
          {error}
        </div>
      )}

      {/* Results */}
      {hasQueried && !error && (
        <div className="bg-surface border border-border rounded-lg overflow-hidden">
          {/* Results header */}
          <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-bg/30">
            <div className="flex items-center gap-3">
              <span className="text-xs text-muted">
                {total} {total === 1 ? 'entry' : 'entries'}
                {filter && ` (${filtered.length} matching filter)`}
              </span>
            </div>
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter results..."
              className="bg-bg border border-border rounded px-2 py-1 text-xs text-text-bright w-48 placeholder:text-muted/50 focus:outline-none focus:border-accent/50"
            />
          </div>

          {/* Log entries */}
          {filtered.length === 0 ? (
            <div className="px-4 py-12 text-center text-sm text-muted">
              {total === 0 ? 'No log entries found for this query and time range.' : 'No entries match the filter.'}
            </div>
          ) : (
            <div className="max-h-[calc(100vh-380px)] overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-surface z-10 border-b border-border">
                  <tr>
                    <th className="text-left text-muted font-medium px-3 py-2 w-24">Time (UTC)</th>
                    <th className="text-left text-muted font-medium px-3 py-2 w-36">Agent</th>
                    <th className="text-left text-muted font-medium px-3 py-2">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((entry, idx) => {
                    const cls = classifyLine(entry.message);
                    const agent = entry.labels.registry_agent || entry.labels.app || '';
                    const isExpanded = expandedRows.has(idx);
                    const isLong = entry.message.length > 200;
                    return (
                      <tr
                        key={idx}
                        onClick={() => isLong && toggleRow(idx)}
                        className={`border-b border-border/30 transition-colors ${
                          isLong ? 'cursor-pointer' : ''
                        } ${
                          cls === 'error'
                            ? 'bg-red/5 hover:bg-red/10'
                            : cls === 'slow'
                            ? 'bg-orange/5 hover:bg-orange/10'
                            : 'hover:bg-surface-hover'
                        }`}
                      >
                        <td className="px-3 py-1.5 text-muted font-mono whitespace-nowrap align-top">
                          {formatTs(entry.timestamp)}
                        </td>
                        <td className="px-3 py-1.5 align-top">
                          <span
                            className={`font-medium ${
                              cls === 'error' ? 'text-red' : cls === 'slow' ? 'text-orange' : 'text-accent'
                            }`}
                          >
                            {agent}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 font-mono text-text-bright align-top">
                          <span className={isExpanded ? 'whitespace-pre-wrap break-all' : 'line-clamp-1'}>
                            {entry.message}
                          </span>
                          {isLong && !isExpanded && (
                            <span className="text-muted/50 ml-1">...</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
        </>
      ) : (
        <OpenSRSHealthDashboard />
      )}
    </div>
  );
}

function LogAIAnalysis({ result }: { result: OpenSRSLogAnalysisResult }) {
  const analysis = result.analysis || {};
  const evidence = result.evidence;
  const answer = typeof analysis.answer === 'string' ? analysis.answer : '';
  const findings = Array.isArray(analysis.findings) ? analysis.findings : [];
  const likelyCauses = Array.isArray(analysis.likely_causes) ? analysis.likely_causes : [];
  const recommendedActions = Array.isArray(analysis.recommended_sre_actions) ? analysis.recommended_sre_actions : [];
  const problemAreas = Array.isArray(evidence.problem_areas) ? evidence.problem_areas : [];
  const latencyAreas = Array.isArray(evidence.latency_areas) ? evidence.latency_areas : [];
  const tldAreas = Array.isArray(evidence.tld_areas) ? evidence.tld_areas : [];
  const scope = evidence.access_scope;
  const warning = typeof analysis.warning === 'string' ? analysis.warning : '';
  const rawFormat = typeof analysis.raw_format === 'string' ? analysis.raw_format : '';

  return (
    <div className="border border-border/50 rounded-md bg-bg/30 p-4 space-y-4">
      {scope && (
        <div className="rounded-md border border-border/60 bg-bg/40 p-3 space-y-2">
          <div className="text-xs font-medium text-muted uppercase">Data scope - AI-selected query</div>
          <div className="font-mono text-xs text-text-bright break-all">{scope.query}</div>
          <div className="text-xs text-muted">
            Source: {scope.source || 'Grafana Loki'} / Range: {formatRangeSeconds(scope.range_seconds)} / Analyzed: {scope.entries_analyzed} entries / Cap: {scope.sample_cap || evidence.entries_analyzed}
          </div>
        </div>
      )}
      {answer ? (
        <div className="text-sm leading-6 text-text-bright whitespace-pre-wrap">{answer}</div>
      ) : typeof analysis.summary === 'string' ? (
        <div className="text-sm leading-6 text-text-bright whitespace-pre-wrap">{analysis.summary}</div>
      ) : analysis.error ? (
        <div className="text-sm text-red">{String(analysis.error)}</div>
      ) : (
        <div className="text-sm text-muted">No AI answer was returned for this query.</div>
      )}
      {findings.length > 0 && (
        <div className="space-y-1">
          <div className="text-xs font-medium text-muted uppercase">What it sees</div>
          {findings.slice(0, 6).map((item, idx) => (
            <div key={idx} className="text-xs text-text-bright">
              {formatAnalysisItem(item)}
            </div>
          ))}
        </div>
      )}
      {tldAreas.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-xs font-medium text-muted uppercase">Top TLD latency</div>
          {tldAreas.slice(0, 4).map((area) => (
            <div key={area.key} className="border-l-2 border-yellow/60 pl-3 py-1">
              <div className="font-mono text-xs text-text-bright break-all">{area.key}</div>
              <div className="text-xs text-muted mt-1">
                {area.events} events / avg {area.avg_latency_ms ?? '--'}ms / p95 {area.p95_latency_ms ?? '--'}ms / {area.failures} failures / {area.timeouts} timeouts / {area.slow} slow
              </div>
            </div>
          ))}
        </div>
      )}
      {latencyAreas.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-xs font-medium text-muted uppercase">Top latency paths</div>
          {latencyAreas.slice(0, 4).map((area) => (
            <div key={area.key} className="border-l-2 border-yellow/50 pl-3 py-1">
              <div className="font-mono text-xs text-text-bright break-all">{area.key}</div>
              <div className="text-xs text-muted mt-1">
                {area.events} events / avg {area.avg_latency_ms ?? '--'}ms / p95 {area.p95_latency_ms ?? '--'}ms / {area.failures} failures / {area.timeouts} timeouts / {area.slow} slow
              </div>
            </div>
          ))}
        </div>
      )}
      {problemAreas.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-xs font-medium text-muted uppercase">Where it found problems</div>
          {problemAreas.slice(0, 4).map((area) => (
            <div key={area.key} className="border-l-2 border-accent/50 pl-3 py-1">
              <div className="font-mono text-xs text-text-bright break-all">{area.key}</div>
              <div className="text-xs text-muted mt-1">
                {area.events} events · {area.failures} failures · {area.timeouts} timeouts · {area.slow} slow · p95 {area.p95_latency_ms ?? '--'}ms
              </div>
            </div>
          ))}
        </div>
      )}
      {likelyCauses.length > 0 && <AnalysisSection title="Likely causes" items={likelyCauses} />}
      {recommendedActions.length > 0 && <AnalysisSection title="Suggested SRE checks" items={recommendedActions} />}
      <div className="text-[11px] text-muted border-t border-border/50 pt-3">
        Evidence used: {evidence.entries_analyzed} entries, {evidence.failures} failures, {evidence.timeouts} timeouts, {evidence.slow} slow.
        {rawFormat === 'json' && ' Model returned JSON; displayed answer was normalized to plain text.'}
        {warning && ` ${warning}`}
      </div>
    </div>
  );
}

function AnalysisSection({ title, items }: { title: string; items: unknown[] }) {
  return (
    <div className="space-y-1">
      <div className="text-xs font-medium text-muted uppercase">{title}</div>
      {items.slice(0, 6).map((item, idx) => (
        <div key={idx} className="text-xs text-text-bright">
          {formatAnalysisItem(item)}
        </div>
      ))}
    </div>
  );
}

function formatAnalysisItem(item: unknown) {
  if (typeof item === 'string') return item;
  if (item && typeof item === 'object') {
    const values = Object.values(item as Record<string, unknown>)
      .filter(value => typeof value === 'string' || typeof value === 'number')
      .map(String);
    if (values.length > 0) return values.join(' - ');
  }
  return String(item ?? '');
}
