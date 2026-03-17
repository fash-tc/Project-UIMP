import { Alert, AIEnrichment, AlertStats, SREFeedback, RunbookEntry, AIInstruction, AIFeedbackSummary, AlertState, RunbookFeedback } from './types';

const API_BASE = '/api/keep';

const SOURCE_LABELS: Record<string, string> = {
  zabbix: 'Zabbix',
  'domains-shared': 'Domains Shared Zabbix',
  'ascio': 'Ascio Zabbix',
  'hostedemail': 'HostedEmail Zabbix',
  'enom': 'Enom Zabbix',
  'iaas': 'IAAS Zabbix',
  prometheus: 'Prometheus',
  grafana: 'Grafana',
  datadog: 'Datadog',
  cloudwatch: 'CloudWatch',
};

function formatSource(raw: string): string {
  return SOURCE_LABELS[raw.toLowerCase()] || raw.charAt(0).toUpperCase() + raw.slice(1);
}

export function getSourceLabel(alert: Alert): string {
  if (alert.zabbixInstance) {
    return SOURCE_LABELS[alert.zabbixInstance] || alert.zabbixInstance + ' Zabbix';
  }
  const src = Array.isArray(alert.source) ? alert.source : [alert.source || 'unknown'];
  return src.map(s => formatSource(String(s))).join(', ');
}

async function keepFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`Keep API ${res.status}: ${path}`);
  return res.json();
}

export async function fetchAlerts(limit = 100): Promise<Alert[]> {
  const data = await keepFetch(`/alerts?limit=${limit}`);
  const items = Array.isArray(data) ? data : data?.items ?? [];
  return items;
}

export async function fetchAlertByFingerprint(fingerprint: string): Promise<Alert | null> {
  const alerts = await fetchAlerts(250);
  return alerts.find((a: Alert) => a.fingerprint === fingerprint) ?? null;
}

export function parseAIEnrichment(note: string | undefined | null): AIEnrichment | null {
  if (!note) return null;
  const startMarker = '---AI-ENRICHMENT-V2---';
  const endMarker = '---END-AI-ENRICHMENT---';

  const startIdx = note.indexOf(startMarker);
  if (startIdx === -1) return null;

  const endIdx = note.indexOf(endMarker, startIdx);
  const block = endIdx !== -1
    ? note.substring(startIdx + startMarker.length, endIdx)
    : note.substring(startIdx + startMarker.length);

  const enrichment: AIEnrichment = {
    assessed_severity: 'unknown',
    likely_cause: '',
    remediation: '',
    impact_scope: '',
    dedup_assessment: '',
    dedup_reason: '',
    noise_score: 5,
    noise_reason: '',
    summary: '',
  };

  const fieldMap: Record<string, keyof AIEnrichment> = {
    'ASSESSED_SEVERITY': 'assessed_severity',
    'LIKELY_CAUSE': 'likely_cause',
    'REMEDIATION': 'remediation',
    'IMPACT_SCOPE': 'impact_scope',
    'DEDUP_ASSESSMENT': 'dedup_assessment',
    'DEDUP_REASON': 'dedup_reason',
    'NOISE_SCORE': 'noise_score',
    'NOISE_REASON': 'noise_reason',
    'SUMMARY': 'summary',
    'LLM_MODEL': 'llm_model',
  };

  for (const line of block.split('\n')) {
    const trimmed = line.trim();
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;
    const key = trimmed.substring(0, colonIdx).trim();
    const val = trimmed.substring(colonIdx + 1).trim();
    const field = fieldMap[key];
    if (!field) continue;
    if (field === 'noise_score') {
      const num = parseInt(val.split('/')[0].split(' ')[0], 10);
      if (!isNaN(num)) enrichment.noise_score = Math.max(1, Math.min(10, num));
    } else {
      (enrichment as unknown as Record<string, string | number>)[field] = val;
    }
  }

  return enrichment.summary ? enrichment : null;
}

export function computeStats(alerts: Alert[]): AlertStats {
  const stats: AlertStats = { total: 0, critical: 0, high: 0, warning: 0, low: 0, noise: 0 };
  for (const alert of alerts) {
    if (alert.status === 'resolved' || alert.status === 'ok') continue;
    stats.total++;
    const enrichment = parseAIEnrichment(alert.note);
    const sev = enrichment?.assessed_severity ?? mapZabbixSeverity(alert.severity);
    if (sev === 'critical') stats.critical++;
    else if (sev === 'high') stats.high++;
    else if (sev === 'warning') stats.warning++;
    else stats.low++;
    if (enrichment && enrichment.noise_score >= 7) stats.noise++;
  }
  return stats;
}

function mapZabbixSeverity(sev: string | number | undefined): string {
  const n = typeof sev === 'string' ? parseInt(sev, 10) : (sev ?? 0);
  if (n >= 5) return 'critical';
  if (n >= 4) return 'high';
  if (n >= 3) return 'high';
  if (n >= 2) return 'warning';
  return 'low';
}

export function severityColor(sev: string): string {
  switch (sev) {
    case 'critical': return 'text-red';
    case 'high': return 'text-orange';
    case 'warning': return 'text-yellow';
    case 'low': return 'text-blue';
    case 'info': return 'text-muted';
    default: return 'text-muted';
  }
}

export function severityBg(sev: string): string {
  switch (sev) {
    case 'critical': return 'bg-red/20 border-red/40';
    case 'high': return 'bg-orange/20 border-orange/40';
    case 'warning': return 'bg-yellow/20 border-yellow/40';
    case 'low': return 'bg-blue/20 border-blue/40';
    default: return 'bg-muted/20 border-muted/40';
  }
}

export function timeAgo(dateStr: string): string {
  if (!dateStr) return '';
  let date: Date;
  if (dateStr.includes('T')) {
    date = new Date(dateStr);
  } else {
    // Handle "2026-03-03 06:00:27.953000" format
    date = new Date(dateStr.replace(/\./g, '-').replace(' ', 'T') + 'Z');
  }
  if (isNaN(date.getTime())) return '';
  const now = Date.now();
  const diff = now - date.getTime();
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

/** Pick the best "when did this alert start" timestamp.
 *  lastReceived resets every poller cycle so prefer startedAt/firingStartTime. */
export function alertStartTime(alert: { startedAt?: string; firingStartTime?: string; lastReceived: string }): string {
  return alert.firingStartTime || alert.startedAt || alert.lastReceived;
}

export function parseSREFeedback(note: string | undefined | null): SREFeedback | null {
  if (!note) return null;
  const startMarker = '---SRE-FEEDBACK---';
  const endMarker = '---END-SRE-FEEDBACK---';
  const startIdx = note.indexOf(startMarker);
  if (startIdx === -1) return null;
  const endIdx = note.indexOf(endMarker, startIdx);
  const block = endIdx !== -1
    ? note.substring(startIdx + startMarker.length, endIdx)
    : note.substring(startIdx + startMarker.length);

  const feedback: SREFeedback = { rating: 'positive' };
  const fieldMap: Record<string, keyof SREFeedback> = {
    'RATING': 'rating',
    'CORRECTED_SEVERITY': 'corrected_severity',
    'CORRECTED_NOISE': 'corrected_noise',
    'COMMENT': 'comment',
    'SRE_USER': 'sre_user',
    'TIMESTAMP': 'timestamp',
  };
  for (const line of block.split('\n')) {
    const trimmed = line.trim();
    const colonIdx = trimmed.indexOf(':');
    if (colonIdx === -1) continue;
    const key = trimmed.substring(0, colonIdx).trim();
    const val = trimmed.substring(colonIdx + 1).trim();
    const field = fieldMap[key];
    if (!field) continue;
    if (field === 'corrected_noise') {
      const num = parseInt(val, 10);
      if (!isNaN(num)) feedback.corrected_noise = Math.max(1, Math.min(10, num));
    } else {
      (feedback as unknown as Record<string, string | number>)[field] = val;
    }
  }
  return feedback;
}

function serializeSREFeedback(feedback: SREFeedback): string {
  let block = '---SRE-FEEDBACK---\n';
  block += `RATING: ${feedback.rating}\n`;
  if (feedback.corrected_severity) block += `CORRECTED_SEVERITY: ${feedback.corrected_severity}\n`;
  if (feedback.corrected_noise !== undefined) block += `CORRECTED_NOISE: ${feedback.corrected_noise}\n`;
  if (feedback.comment) block += `COMMENT: ${feedback.comment}\n`;
  if (feedback.sre_user) block += `SRE_USER: ${feedback.sre_user}\n`;
  block += `TIMESTAMP: ${new Date().toISOString()}\n`;
  block += '---END-SRE-FEEDBACK---';
  return block;
}

export async function submitFeedback(
  fingerprint: string,
  currentNote: string | undefined | null,
  feedback: SREFeedback
): Promise<boolean> {
  let enrichmentBlock = '';
  if (currentNote) {
    const startMarker = '---AI-ENRICHMENT-V2---';
    const endMarker = '---END-AI-ENRICHMENT---';
    const startIdx = currentNote.indexOf(startMarker);
    if (startIdx !== -1) {
      const endIdx = currentNote.indexOf(endMarker, startIdx);
      enrichmentBlock = endIdx !== -1
        ? currentNote.substring(startIdx, endIdx + endMarker.length)
        : currentNote.substring(startIdx);
    }
  }

  const feedbackBlock = serializeSREFeedback(feedback);
  const mergedNote = enrichmentBlock
    ? `${enrichmentBlock}\n${feedbackBlock}`
    : feedbackBlock;

  const res = await fetch(`${API_BASE}/alerts/enrich`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fingerprint,
      enrichments: { note: mergedNote },
    }),
  });
  return res.ok;
}

export async function submitStructuredFeedback(data: {
  alert_name: string;
  hostname: string;
  service: string;
  severity_correction: string;
  cause_correction: string;
  remediation_correction: string;
  full_text: string;
}): Promise<boolean> {
  try {
    const res = await fetch('/api/runbook/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Runbook API ──────────────────────────────────────

const RUNBOOK_BASE = '/api/runbook';
const AUTH_BASE = '/api/auth';
const ALERT_STATE_BASE = '/api/alert-states';
const LOKI_BASE = '/api/loki';

export async function fetchRunbookMatches(
  alertName: string,
  hostname?: string,
  service?: string,
): Promise<RunbookEntry[]> {
  const params = new URLSearchParams({ alert_name: alertName });
  if (hostname) params.set('hostname', hostname);
  if (service) params.set('service', service);
  try {
    const res = await fetch(`${RUNBOOK_BASE}/match?${params}`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function submitRunbookEntry(entry: {
  alert_name: string;
  alert_fingerprint?: string;
  hostname?: string;
  service?: string;
  severity?: string;
  remediation: string;
  sre_user?: string;
}): Promise<boolean> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/entries`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(entry),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function deleteRunbookEntry(id: number): Promise<boolean> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/entries/${id}`, { method: 'DELETE' });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Alert Actions ──────────────────────────────────────

export async function resolveAlert(fingerprint: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/alerts/enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fingerprint,
        enrichments: { status: 'resolved' },
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function resolveAlerts(fingerprints: string[]): Promise<boolean> {
  try {
    const results = await Promise.all(
      fingerprints.map(fp => resolveAlert(fp))
    );
    return results.every(ok => ok);
  } catch {
    return false;
  }
}

export async function silenceAlert(
  alertName: string,
  durationSeconds: number,
  hostname?: string,
): Promise<boolean> {
  const escapedName = alertName.replace(/"/g, '\\"');
  let celQuery = `name == "${escapedName}"`;
  if (hostname) {
    celQuery += ` && hostname == "${hostname.replace(/"/g, '\\"')}"`;
  }
  try {
    const res = await fetch(`${API_BASE}/maintenance`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: `Silenced: ${alertName.substring(0, 60)}`,
        description: 'Silenced from SRE Command Center',
        cel_query: celQuery,
        duration_seconds: durationSeconds,
        start_time: new Date().toISOString(),
        enabled: true,
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Jira Integration ──────────────────────────────────

export async function createJiraIncident(details: {
  summary: string;
  description: string;
  classId: string;
  operationalServiceId?: string;
  alertLink?: string;
  attachments?: { data: string; filename: string }[];
}): Promise<{ ok: boolean; issueKey?: string; issueUrl?: string; error?: string }> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/jira/incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(details),
    });
    const data = await res.json();
    if (res.ok) {
      return { ok: true, issueKey: data.issue_key, issueUrl: data.issue_url };
    }
    return { ok: false, error: data.error || 'Failed to create incident' };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

// ── Registry Health (Loki) ───────────────────────────

export interface RegistryHealthOperator {
  status: 'healthy' | 'degraded' | 'down' | 'no_data';
  request_count: number;
  avg_response_ms: number;
  avg_sendrecv_ms: number;
  p95_response_ms: number;
  error_rate: number;
  resp_codes: Record<string, number>;
  epp_error_rate: number;
  epp_codes: Record<string, number>;
  top_operations: Record<string, number>;
}

export interface RegistryHealthData {
  last_updated: string | null;
  query_window_seconds: number;
  poll_interval_seconds: number;
  loki_error: string | null;
  operators: Record<string, RegistryHealthOperator>;
  unmapped_agents: string[];
}

export async function fetchRegistryHealth(): Promise<RegistryHealthData | null> {
  try {
    const res = await fetch(`${LOKI_BASE}/registry-health`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function fetchRegistryTrends(operatorId: string, rangeSeconds: number = 86400) {
  const res = await fetch(`${LOKI_BASE}/registry-trends?operator=${encodeURIComponent(operatorId)}&range_seconds=${rangeSeconds}`);
  if (!res.ok) throw new Error(`Registry trends failed: ${res.status}`);
  return res.json();
}

// ── Loki Logs ────────────────────────────────────────

export interface LogEntry {
  timestamp: string;
  labels: Record<string, string>;
  message: string;
}

export interface LogQueryResult {
  entries: LogEntry[];
  total: number;
  query: string;
  range_seconds: number;
}

export async function queryLokiLogs(
  query: string,
  limit = 200,
  range = 3600,
): Promise<LogQueryResult> {
  const res = await fetch(`${LOKI_BASE}/logs/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, limit, range }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Query failed');
  return data;
}

// ── AI Instructions ──────────────────────────────────

export async function fetchAIInstructions(): Promise<AIInstruction[]> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/ai-instructions`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function createAIInstruction(instruction: string, sre_user?: string): Promise<boolean> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/ai-instructions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ instruction, sre_user }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function updateAIInstruction(id: number, updates: { instruction?: string; active?: boolean }): Promise<boolean> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/ai-instructions/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function deleteAIInstruction(id: number): Promise<boolean> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/ai-instructions/${id}`, { method: 'DELETE' });
    return res.ok;
  } catch {
    return false;
  }
}

export async function fetchAIFeedbackSummary(): Promise<AIFeedbackSummary | null> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/ai-feedback-summary`);
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

// ── Alert State (Investigating / Acknowledge) ─────────

export async function fetchAlertStates(): Promise<AlertState[]> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function toggleInvestigating(
  fingerprint: string,
  alertName: string,
): Promise<{ status: string; investigating_user: string | null } | null> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/investigate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint, alert_name: alertName }),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function acknowledgeAlerts(
  fingerprints: string[],
  alertNames: Record<string, string>,
  firingStarts: Record<string, string>,
): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/acknowledge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprints, alert_names: alertNames, firing_starts: firingStarts }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function unacknowledgeAlerts(fingerprints: string[]): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/unacknowledge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprints }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function markAlertsUpdated(fingerprints: string[]): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/mark-updated`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprints }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Escalation API ───────────────────────────────────

const ESCALATION_BASE = '/api/escalation';

export async function fetchEscalationTeams(): Promise<{id: string; name: string}[]> {
  try {
    const res = await fetch(`${ESCALATION_BASE}/teams`);
    if (!res.ok) return [];
    return await res.json();
  } catch { return []; }
}

export async function fetchEscalationUsers(): Promise<{id: string; name: string; email: string}[]> {
  try {
    const res = await fetch(`${ESCALATION_BASE}/users`);
    if (!res.ok) return [];
    return await res.json();
  } catch { return []; }
}

export async function escalateAlert(data: {
  team_id?: string;
  user_ids?: string[];
  alert_name: string;
  severity: string;
  summary: string;
  message: string;
  uip_link: string;
}): Promise<{success: boolean; error?: string}> {
  try {
    const res = await fetch(`${ESCALATION_BASE}/escalate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return await res.json();
  } catch {
    return { success: false, error: 'Network error' };
  }
}

export async function forceEnrich(fingerprint: string): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/force-enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function storeIncidentState(
  fingerprint: string,
  jiraKey: string,
  jiraUrl: string,
): Promise<void> {
  await fetch('/api/alert-states/incident', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ fingerprint, jira_key: jiraKey, jira_url: jiraUrl }),
  });
}

export async function storeEscalationState(
  fingerprint: string,
  escalatedTo: string,
): Promise<void> {
  await fetch('/api/alert-states/escalation', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ fingerprint, escalated_to: escalatedTo }),
  });
}

export async function submitRunbookFeedback(
  fingerprint: string,
  alertName: string,
  entryId: number,
  vote: 'up' | 'down' | 'none',
): Promise<void> {
  await fetch('/api/alert-states/runbook-feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ fingerprint, alert_name: alertName, entry_id: entryId, vote }),
  });
}

export async function fetchRunbookFeedback(
  entryIds: number[],
): Promise<RunbookFeedback[]> {
  if (entryIds.length === 0) return [];
  const res = await fetch(`/api/alert-states/runbook-feedback?entry_ids=${entryIds.join(',')}`, {
    credentials: 'include',
  });
  if (!res.ok) return [];
  return res.json();
}
