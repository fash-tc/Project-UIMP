import { Alert, AIEnrichment, AlertStats, SREFeedback, RunbookEntry, AIInstruction, AIFeedbackSummary, AlertState, RunbookFeedback, SituationSummary, SuggestedMerge, SREFeedbackEntry, RunbookExclusion, PaginatedResponse, IncidentAssessment, WebhookSubscriber, WebhookDelivery, StatuspageComponent, StatuspageComponentUpdate, StatuspageIncident, Role, UserProfile, CustomAlertGroup, SharedMaintenanceAuthConfig } from './types';

const API_BASE = '/api/keep';

const SOURCE_LABELS: Record<string, string> = {
  zabbix: 'Zabbix',
  'grafana-irm': 'Grafana IRM',
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

async function readResponseBody(res: Response): Promise<any> {
  const contentType = res.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/json')) {
      return await res.json();
    }
    return await res.text();
  } catch {
    return null;
  }
}

function extractResponseError(body: any, fallback: string): string {
  if (typeof body === 'string') {
    const normalized = body.replace(/\s+/g, ' ').trim();
    if (!normalized || normalized.startsWith('<')) {
      return fallback;
    }
    return normalized.slice(0, 200);
  }
  if (body && typeof body === 'object') {
    return body.error || body.detail || body.message || fallback;
  }
  return fallback;
}

const MAINT_AUTH_STORAGE_KEY = 'ump-auth-token';

function getMaintenanceAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.sessionStorage.getItem(MAINT_AUTH_STORAGE_KEY);
  } catch {
    return null;
  }
}

function setMaintenanceAuthToken(token: string | null) {
  if (typeof window === 'undefined') return;
  try {
    if (token) {
      window.sessionStorage.setItem(MAINT_AUTH_STORAGE_KEY, token);
    } else {
      window.sessionStorage.removeItem(MAINT_AUTH_STORAGE_KEY);
    }
  } catch {
    // Ignore storage failures in private browsing or restricted contexts.
  }
}

function getMaintenanceWriteHeaders(): Record<string, string> | null {
  const token = getMaintenanceAuthToken();
  if (!token) return null;
  return { Authorization: `Bearer ${token}` };
}

function extractMaintenanceWriteError(body: any, fallback: string): string {
  const message = extractResponseError(body, fallback);
  if (/missing bearer token/i.test(message)) {
    return 'Maintenance API auth required. Sign in to Maintenance Auth on this page and retry.';
  }
  if (/invalid token/i.test(message)) {
    return 'Maintenance API token expired or invalid. Sign in to Maintenance Auth again.';
  }
  if (/validation error/i.test(message) || /field required/i.test(message)) {
    return 'Maintenance API auth required. Sign in to Maintenance Auth on this page and retry.';
  }
  return message;
}

const HIGHLIGHT_COLOR_ALIASES: Record<string, string> = {
  red: '#ef4444',
  orange: '#f97316',
  yellow: '#eab308',
  green: '#22c55e',
  blue: '#3b82f6',
  purple: '#a855f7',
  gray: '#6b7280',
};

export function normalizeHighlightColor(color?: string | null): string {
  if (!color) return '#ef4444';
  const normalized = color.trim().toLowerCase();
  return HIGHLIGHT_COLOR_ALIASES[normalized] || color;
}

export function colorWithAlpha(color: string | undefined | null, alpha: number): string {
  const normalized = normalizeHighlightColor(color);
  if (/^#[0-9a-f]{6}$/i.test(normalized)) {
    const clamped = Math.max(0, Math.min(1, alpha));
    const alphaHex = Math.round(clamped * 255).toString(16).padStart(2, '0');
    return `${normalized}${alphaHex}`;
  }
  return normalized;
}

function normalizeWebhookDelivery(raw: any): WebhookDelivery {
  return {
    id: raw.id,
    subscriber_id: raw.subscriber_id,
    subscriber_name: raw.subscriber_name,
    timestamp: raw.timestamp || raw.created_at || '',
    http_status: raw.http_status ?? raw.status_code ?? null,
    attempts: raw.attempts ?? raw.attempt ?? 0,
    success: Boolean(raw.success),
    is_test: Boolean(raw.is_test),
    event_type: raw.event_type || '',
    error_message: raw.error_message || null,
    payload_hash: raw.payload_hash || '',
  };
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

export async function searchRunbookEntries(search: string, limit = 20): Promise<RunbookEntry[]> {
  try {
    const params = new URLSearchParams();
    params.set('page', '1');
    params.set('limit', String(limit));
    if (search.trim()) params.set('search', search.trim());
    const res = await fetch(`${RUNBOOK_BASE}/entries?${params.toString()}`, { credentials: 'include' });
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data : (data.items || []);
  } catch {
    return [];
  }
}

export async function attachRunbookEntry(entryId: number, data: {
  alert_name: string;
  hostname?: string;
  service?: string;
}): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/entries/${entryId}/attach`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const body = await readResponseBody(res);
    return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, 'Failed to attach runbook') };
  } catch {
    return { ok: false, error: 'Network error' };
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

export async function unresolveAlert(fingerprint: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/alerts/enrich`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fingerprint,
        enrichments: { status: 'firing' },
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function unresolveAlerts(fingerprints: string[]): Promise<boolean> {
  try {
    const results = await Promise.all(
      fingerprints.map(fp => unresolveAlert(fp))
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
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(details),
    });
    const data = await readResponseBody(res);
    if (res.ok) {
      return { ok: true, issueKey: data.issue_key, issueUrl: data.issue_url };
    }
    return { ok: false, error: extractResponseError(data, 'Failed to create incident') };
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

export async function syncCustomAlertGroups(activeFingerprints: string[]): Promise<CustomAlertGroup[]> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/custom-groups/sync`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active_fingerprints: activeFingerprints }),
    });
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function createCustomAlertGroup(name: string, fingerprints: string[]): Promise<{ ok: boolean; group?: CustomAlertGroup; error?: string }> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/custom-groups`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, fingerprints }),
    });
    const body = await readResponseBody(res);
    if (!res.ok) return { ok: false, error: extractResponseError(body, 'Failed to create custom group') };
    return { ok: true, group: body };
  } catch (e: any) {
    return { ok: false, error: e.message || 'Network error' };
  }
}

export async function renameCustomAlertGroup(groupId: number, name: string): Promise<{ ok: boolean; group?: CustomAlertGroup; error?: string }> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/custom-groups/${groupId}`, {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    const body = await readResponseBody(res);
    if (!res.ok) return { ok: false, error: extractResponseError(body, 'Failed to rename custom group') };
    return { ok: true, group: body };
  } catch (e: any) {
    return { ok: false, error: e.message || 'Network error' };
  }
}

export async function addAlertsToCustomAlertGroup(groupId: number, fingerprints: string[]): Promise<{ ok: boolean; group?: CustomAlertGroup; error?: string }> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/custom-groups/${groupId}`, {
      method: 'PUT',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprints }),
    });
    const body = await readResponseBody(res);
    if (!res.ok) return { ok: false, error: extractResponseError(body, 'Failed to update custom group') };
    return { ok: true, group: body };
  } catch (e: any) {
    return { ok: false, error: e.message || 'Network error' };
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
  hostname?: string;
  message: string;
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
  firingStart?: string,
): Promise<void> {
  await fetch('/api/alert-states/incident', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ fingerprint, jira_key: jiraKey, jira_url: jiraUrl, firing_start: firingStart || '' }),
  });
}

export async function storeIncidentStateBulk(
  fingerprints: string[],
  jiraKey: string,
  jiraUrl: string,
  firingStarts?: Record<string, string>,
): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch('/api/alert-states/incident/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ fingerprints, jira_key: jiraKey, jira_url: jiraUrl, firing_starts: firingStarts || {} }),
    });
    const body = await readResponseBody(res);
    return {
      ok: res.ok,
      error: res.ok ? undefined : extractResponseError(body, 'Failed to store incident state'),
    };
  } catch (e: any) {
    return { ok: false, error: e.message || 'Network error' };
  }
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
  fingerprint: string,
): Promise<RunbookFeedback[]> {
  if (entryIds.length === 0) return [];
  const res = await fetch(`/api/alert-states/runbook-feedback?entry_ids=${entryIds.join(',')}&fingerprint=${encodeURIComponent(fingerprint)}`, {
    credentials: 'include',
  });
  if (!res.ok) return [];
  return res.json();
}

export async function fetchSituationSummary(): Promise<SituationSummary | null> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/situation-summary`);
    if (!res.ok) return null;
    const data = await res.json();
    if (!data.one_liner) return null;
    return data as SituationSummary;
  } catch {
    return null;
  }
}

export async function overrideSeverity(fingerprint: string, severity: string): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/severity-override`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fingerprint, severity }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function overrideSeverityBulk(fingerprints: string[], severity: string): Promise<boolean> {
  try {
    const results = await Promise.all(
      fingerprints.map(fp => overrideSeverity(fp, severity))
    );
    return results.every(r => r);
  } catch {
    return false;
  }
}

export async function invalidateSummary(): Promise<void> {
  try {
    await fetch(`${ALERT_STATE_BASE}/invalidate-summary`, { method: 'POST' });
  } catch {}
}

// ── Silence Rules ──────────────────────────────────

export interface SilenceRule {
  id: number;
  alert_name_pattern: string;
  hostname_pattern: string | null;
  created_by: string;
  created_at: string;
  expires_at: string;
  reason: string;
  active: number;
}

export async function fetchSilenceRules(): Promise<SilenceRule[]> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/silence-rules`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function createSilenceRule(
  alertNamePattern: string,
  durationSeconds: number,
  hostnamePattern?: string,
  reason?: string,
): Promise<{ id: number; expires_at: string } | null> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/silence-rules`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        alert_name_pattern: alertNamePattern,
        hostname_pattern: hostnamePattern || null,
        duration_seconds: durationSeconds,
        reason: reason || '',
      }),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function cancelSilenceRule(ruleId: number): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/silence-rules/cancel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: ruleId }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** Check if an alert name matches a pattern (supports wildcards * and comma-separated patterns) */
function matchesNamePattern(alertName: string, pattern: string): boolean {
  const name = alertName.toLowerCase();
  // Support comma-separated patterns: "High Memory Utilization, High CPU Utilization"
  const patterns = pattern.includes(',') ? pattern.split(',').map(p => p.trim()) : [pattern.trim()];
  for (const p of patterns) {
    const pat = p.toLowerCase();
    if (pat.includes('*')) {
      // Wildcard matching: "High * Utilization" matches "High CPU Utilization on host"
      const regexStr = pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*');
      if (new RegExp(regexStr, 'i').test(name)) return true;
    } else {
      // Substring match
      if (name.includes(pat)) return true;
    }
  }
  return false;
}

/** Check if a hostname matches a pattern (supports wildcards * and comma-separated) */
function matchesHostPattern(hostname: string, pattern: string): boolean {
  const patterns = pattern.includes(',') ? pattern.split(',').map(p => p.trim()) : [pattern.trim()];
  for (const p of patterns) {
    const hostPattern = p.toLowerCase();
    if (hostPattern.includes('*')) {
      const regexStr = hostPattern.replace(/\./g, '\\.').replace(/\*/g, '.*');
      const regex = new RegExp('(^|\\.)' + regexStr + '$', 'i');
      if (regex.test(hostname)) return true;
    } else {
      if (hostname.toLowerCase().includes(hostPattern)) return true;
    }
  }
  return false;
}

/** Check if an alert matches any active silence rule */
export function isAlertSilenced(
  alertName: string,
  hostname: string,
  rules: SilenceRule[],
): SilenceRule | null {
  const now = new Date().toISOString();
  for (const rule of rules) {
    if (!rule.active || rule.expires_at < now) continue;
    // Check alert name pattern
    if (!matchesNamePattern(alertName, rule.alert_name_pattern)) continue;
    // Check hostname pattern if specified
    if (rule.hostname_pattern) {
      if (!matchesHostPattern(hostname, rule.hostname_pattern)) continue;
    }
    return rule;
  }
  return null;
}

// ── SRE Feedback (New Multi-Entry System) ─────────────────

export async function fetchSREFeedback(fingerprint: string): Promise<SREFeedbackEntry[]> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/sre-feedback?fingerprint=${encodeURIComponent(fingerprint)}`, {
      credentials: 'include',
    });
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchAllSREFeedback(params: {
  page?: number;
  limit?: number;
  search?: string;
  rating?: string;
  user?: string;
  sort?: string;
} = {}): Promise<PaginatedResponse<SREFeedbackEntry>> {
  try {
    const qs = new URLSearchParams();
    if (params.page) qs.set('page', String(params.page));
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.search) qs.set('search', params.search);
    if (params.rating) qs.set('rating', params.rating);
    if (params.user) qs.set('user', params.user);
    if (params.sort) qs.set('sort', params.sort);
    const res = await fetch(`${ALERT_STATE_BASE}/sre-feedback/all?${qs.toString()}`, {
      credentials: 'include',
    });
    if (!res.ok) return { items: [], total: 0, page: 1, limit: 50 };
    return await res.json();
  } catch {
    return { items: [], total: 0, page: 1, limit: 50 };
  }
}

export async function submitSREFeedback(data: {
  fingerprint: string;
  alert_name: string;
  rating?: string;
  corrected_severity?: string;
  corrected_noise?: number;
  comment?: string;
}): Promise<{ id: number } | null> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/sre-feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(data),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

export async function updateSREFeedback(id: number, data: {
  rating?: string;
  corrected_severity?: string;
  corrected_noise?: number;
  comment?: string;
}): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/sre-feedback/update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ id, ...data }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function deleteSREFeedback(id: number): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/sre-feedback/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ id }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function bulkDeleteSREFeedback(ids: number[]): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/sre-feedback/bulk-delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ ids }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function voteSREFeedback(id: number, vote: 'up' | 'down' | 'none'): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/sre-feedback/vote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ id, vote }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Runbook Exclusions ─────────────────────────────────

export async function fetchRunbookExclusions(alertName: string): Promise<RunbookExclusion[]> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/runbook-exclusions?alert_name=${encodeURIComponent(alertName)}`, {
      credentials: 'include',
    });
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchAllRunbookExclusions(params: {
  page?: number;
  limit?: number;
  search?: string;
} = {}): Promise<PaginatedResponse<RunbookExclusion>> {
  try {
    const qs = new URLSearchParams();
    if (params.page) qs.set('page', String(params.page));
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.search) qs.set('search', params.search);
    const res = await fetch(`${ALERT_STATE_BASE}/runbook-exclusions/all?${qs.toString()}`, {
      credentials: 'include',
    });
    if (!res.ok) return { items: [], total: 0, page: 1, limit: 50 };
    return await res.json();
  } catch {
    return { items: [], total: 0, page: 1, limit: 50 };
  }
}

export async function createRunbookExclusion(alertName: string, runbookEntryId: number): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/runbook-exclusions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ alert_name: alertName, runbook_entry_id: runbookEntryId }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export async function deleteRunbookExclusion(id: number): Promise<boolean> {
  try {
    const res = await fetch(`${ALERT_STATE_BASE}/runbook-exclusions/delete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ id }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Maintenance Events ─────────────────────────────────

export interface MaintenanceEvent {
  id: number;
  source_type: string;
  title: string;
  summary: string | null;
  vendor: string;
  severity: string | null;
  start_time: string;
  end_time: string | null;
  impact: string | null;
  status: string | null;
  permalink: string;
  ingested_at: string;
  event_type: string;
}

export async function fetchMaintenanceEvents(): Promise<MaintenanceEvent[]> {
  try {
    const res = await fetch('/api/maintenance/active-now');
    if (!res.ok) return [];
    const data = await res.json();
    return data.results || [];
  } catch {
    return [];
  }
}

// Re-export SuggestedMerge so consumers can import from keep-api if needed
export type { SuggestedMerge };

// ── Incident Notification APIs ───────────────────────

const MAINT_BASE = '/api/maintenance';

export function hasMaintenanceAuthToken(): boolean {
  return Boolean(getMaintenanceAuthToken());
}

export function clearMaintenanceAuthToken() {
  setMaintenanceAuthToken(null);
}

export async function loginMaintenanceAuth(username: string, password: string): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`${MAINT_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const body = await readResponseBody(res);
    if (!res.ok) return { ok: false, error: extractResponseError(body, `HTTP ${res.status}`) };
    if (!body?.token || typeof body.token !== 'string') {
      return { ok: false, error: 'Maintenance login succeeded but no token was returned.' };
    }
    setMaintenanceAuthToken(body.token);
    return { ok: true };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

export async function fetchSharedMaintenanceAuth(): Promise<SharedMaintenanceAuthConfig> {
  const res = await fetch('/api/auth/shared-integrations/maintenance', { credentials: 'include' });
  const body = await readResponseBody(res);
  if (!res.ok) throw new Error(extractResponseError(body, 'Failed to load shared maintenance auth'));
  return body as SharedMaintenanceAuthConfig;
}

export async function saveSharedMaintenanceAuth(username: string, password: string): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch('/api/auth/shared-integrations/maintenance', {
    method: 'PUT',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const body = await readResponseBody(res);
  return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, 'Failed to save shared maintenance auth') };
}

export async function testSharedMaintenanceAuth(): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch('/api/auth/shared-integrations/maintenance/test', {
    method: 'POST',
    credentials: 'include',
  });
  const body = await readResponseBody(res);
  return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, 'Failed to test shared maintenance auth') };
}

export async function clearSharedMaintenanceAuth(): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch('/api/auth/shared-integrations/maintenance', {
    method: 'DELETE',
    credentials: 'include',
  });
  const body = await readResponseBody(res);
  return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, 'Failed to clear shared maintenance auth') };
}

export async function bootstrapSharedMaintenanceAuth(): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch('/api/auth/maintenance/bootstrap', {
    method: 'POST',
    credentials: 'include',
  });
  const body = await readResponseBody(res);
  if (!res.ok) return { ok: false, error: extractResponseError(body, 'Failed to bootstrap maintenance auth') };
  if (!body?.token || typeof body.token !== 'string') {
    return { ok: false, error: 'Maintenance bootstrap succeeded but no token was returned.' };
  }
  setMaintenanceAuthToken(body.token);
  return { ok: true };
}

export async function persistWebhookSubscriberSecret(id: number, name: string, url: string, secret: string): Promise<{ ok: boolean; error?: string }> {
  const res = await fetch(`/api/auth/webhook-subscriber-secrets/${id}`, {
    method: 'PUT',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, url, secret }),
  });
  const body = await readResponseBody(res);
  return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, 'Failed to store webhook signing secret') };
}

export async function assessIncidentDescription(title: string, description: string): Promise<IncidentAssessment> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/incident/assess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, description }),
    });
    return await res.json();
  } catch {
    return { grade: '?', feedback: 'Failed to connect to assessment service.' };
  }
}

export async function sendIncidentWebhook(title: string, description: string, started_at?: string): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/incident/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, description, started_at }),
    });
    return await res.json();
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

export async function fetchStatuspageComponents(): Promise<StatuspageComponent[]> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/statuspage/components`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function createStatuspageIncident(data: {
  name: string;
  body: string;
  status: string;
  impact_override: string;
  components?: StatuspageComponentUpdate[];
  component_ids?: string[];
}): Promise<{ result?: StatuspageIncident; error?: string }> {
  try {
    const payload = {
      ...data,
      components: data.components ?? (data.component_ids || []).map(component_id => ({
        component_id,
        status: 'degraded_performance' as const,
      })),
    };
    const res = await fetch(`${RUNBOOK_BASE}/statuspage/incident`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    if (!res.ok) return { error: json.error || `HTTP ${res.status}` };
    return { result: json };
  } catch {
    return { error: 'Network error' };
  }
}

// ── Webhook Management APIs ──────────────────────────

export async function fetchStatuspageIncidents(): Promise<StatuspageIncident[]> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/statuspage/incidents`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function updateStatuspageIncident(id: string, data: {
  name: string;
  body: string;
  status: string;
  impact_override: string;
  components: StatuspageComponentUpdate[];
}): Promise<{ result?: StatuspageIncident; error?: string }> {
  try {
    const res = await fetch(`${RUNBOOK_BASE}/statuspage/incidents/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const json = await res.json();
    if (!res.ok) return { error: json.error || `HTTP ${res.status}` };
    return { result: json };
  } catch {
    return { error: 'Network error' };
  }
}

export async function fetchWebhookSubscribers(): Promise<WebhookSubscriber[]> {
  try {
    const res = await fetch(`${MAINT_BASE}/webhooks/subscribers`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function createWebhookSubscriber(name: string, url: string): Promise<{ subscriber?: WebhookSubscriber; error?: string }> {
  try {
    const authHeaders = getMaintenanceWriteHeaders();
    if (!authHeaders) {
      return { error: 'Maintenance API auth required. Sign in to Maintenance Auth on this page and retry.' };
    }
    const res = await fetch(`${MAINT_BASE}/webhooks/subscribers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify({ name, url }),
    });
    const json = await readResponseBody(res);
    if (!res.ok) return { error: extractMaintenanceWriteError(json, `HTTP ${res.status}`) };
    return { subscriber: json };
  } catch {
    return { error: 'Network error' };
  }
}

export async function updateWebhookSubscriber(id: number, data: Partial<{ name: string; url: string; is_active: boolean }>): Promise<{ ok: boolean; error?: string }> {
  try {
    const authHeaders = getMaintenanceWriteHeaders();
    if (!authHeaders) {
      return { ok: false, error: 'Maintenance API auth required. Sign in to Maintenance Auth on this page and retry.' };
    }
    const res = await fetch(`${MAINT_BASE}/webhooks/subscribers/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify(data),
    });
    const body = await readResponseBody(res);
    return { ok: res.ok, error: res.ok ? undefined : extractMaintenanceWriteError(body, `HTTP ${res.status}`) };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

export async function deleteWebhookSubscriber(id: number): Promise<{ ok: boolean; error?: string }> {
  try {
    const authHeaders = getMaintenanceWriteHeaders();
    if (!authHeaders) {
      return { ok: false, error: 'Maintenance API auth required. Sign in to Maintenance Auth on this page and retry.' };
    }
    const res = await fetch(`${MAINT_BASE}/webhooks/subscribers/${id}`, { method: 'DELETE', headers: authHeaders });
    const body = await readResponseBody(res);
    return { ok: res.ok, error: res.ok ? undefined : extractMaintenanceWriteError(body, `HTTP ${res.status}`) };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

export async function rotateWebhookSecret(id: number): Promise<{ secret?: string; error?: string }> {
  try {
    const authHeaders = getMaintenanceWriteHeaders();
    if (!authHeaders) {
      return { error: 'Maintenance API auth required. Sign in to Maintenance Auth on this page and retry.' };
    }
    const res = await fetch(`${MAINT_BASE}/webhooks/subscribers/${id}/rotate-secret`, { method: 'POST', headers: authHeaders });
    const json = await readResponseBody(res);
    if (!res.ok) return { error: extractMaintenanceWriteError(json, `HTTP ${res.status}`) };
    return { secret: json.secret };
  } catch {
    return { error: 'Network error' };
  }
}

export async function testWebhookDelivery(id: number): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`${MAINT_BASE}/webhooks/test/${id}`, { method: 'POST' });
    const body = await readResponseBody(res);
    return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, `HTTP ${res.status}`) };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

export async function sendIncidentWebhookPreview(details?: Partial<{ title: string; description: string; started_at: string }>): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch('/api/runbook/incident/webhook', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: details?.title || 'Test Incident: Customer-facing outage',
        description: details?.description || 'This is a preview incident generated from UIP so you can review the customer webhook payload.',
        started_at: details?.started_at || new Date().toISOString(),
        preview_only: true,
      }),
    });
    const body = await readResponseBody(res);
    return { ok: res.ok, error: res.ok ? undefined : extractResponseError(body, `HTTP ${res.status}`) };
  } catch {
    return { ok: false, error: 'Network error' };
  }
}

export async function fetchWebhookDeliveries(subscriberId?: number, success?: boolean): Promise<WebhookDelivery[]> {
  try {
    const params = new URLSearchParams();
    if (subscriberId !== undefined) params.set('subscriber_id', String(subscriberId));
    if (success !== undefined) params.set('success', String(success));
    const qs = params.toString();
    const res = await fetch(`${MAINT_BASE}/webhooks/deliveries${qs ? '?' + qs : ''}`);
    if (!res.ok) return [];
    const data = await readResponseBody(res);
    return Array.isArray(data) ? data.map(normalizeWebhookDelivery) : [];
  } catch {
    return [];
  }
}

// ── Admin: User Management ────────────────────────────

export async function fetchUsers(): Promise<UserProfile[]> {
  const res = await fetch('/api/auth/users', { credentials: 'include' });
  const body = await readResponseBody(res);
  if (!res.ok) throw new Error(extractResponseError(body, 'Failed to load users'));
  return Array.isArray(body) ? body : [];
}

export async function createUser(username: string, display_name: string, password: string, role_id: number): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch('/api/auth/users', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, display_name, password, role_id }),
    });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || 'Failed' };
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

export async function updateUser(id: number, data: Partial<{ display_name: string; role_id: number; password: string }>): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`/api/auth/users/${id}`, {
      method: 'PUT', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const result = await res.json();
    if (!res.ok) return { ok: false, error: result.error || 'Failed' };
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

export async function deleteUser(id: number): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`/api/auth/users/${id}`, { method: 'DELETE', credentials: 'include' });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || 'Failed' };
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

// ── Admin: Role Management ────────────────────────────

export async function fetchRoles(): Promise<Role[]> {
  const res = await fetch('/api/auth/roles', { credentials: 'include' });
  const body = await readResponseBody(res);
  if (!res.ok) throw new Error(extractResponseError(body, 'Failed to load roles'));
  return Array.isArray(body) ? body : [];
}

export async function createRole(name: string, description: string, permissions: string[]): Promise<{ ok: boolean; id?: number; error?: string }> {
  try {
    const res = await fetch('/api/auth/roles', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description, permissions }),
    });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || 'Failed' };
    return { ok: true, id: data.id };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

export async function updateRole(id: number, data: Partial<{ name: string; description: string }>): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`/api/auth/roles/${id}`, {
      method: 'PUT', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const result = await res.json();
    if (!res.ok) return { ok: false, error: result.error || 'Failed' };
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

export async function deleteRole(id: number): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`/api/auth/roles/${id}`, { method: 'DELETE', credentials: 'include' });
    const data = await res.json();
    if (!res.ok) return { ok: false, error: data.error || 'Failed' };
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

export async function updateRolePermissions(id: number, permissions: string[]): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`/api/auth/roles/${id}/permissions`, {
      method: 'PUT', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ permissions }),
    });
    const result = await res.json();
    if (!res.ok) return { ok: false, error: result.error || 'Failed' };
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

// ── Alert Rules ───────────────────────────────────────

export interface AlertRule {
  id: number;
  name: string;
  rule_type: 'routing' | 'highlight';
  conditions_json: any;
  expression_text: string;
  action?: string;
  action_params?: any;
  color?: string;
  label?: string;
  priority: number;
  enabled: boolean;
  created_by: string;
  created_at: string;
}

export async function fetchAlertRules(type?: 'routing' | 'highlight'): Promise<AlertRule[]> {
  try {
    const qs = type ? `?type=${type}` : '';
    const res = await fetch(`/api/alert-states/rules${qs}`, { credentials: 'include' });
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function createAlertRule(rule: Partial<AlertRule>): Promise<{ ok: boolean; id?: number; error?: string }> {
  try {
    const res = await fetch('/api/alert-states/rules', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(rule),
    });
    const data = await readResponseBody(res);
    if (!res.ok) return { ok: false, error: extractResponseError(data, 'Failed to create rule') };
    return { ok: true, id: data.id };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

export async function updateAlertRule(id: number, updates: Partial<AlertRule>): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`/api/alert-states/rules/${id}`, {
      method: 'PUT', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    const data = await readResponseBody(res);
    if (!res.ok) return { ok: false, error: extractResponseError(data, 'Failed to update rule') };
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

export async function deleteAlertRule(id: number): Promise<{ ok: boolean; error?: string }> {
  try {
    const res = await fetch(`/api/alert-states/rules/${id}`, { method: 'DELETE', credentials: 'include' });
    const data = await readResponseBody(res);
    if (!res.ok) return { ok: false, error: extractResponseError(data, 'Failed to delete rule') };
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

// ── Webhook Test Receiver ────────────────────────────

export interface WebhookTestDelivery {
  id: number;
  timestamp: string;
  headers: Record<string, string>;
  body: any;
  signature_header: string;
  signature_result: string;
  content_length: number;
}

export async function fetchWebhookTestDeliveries(): Promise<WebhookTestDelivery[]> {
  try {
    const res = await fetch('/api/runbook/webhook-test/deliveries', { credentials: 'include' });
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function clearWebhookTestDeliveries(): Promise<{ ok: boolean }> {
  try {
    const res = await fetch('/api/runbook/webhook-test/deliveries', { method: 'DELETE', credentials: 'include' });
    return { ok: res.ok };
  } catch {
    return { ok: false };
  }
}

export const CONDITION_FIELDS = [
  { value: 'hostname', label: 'Hostname' },
  { value: 'name', label: 'Alert Name' },
  { value: 'severity', label: 'Severity' },
  { value: 'source', label: 'Source' },
  { value: 'description', label: 'Description' },
  { value: 'status', label: 'Status' },
  { value: 'zabbixInstance', label: 'Zabbix Instance' },
  { value: 'payload', label: 'Entire Payload' },
];

export const CONDITION_OPERATORS = [
  { value: 'equals', label: '=' },
  { value: 'not_equals', label: '!=' },
  { value: 'contains', label: 'contains' },
  { value: 'not_contains', label: 'not contains' },
  { value: 'starts_with', label: 'starts with' },
  { value: 'ends_with', label: 'ends with' },
  { value: 'regex', label: 'regex' },
  { value: '>=', label: '>=' },
  { value: '<=', label: '<=' },
  { value: '>', label: '>' },
  { value: '<', label: '<' },
];

export const ALL_PERMISSIONS = [
  { key: 'view_dashboard', label: 'View Dashboard', group: 'Views' },
  { key: 'view_alerts', label: 'View Alerts', group: 'Views' },
  { key: 'view_knowledge_base', label: 'View Knowledge Base', group: 'Views' },
  { key: 'view_settings', label: 'View Settings', group: 'Views' },
  { key: 'view_webhooks', label: 'View Webhooks', group: 'Views' },
  { key: 'view_admin', label: 'View Admin', group: 'Views' },
  { key: 'ack_alerts', label: 'Acknowledge Alerts', group: 'Alert Actions' },
  { key: 'resolve_alerts', label: 'Resolve Alerts', group: 'Alert Actions' },
  { key: 'silence_alerts', label: 'Silence Alerts', group: 'Alert Actions' },
  { key: 'investigate_alerts', label: 'Investigate Alerts', group: 'Alert Actions' },
  { key: 'escalate_alerts', label: 'Escalate Alerts', group: 'Alert Actions' },
  { key: 'override_severity', label: 'Override Severity', group: 'Alert Actions' },
  { key: 'create_tickets', label: 'Create Jira Tickets', group: 'Incidents' },
  { key: 'create_incidents', label: 'Create Incidents', group: 'Incidents' },
  { key: 'manage_routing_rules', label: 'Manage Routing Rules', group: 'Management' },
  { key: 'manage_highlight_rules', label: 'Manage Highlight Rules', group: 'Management' },
  { key: 'manage_webhooks', label: 'Manage Webhooks', group: 'Management' },
  { key: 'manage_users', label: 'Manage Users', group: 'Admin' },
  { key: 'manage_roles', label: 'Manage Roles', group: 'Admin' },
];

/* ── Client-side highlight rule evaluator ── */

const SEVERITY_ORDINAL: Record<string, number> = {
  critical: 5, high: 4, warning: 3, low: 2, info: 1, unknown: 0,
};

function getAlertField(alert: Alert, field: string): string {
  if (field === 'payload') {
    return Object.values(alert).filter(v => typeof v === 'string').join(' ');
  }
  if (field === 'hostname') return alert.hostName || (alert as any).hostname || '';
  return (alert as any)[field] ?? '';
}

function evaluateLeaf(alert: Alert, cond: { field: string; op: string; value: string }): boolean {
  const raw = getAlertField(alert, cond.field);
  const val = cond.value || '';

  // Severity ordinal comparison
  if (cond.field === 'severity' && ['>=', '<=', '>', '<'].includes(cond.op)) {
    const a = SEVERITY_ORDINAL[raw.toLowerCase()] ?? 0;
    const b = SEVERITY_ORDINAL[val.toLowerCase()] ?? 0;
    switch (cond.op) {
      case '>=': return a >= b;
      case '<=': return a <= b;
      case '>': return a > b;
      case '<': return a < b;
    }
  }

  const fieldLower = raw.toLowerCase();
  const valLower = val.toLowerCase();

  switch (cond.op) {
    case 'equals': return fieldLower === valLower;
    case 'not_equals': return fieldLower !== valLower;
    case 'contains': return fieldLower.includes(valLower);
    case 'not_contains': return !fieldLower.includes(valLower);
    case 'starts_with': return fieldLower.startsWith(valLower);
    case 'ends_with': return fieldLower.endsWith(valLower);
    case 'regex':
      try { return new RegExp(val, 'i').test(raw); } catch { return false; }
    case '>=': return parseFloat(raw) >= parseFloat(val);
    case '<=': return parseFloat(raw) <= parseFloat(val);
    case '>': return parseFloat(raw) > parseFloat(val);
    case '<': return parseFloat(raw) < parseFloat(val);
    default: return false;
  }
}

export function evaluateCondition(alert: Alert, condition: any): boolean {
  if (!condition) return false;
  if (condition.AND) {
    return (condition.AND as any[]).every(c => evaluateCondition(alert, c));
  }
  if (condition.OR) {
    return (condition.OR as any[]).some(c => evaluateCondition(alert, c));
  }
  if (condition.field && condition.op) {
    return evaluateLeaf(alert, condition);
  }
  return false;
}

export interface HighlightMatch {
  color: string;
  label: string;
  style: 'side' | 'box';
}

export function matchHighlightRules(alert: Alert, rules: AlertRule[]): HighlightMatch | null {
  for (const rule of rules) {
    if (!rule.enabled) continue;
    const cond = typeof rule.conditions_json === 'string'
      ? JSON.parse(rule.conditions_json)
      : rule.conditions_json;
    if (evaluateCondition(alert, cond)) {
      return {
        color: normalizeHighlightColor(rule.color),
        label: rule.label || '',
        style: rule.action_params?.highlight_style === 'box' ? 'box' : 'side',
      };
    }
  }
  return null;
}
