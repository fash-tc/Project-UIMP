import { Alert, AIEnrichment, AlertStats, SREFeedback } from './types';

const API_BASE = '/api/keep';

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
