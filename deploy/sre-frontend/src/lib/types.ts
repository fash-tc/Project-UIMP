export interface Alert {
  id: string;
  fingerprint: string;
  name: string;
  status: string;
  severity: string;
  source: string[];
  hostName?: string;
  hostname?: string;
  description?: string;
  lastReceived: string;
  startedAt?: string;
  firingStartTime?: string;
  note?: string;
  tags?: Tag[];
  url?: string;
  triggerId?: string;
  zabbixInstance?: string;
}

export interface Tag {
  tag?: string;
  name?: string;
  value: string;
}

export interface AIEnrichment {
  assessed_severity: string;
  likely_cause: string;
  remediation: string;
  impact_scope: string;
  dedup_assessment: string;
  dedup_reason: string;
  noise_score: number;
  noise_reason: string;
  summary: string;
  llm_model?: string;
}

export interface SREFeedback {
  rating: 'positive' | 'negative' | 'correction';
  corrected_severity?: string;
  corrected_noise?: number;
  comment?: string;
  sre_user?: string;
  timestamp?: string;
}

export interface AlertStats {
  total: number;
  critical: number;
  high: number;
  warning: number;
  low: number;
  noise: number;
}

export interface RunbookEntry {
  id: number;
  alert_name: string;
  alert_fingerprint?: string;
  hostname?: string;
  service?: string;
  severity?: string;
  remediation: string;
  sre_user?: string;
  created_at: string;
  score?: number;
}

export interface AIInstruction {
  id: number;
  instruction: string;
  sre_user?: string;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface AIFeedbackSummary {
  total_runbook_entries: number;
  recent_entries: RunbookEntry[];
  active_instructions: number;
}

export interface AlertState {
  alert_fingerprint: string;
  alert_name: string;
  investigating_user: string | null;
  investigating_since: string | null;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  ack_firing_start: string | null;
  is_updated: number;
  // Incident tracking
  incident_jira_key?: string | null;
  incident_jira_url?: string | null;
  incident_created_by?: string | null;
  incident_created_at?: string | null;
  // Escalation tracking
  escalated_to?: string | null;
  escalated_by?: string | null;
  escalated_at?: string | null;
  // Severity override
  severity_override?: string | null;
  severity_override_by?: string | null;
}

export interface SSEEvent {
  type: string;
  fingerprint?: string;
  fingerprints?: string[];
  user?: string;
  active?: boolean;
  jira_key?: string;
  jira_url?: string;
  escalated_to?: string;
  entry_id?: number;
  vote?: string;
  severity?: string;
  rule_id?: number;
  alert_name_pattern?: string;
  hostname_pattern?: string;
  expires_at?: string;
  timestamp: string;
}

export interface RunbookFeedback {
  id: number;
  alert_fingerprint: string;
  alert_name: string;
  runbook_entry_id: number;
  vote: 'up' | 'down';
  user: string;
  created_at: string;
}

export interface SREFeedbackEntry {
  id: number;
  alert_fingerprint: string;
  alert_name: string;
  rating: 'positive' | 'negative' | 'correction';
  corrected_severity?: string;
  corrected_noise?: number;
  comment?: string;
  user: string;
  created_at: string;
  updated_at: string;
  vote_score: number;
  user_vote?: 'up' | 'down' | null;
}

export interface RunbookExclusion {
  id: number;
  alert_name: string;
  runbook_entry_id: number;
  excluded_by: string;
  created_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
}

export interface ClusterInfo {
  cluster_id: string;
  label?: string;
  fingerprints?: string[];
  alert_names?: string[];
  top_severity?: string;
  count?: number;
  hosts?: string[];
  assessment?: string;
  priority?: number;
}

export interface ShiftContext {
  new_since_last: number;
  resolved_since_last: number;
  trend: 'improving' | 'stable' | 'worsening';
  recurring: string[];
}

export interface SuggestedMerge {
  clusters: string[];
  reason: string;
}

export interface SituationSummary {
  one_liner: string | null;
  clusters: ClusterInfo[];
  shift_context: ShiftContext;
  recommended_actions: string[];
  generated_at: string;
  alert_hash: string;
  suggested_merges?: SuggestedMerge[];
}

// ── Incident Notification Types ──────────────────────

export interface IncidentAssessment {
  grade: string;
  feedback: string;
}

export interface WebhookSubscriber {
  id: number;
  name: string;
  url: string;
  is_active: boolean;
  created_at: string;
  secret?: string;  // only returned on creation/rotation
}

export interface WebhookDelivery {
  id: number;
  subscriber_id: number;
  subscriber_name?: string;
  timestamp: string;
  http_status: number | null;
  attempts: number;
  success: boolean;
  is_test: boolean;
}

export interface StatuspageComponent {
  id: string;
  name: string;
  status: string;
  description: string;
}

export interface StatuspageIncident {
  id: string;
  shortlink: string;
  status: string;
}
