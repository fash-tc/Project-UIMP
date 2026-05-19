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
  vote_score?: number;
  user_vote?: 'up' | 'down' | null;
  [key: string]: unknown;
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
  severity?: string;
  active?: boolean;
  jira_key?: string;
  jira_url?: string;
  escalated_to?: string;
  entry_id?: number;
  vote?: string;
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

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page?: number;
  limit?: number;
  offset?: number;
}

export interface Role {
  id: number;
  name: string;
  description?: string;
  permissions: string[];
  is_system?: boolean;
  user_count?: number;
  created_at?: string;
  [key: string]: unknown;
}

export interface UserProfile {
  id: number;
  username: string;
  display_name?: string;
  name?: string;
  email?: string;
  role_id?: number | null;
  role_name?: string;
  roles?: Role[];
  is_active?: boolean;
  created_at?: string;
  [key: string]: unknown;
}

export interface SharedMaintenanceAuthConfig {
  configured?: boolean;
  username?: string;
  updated_by?: string;
  updated_at?: string;
  [key: string]: unknown;
}

export interface CustomAlertGroup {
  id: number;
  name: string;
  fingerprints: string[];
  active_count?: number;
  created_at?: string;
  [key: string]: unknown;
}

export interface SREFeedbackEntry {
  id: number;
  alert_fingerprint?: string;
  alert_name?: string;
  rating: string;
  corrected_severity?: string;
  corrected_noise?: number;
  vote?: 'up' | 'down' | 'none';
  vote_score: number;
  user_vote?: 'up' | 'down' | null;
  comment?: string;
  user: string;
  created_at: string;
  [key: string]: unknown;
}

export interface RunbookExclusion {
  id: number;
  alert_name?: string;
  runbook_entry_id?: number;
  excluded_by: string;
  created_at: string;
  [key: string]: unknown;
}

export interface IncidentAssessment {
  grade: string;
  feedback?: string;
  title?: string;
  summary?: string;
  impact?: string;
  severity?: string;
  components?: string[];
  [key: string]: unknown;
}

export type StatuspageComponentStatus = 'operational' | 'degraded_performance' | 'partial_outage' | 'major_outage' | string;

export interface StatuspageComponent {
  id: string;
  name: string;
  description?: string;
  status: StatuspageComponentStatus;
  group_id?: string | null;
  [key: string]: unknown;
}

export interface StatuspageComponentUpdate {
  id?: string;
  component_id: string;
  status: StatuspageComponentStatus;
}

export interface StatuspageIncident {
  id: string;
  name: string;
  status: string;
  impact?: string;
  components: StatuspageComponent[];
  created_at?: string;
  updated_at?: string;
  shortlink?: string;
  [key: string]: unknown;
}

export interface WebhookSubscriber {
  id: number;
  name: string;
  url: string;
  is_active?: boolean;
  [key: string]: unknown;
}

export interface WebhookDelivery {
  id: number;
  subscriber_id?: number;
  status?: string;
  created_at?: string;
  [key: string]: unknown;
}

export interface OpenSRSHealthSample {
  timestamp: string;
  message: string;
  labels?: Record<string, string>;
  [key: string]: unknown;
}

export interface OpenSRSHealthHotspot {
  key: string;
  events: number;
  failures: number;
  timeouts: number;
  slow: number;
  avg_latency_ms: number | null;
  p95_latency_ms: number | null;
  issue_type?: string;
  impact?: string;
  trend?: string;
  examples?: OpenSRSHealthSample[];
}

export interface OpenSRSHealthIssue {
  lane: string;
  lane_label: string;
  type: string;
  severity: string;
  where: string;
  host: string;
  action: string;
  impact: string;
  events: number;
  failures: number;
  timeouts: number;
  slow: number;
  p95_latency_ms: number | null;
  trend: string;
  description: string;
  evidence: OpenSRSHealthSample[];
}

export interface OpenSRSHealthIssueSummary {
  has_issue: boolean;
  primary_issue: OpenSRSHealthIssue | null;
  issues: OpenSRSHealthIssue[];
  health_signals: Record<string, string>;
}

export interface OpenSRSHealthLane {
  id: string;
  label: string;
  status: 'healthy' | 'degraded' | 'unknown' | string;
  events: number;
  errors: number;
  failures: number;
  timeouts: number;
  slow?: number;
  avg_latency_ms: number | null;
  p95_latency_ms: number | null;
  samples: OpenSRSHealthSample[];
  problem_samples?: OpenSRSHealthSample[];
  hotspots?: OpenSRSHealthHotspot[];
  top_hosts?: OpenSRSHealthHotspot[];
  error?: string;
}

export interface OpenSRSHealthReportSummary {
  run_id: string;
  started_at: string;
  completed_at: string;
  requested_by?: string | null;
  window_seconds: number;
  overall: 'healthy' | 'degraded' | 'unknown' | string;
  error?: string;
}

export interface OpenSRSHealthReport extends OpenSRSHealthReportSummary {
  lanes: OpenSRSHealthLane[];
  issue_summary?: OpenSRSHealthIssueSummary;
  timeline: Array<{
    bucket: string;
    lanes: string[];
  }>;
  correlations: Array<{
    bucket: string;
    lanes: string[];
  }>;
  ai_analysis: Record<string, unknown>;
}

export interface OpenSRSLogAnalysisResult {
  analysis: Record<string, unknown>;
  evidence: {
    query: string;
    range_seconds: number;
    entries_analyzed: number;
    access_scope?: {
      source?: string;
      query: string;
      range_seconds: number;
      entries_analyzed: number;
      sample_cap?: number;
    };
    failures: number;
    timeouts: number;
    slow: number;
    avg_latency_ms: number | null;
    p95_latency_ms: number | null;
    problem_areas: OpenSRSHealthHotspot[];
    latency_areas?: OpenSRSHealthHotspot[];
    tld_areas?: OpenSRSHealthHotspot[];
    top_hosts: OpenSRSHealthHotspot[];
    problem_samples: OpenSRSHealthSample[];
    samples: OpenSRSHealthSample[];
  };
}

export type StatuspageIncidentStatus = 'investigating' | 'identified' | 'monitoring' | 'resolved' | 'scheduled_maintenance';
export type StatuspageImpact = 'none' | 'minor' | 'major' | 'critical' | 'maintenance';
export type InternalComponentStatus = 'operational' | 'degraded_performance' | 'partial_outage' | 'major_outage' | 'maintenance';

export interface InternalStatuspageComponent {
  id: number;
  component_id?: number;
  component_status?: InternalComponentStatus;
  group_id?: number | null;
  group_name?: string | null;
  name: string;
  description: string;
  status: InternalComponentStatus;
  display_order: number;
  active?: number;
  created_at: string;
  updated_at: string;
}

export interface InternalStatuspageComponentGroup {
  id: number | null;
  name: string;
  description: string;
  display_order: number;
  active?: number;
  components: InternalStatuspageComponent[];
}

export interface InternalStatuspageIncident {
  id: number;
  title: string;
  status: StatuspageIncidentStatus;
  impact: StatuspageImpact;
  created_by: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
  scheduled_start?: string | null;
  scheduled_end?: string | null;
  components?: InternalStatuspageComponent[];
  latest_update?: {
    id: number;
    incident_id: number;
    status: StatuspageIncidentStatus;
    body: string;
    created_by: string;
    created_at: string;
    email_required: number;
  } | null;
}

export interface InternalStatuspageSummary {
  overall_status: string;
  components: InternalStatuspageComponent[];
  component_groups: InternalStatuspageComponentGroup[];
  active_incidents: InternalStatuspageIncident[];
  recent_incidents: InternalStatuspageIncident[];
}

export interface StatuspageSubscriber {
  id: number;
  email: string;
  label: string;
  active: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface StatuspageEmailDelivery {
  id: number;
  incident_update_id: number;
  recipient_email: string;
  subject: string;
  status: 'pending' | 'sent' | 'failed';
  attempts: number;
  last_error: string;
  created_at: string;
  sent_at?: string | null;
  updated_at: string;
}

export interface StatuspageSmtpSettings {
  host: string;
  port: number;
  tls: boolean;
  username: string;
  password: string;
  password_set: boolean;
  email_from: string;
}
