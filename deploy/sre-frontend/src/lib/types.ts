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
  note?: string;
  tags?: Tag[];
  url?: string;
  triggerId?: string;
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
