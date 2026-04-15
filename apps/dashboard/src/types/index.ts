export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type DeviceStatus = "online" | "offline" | "warning" | "critical";
export type AlertStatus = "open" | "investigating" | "resolved" | "false_positive";
export type OSType = "windows" | "linux" | "macos";
export type UserRole = "owner" | "admin" | "analyst" | "viewer";
export type EvidenceType = "file" | "memory" | "log" | "network_capture" | "registry" | "process_dump";
export type CustodyAction = "acquired" | "accessed" | "transferred" | "archived" | "exported" | "verified";

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: UserRole;
  tenant_id: string;
  mfa_enabled: boolean;
  last_login: string | null;
}

export interface Tenant {
  id: string;
  name: string;
  plan: "starter" | "pro" | "enterprise";
  is_active: boolean;
  max_devices: number;
}

export interface Device {
  id: string;
  hostname: string;
  os: OSType;
  ip_address: string | null;
  status: DeviceStatus;
  agent_version: string | null;
  last_seen: string | null;
  is_active: boolean;
  created_at: string;
}

export interface MitreEntry {
  tactic: string;
  tactic_id: string;
  technique: string;
  technique_id: string;
  sub_technique_id?: string;
  evidence: string;
}

export interface IOC {
  type: "ip" | "hash" | "domain" | "url" | "process" | "registry";
  value: string;
  context: string;
  risk: "high" | "medium" | "low";
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  evidence: string;
}

export interface Recommendation {
  priority: number;
  action: string;
  description: string;
  requires_approval: boolean;
  action_type: string;
  target: string;
  automated_safe: boolean;
}

export interface LLMAnalysis {
  executive_summary: string;
  findings: Finding[];
  indicators: IOC[];
  mitre_mapping: MitreEntry[];
  hypotheses: string[];
  risk_level: Severity;
  confidence: number;
  recommendations: Recommendation[];
  forensic_next_steps: string[];
  is_imminent_danger: boolean;
  imminent_danger_reason: string | null;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  device_id: string;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  requires_approval: boolean;
  auto_action_taken: boolean;
  pending_action: PendingAction | null;
  llm_analysis: LLMAnalysis | null;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PendingAction {
  action_type: string;
  device_id: string;
  params: Record<string, unknown>;
  justification: string;
  risk_level: Severity;
}

export interface Evidence {
  id: string;
  device_id: string;
  alert_id: string | null;
  evidence_type: EvidenceType;
  filename: string;
  file_size: number | null;
  sha256_hash: string;
  sha512_hash?: string;
  acquisition_method: string;
  is_immutable: boolean;
  notes: string | null;
  acquired_by: string;
  acquired_at: string;
}

export interface CustodyRecord {
  id: string;
  action: CustodyAction;
  performed_by: string;
  performed_at: string;
  ip_address: string | null;
  signature: string;
  notes: string | null;
}

export interface CustodyChainResponse {
  evidence_id: string;
  integrity_verified: boolean;
  total_records: number;
  chain: CustodyRecord[];
}

export interface Subscription {
  id: string;
  plan: "starter" | "pro" | "enterprise";
  status: "active" | "past_due" | "canceled" | "trialing" | "incomplete";
  price_per_device: number;
  active_devices: number;
  current_period_start: string | null;
  current_period_end: string | null;
}

export interface Plan {
  id: string;
  name: string;
  price_per_device: number;
  max_devices: number | null;
  currency: string;
  billing_period: string;
  features: string[];
  popular?: boolean;
}

export interface DashboardStats {
  total_devices: number;
  online_devices: number;
  critical_alerts_24h: number;
  events_processed_24h: number;
  risk_level: Severity;
  open_alerts: number;
}

export interface IOCEnrichment {
  type: string;
  value: string;
  abuse_confidence?: number;
  country?: string;
  isp?: string;
  is_tor?: boolean;
  risk_score: number;
  malicious?: number;
  threat_label?: string | null;
}

export interface ApiError {
  detail: string;
  status?: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}
