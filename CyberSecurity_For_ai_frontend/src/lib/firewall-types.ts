export type Decision = "allow" | "sanitize" | "block";

export interface FirewallMeta {
  risk_score: number;
  attack_type: string | null;
  decision: Decision;
  confidence: string;
  matched_patterns: { label: string; type: string; weight: number }[];
  normalized_input: string;
  final_prompt: string;
  output_filter_action: string;
  latency_ms: number;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  meta?: FirewallMeta;
}

export interface FirewallLog {
  id: string;
  created_at: string;
  session_id: string;
  security_enabled: boolean;
  user_input: string;
  normalized_input: string | null;
  risk_score: number;
  attack_type: string | null;
  decision: string;
  final_prompt: string | null;
  llm_response: string | null;
  output_filter_action: string | null;
  latency_ms: number | null;
  matched_patterns: any;
}
