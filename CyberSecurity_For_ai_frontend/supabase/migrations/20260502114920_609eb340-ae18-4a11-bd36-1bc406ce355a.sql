
CREATE TABLE public.firewall_logs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  session_id TEXT NOT NULL,
  security_enabled BOOLEAN NOT NULL,
  user_input TEXT NOT NULL,
  normalized_input TEXT,
  risk_score NUMERIC NOT NULL DEFAULT 0,
  attack_type TEXT,
  decision TEXT NOT NULL,
  final_prompt TEXT,
  llm_response TEXT,
  output_filter_action TEXT,
  latency_ms INTEGER,
  matched_patterns JSONB DEFAULT '[]'::jsonb
);

ALTER TABLE public.firewall_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Anyone can read firewall logs"
  ON public.firewall_logs FOR SELECT
  USING (true);

CREATE POLICY "Anyone can insert firewall logs"
  ON public.firewall_logs FOR INSERT
  WITH CHECK (true);

CREATE INDEX idx_firewall_logs_created_at ON public.firewall_logs(created_at DESC);
CREATE INDEX idx_firewall_logs_session ON public.firewall_logs(session_id);
