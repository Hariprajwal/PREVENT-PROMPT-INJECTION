import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { ChevronDown, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { FirewallLog } from "@/lib/firewall-types";

const decisionColor: Record<string, string> = {
  allow: "text-primary border-primary/40 bg-primary/10",
  sanitize: "text-warning border-warning/40 bg-warning/10",
  block: "text-destructive border-destructive/40 bg-destructive/10",
};

export function LogsPanel({ refreshKey, sessionId }: { refreshKey: number; sessionId: string }) {
  const [logs, setLogs] = useState<FirewallLog[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    supabase
      .from("firewall_logs")
      .select("*")
      .eq("session_id", sessionId)
      .order("created_at", { ascending: false })
      .limit(50)
      .then(({ data }) => setLogs((data ?? []) as FirewallLog[]));
  }, [refreshKey, sessionId]);

  if (logs.length === 0) {
    return (
      <div className="text-sm text-muted-foreground text-center py-8 font-mono">
        No requests logged yet. Send a message to begin.
      </div>
    );
  }

  return (
    <ScrollArea className="h-[420px] scrollbar-thin">
      <div className="space-y-2 pr-2">
        {logs.map((log) => {
          const open = expanded === log.id;
          return (
            <div key={log.id} className="border border-border rounded-lg bg-card/50 text-xs font-mono">
              <button
                onClick={() => setExpanded(open ? null : log.id)}
                className="w-full flex items-center gap-2 px-3 py-2 hover:bg-secondary/40 transition-colors text-left"
              >
                {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                <Badge variant="outline" className={cn(decisionColor[log.decision] ?? "")}>
                  {log.decision}
                </Badge>
                <span className="truncate flex-1 text-foreground">{log.user_input}</span>
                <span className="text-muted-foreground shrink-0">
                  {(Number(log.risk_score) * 100).toFixed(0)}%
                </span>
              </button>
              {open && (
                <div className="px-3 pb-3 pt-1 space-y-2 border-t border-border">
                  <Field label="Timestamp" value={new Date(log.created_at).toLocaleString()} />
                  <Field label="Security" value={log.security_enabled ? "ON" : "OFF"} />
                  <Field label="Attack Type" value={log.attack_type ?? "—"} />
                  <Field label="Risk Score" value={`${(Number(log.risk_score) * 100).toFixed(1)}%`} />
                  <Field label="Latency" value={`${log.latency_ms ?? 0}ms`} />
                  <Field label="Output Filter" value={log.output_filter_action ?? "none"} />
                  <Field label="Normalized Input" value={log.normalized_input ?? "—"} multiline />
                  <Field label="Final Prompt → LLM" value={log.final_prompt ?? "—"} multiline />
                  <Field label="LLM Response" value={log.llm_response ?? "—"} multiline />
                  {Array.isArray(log.matched_patterns) && log.matched_patterns.length > 0 && (
                    <div>
                      <div className="text-muted-foreground mb-1">Matched Patterns</div>
                      <div className="flex flex-wrap gap-1">
                        {log.matched_patterns.map((p: any, i: number) => (
                          <Badge key={i} variant="outline" className="text-accent border-accent/40 bg-accent/5">
                            {p.label}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </ScrollArea>
  );
}

function Field({ label, value, multiline }: { label: string; value: string; multiline?: boolean }) {
  return (
    <div>
      <div className="text-muted-foreground">{label}</div>
      <div className={cn("text-foreground", multiline && "whitespace-pre-wrap break-words bg-secondary/40 rounded p-2 mt-0.5")}>
        {value}
      </div>
    </div>
  );
}
