import ReactMarkdown from "react-markdown";
import { Shield, ShieldAlert, ShieldCheck, ShieldX, User, WifiOff, AlertOctagon, Globe, FileWarning, Lock, Plug, Wifi, MapPin, Key, BarChart3 } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ChatMessage } from "@/lib/firewall-types";
import { Badge } from "@/components/ui/badge";

const decisionStyle: Record<string, { icon: React.ElementType; className: string; label: string }> = {
  allow:    { icon: ShieldCheck, className: "text-primary border-primary/40 bg-primary/10", label: "Allowed" },
  sanitize: { icon: ShieldAlert, className: "text-warning border-warning/40 bg-warning/10", label: "Sanitized" },
  block:    { icon: ShieldX,     className: "text-destructive border-destructive/40 bg-destructive/10", label: "Blocked" },
  restrict: { icon: ShieldAlert, className: "text-amber-400 border-amber-400/40 bg-amber-400/10", label: "Restricted" },
};

const networkBadge: Record<string, { label: string; className: string; icon: React.ElementType }> = {
  "TOR Anonymity Abuse":              { label: "TOR NODE",          className: "text-purple-300 border-purple-400/60 bg-purple-600/20",  icon: WifiOff },
  "Known Proxy Attack":               { label: "PROXY ATTACK",      className: "text-orange-300 border-orange-400/60 bg-orange-600/20",  icon: Wifi },
  "Prompt Injection (Bot Attack)":    { label: "BOT FLOOD",         className: "text-red-300 border-red-400/60 bg-red-600/20",           icon: AlertOctagon },
  "Multi-IP Distributed Attack":      { label: "DISTRIBUTED FLOOD", className: "text-rose-300 border-rose-400/60 bg-rose-600/20",        icon: Globe },
  "Malicious File Upload":            { label: "MALICIOUS FILE",    className: "text-red-200 border-red-500/60 bg-red-800/30",           icon: FileWarning },
  "VPN Policy Evasion":               { label: "VPN EVASION",       className: "text-amber-300 border-amber-400/60 bg-amber-600/20",     icon: Lock },
  "Plugin/API Exploit":               { label: "API EXPLOIT",       className: "text-teal-300 border-teal-400/60 bg-teal-600/20",        icon: Plug },
  "Geo-IP Country Block":             { label: "GEO BLOCK",         className: "text-rose-200 border-rose-500/60 bg-rose-900/30",        icon: MapPin },
  "Session Token Hijacking":          { label: "TOKEN HIJACK",      className: "text-indigo-300 border-indigo-400/60 bg-indigo-600/20",  icon: Key },
  "Prompt Flooding Attack":           { label: "TOKEN FLOOD",       className: "text-yellow-300 border-yellow-400/60 bg-yellow-600/20",  icon: BarChart3 },
};

export function ChatBubble({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === "user";
  const meta = msg.meta;
  const ds = meta ? (decisionStyle[meta.decision] ?? decisionStyle["block"]) : null;
  const Icon = ds?.icon ?? Shield;
  const netKey = meta?.attack_type ? networkBadge[meta.attack_type] : null;

  return (
    <div className={cn("flex gap-3 group", isUser ? "justify-end" : "justify-start")}>
      {!isUser && (
        <div className="w-8 h-8 rounded-lg bg-primary/15 border border-primary/30 flex items-center justify-center shrink-0">
          <Icon className={cn("w-4 h-4", ds ? ds.className.split(" ")[0] : "text-primary")} />
        </div>
      )}
      <div className={cn("max-w-[78%] space-y-2", isUser && "items-end flex flex-col")}>
        <div
          className={cn(
            "rounded-2xl px-4 py-2.5 text-sm leading-relaxed border",
            isUser
              ? "bg-secondary border-border rounded-br-sm"
              : meta?.decision === "block" && netKey
                ? "bg-card border-destructive/30 rounded-bl-sm"
                : meta?.decision === "restrict"
                  ? "bg-card border-amber-500/30 rounded-bl-sm"
                  : "bg-card border-border rounded-bl-sm",
          )}
        >
          {isUser ? (
            <p className="whitespace-pre-wrap break-words">{msg.content}</p>
          ) : (
            <div className="prose prose-sm prose-invert max-w-none prose-p:my-1.5 prose-pre:bg-secondary prose-pre:border prose-pre:border-border">
              <ReactMarkdown>{msg.content}</ReactMarkdown>
            </div>
          )}
        </div>
        {meta && ds && (
          <div className="flex flex-wrap gap-1.5 items-center text-xs">
            <Badge variant="outline" className={cn("gap-1 font-mono", ds.className)}>
              <Icon className="w-3 h-3" /> {ds.label}
            </Badge>
            <Badge variant="outline" className="font-mono text-muted-foreground">
              risk {(meta.risk_score * 100).toFixed(0)}%
            </Badge>
            {/* Network attack badge */}
            {netKey && (() => {
              const NetIcon = netKey.icon;
              return (
                <Badge variant="outline" className={cn("gap-1 font-mono font-bold", netKey.className)}>
                  <NetIcon className="w-3 h-3" /> {netKey.label}
                </Badge>
              );
            })()}
            {/* Regular attack type (only when no network badge) */}
            {meta.attack_type && !netKey && (
              <Badge variant="outline" className="font-mono text-accent border-accent/40 bg-accent/5">
                {meta.attack_type.replace(/_/g, " ")}
              </Badge>
            )}
            <span className="text-muted-foreground font-mono">{meta.latency_ms}ms</span>
          </div>
        )}
      </div>
      {isUser && (
        <div className="w-8 h-8 rounded-lg bg-secondary border border-border flex items-center justify-center shrink-0">
          <User className="w-4 h-4 text-muted-foreground" />
        </div>
      )}
    </div>
  );
}
