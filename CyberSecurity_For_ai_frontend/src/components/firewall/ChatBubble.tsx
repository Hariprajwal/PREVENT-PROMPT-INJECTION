import ReactMarkdown from "react-markdown";
import { Shield, ShieldAlert, ShieldCheck, ShieldX, User } from "lucide-react";
import { cn } from "@/lib/utils";
import type { ChatMessage } from "@/lib/firewall-types";
import { Badge } from "@/components/ui/badge";

const decisionStyle: Record<string, { icon: React.ElementType; className: string; label: string }> = {
  allow:    { icon: ShieldCheck, className: "text-primary border-primary/40 bg-primary/10", label: "Allowed" },
  sanitize: { icon: ShieldAlert, className: "text-warning border-warning/40 bg-warning/10", label: "Sanitized" },
  block:    { icon: ShieldX,     className: "text-destructive border-destructive/40 bg-destructive/10", label: "Blocked" },
};

export function ChatBubble({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === "user";
  const meta = msg.meta;
  const ds = meta ? decisionStyle[meta.decision] : null;
  const Icon = ds?.icon ?? Shield;

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
            {meta.attack_type && (
              <Badge variant="outline" className="font-mono text-accent border-accent/40 bg-accent/5">
                {meta.attack_type.replace("_", " ")}
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
