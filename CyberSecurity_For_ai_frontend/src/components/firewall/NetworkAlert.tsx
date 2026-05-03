import { useEffect, useState } from "react";
import { Shield, Wifi, WifiOff, AlertOctagon } from "lucide-react";
import { cn } from "@/lib/utils";

export type NetworkAlertType = "tor" | "bot" | null;

interface NetworkAlertProps {
  type: NetworkAlertType;
  ip?: string;
  onDismiss?: () => void;
}

const ALERT_CONFIG = {
  tor: {
    icon: WifiOff,
    label: "TOR Anonymity Abuse",
    detail: "Anonymous attacker detected via TOR exit node",
    color: "from-purple-900/80 to-purple-800/60 border-purple-500/60",
    badgeColor: "bg-purple-600/30 border-purple-400/60 text-purple-300",
    dotColor: "bg-purple-400",
    glow: "shadow-[0_0_20px_rgba(147,51,234,0.3)]",
    tag: "TOR NODE",
  },
  bot: {
    icon: AlertOctagon,
    label: "Bot-Based Jailbreak Attack",
    detail: "Rate limit exceeded — automated request flood detected",
    color: "from-red-900/80 to-red-800/60 border-red-500/60",
    badgeColor: "bg-red-600/30 border-red-400/60 text-red-300",
    dotColor: "bg-red-400",
    glow: "shadow-[0_0_20px_rgba(239,68,68,0.3)]",
    tag: "BOT FLOOD",
  },
};

export function NetworkAlert({ type, ip, onDismiss }: NetworkAlertProps) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (type) {
      setVisible(true);
      const t = setTimeout(() => {
        setVisible(false);
        setTimeout(() => onDismiss?.(), 400);
      }, 8000);
      return () => clearTimeout(t);
    }
  }, [type, ip]);

  if (!type) return null;

  const cfg = ALERT_CONFIG[type];
  const Icon = cfg.icon;

  return (
    <div
      className={cn(
        "transition-all duration-500 overflow-hidden",
        visible ? "max-h-24 opacity-100 mb-2" : "max-h-0 opacity-0"
      )}
    >
      <div
        className={cn(
          "flex items-center gap-3 px-4 py-3 rounded-lg border bg-gradient-to-r backdrop-blur-sm text-sm",
          cfg.color,
          cfg.glow
        )}
      >
        {/* Pulsing dot */}
        <span className="relative flex h-3 w-3 shrink-0">
          <span
            className={cn(
              "animate-ping absolute inline-flex h-full w-full rounded-full opacity-75",
              cfg.dotColor
            )}
          />
          <span className={cn("relative inline-flex rounded-full h-3 w-3", cfg.dotColor)} />
        </span>

        <Icon className="w-4 h-4 text-white shrink-0" />

        <div className="flex-1 min-w-0">
          <span className="font-semibold text-white">{cfg.label}</span>
          {ip && (
            <span className="ml-2 font-mono text-xs text-white/70">
              from {ip}
            </span>
          )}
          <p className="text-xs text-white/60 mt-0.5">{cfg.detail}</p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span
            className={cn(
              "px-2 py-0.5 rounded border text-xs font-bold font-mono tracking-widest",
              cfg.badgeColor
            )}
          >
            ⛔ {cfg.tag}
          </span>
          <span className="text-xs text-white/50 font-mono">
            BLOCKED
          </span>
        </div>

        <Shield className="w-4 h-4 text-white/40 shrink-0" />
      </div>
    </div>
  );
}
