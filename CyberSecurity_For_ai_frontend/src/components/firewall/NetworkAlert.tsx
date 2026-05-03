import { useEffect, useState } from "react";
import { Shield, Wifi, WifiOff, AlertOctagon, Globe, FileWarning, Lock, Plug, MapPin, Key, BarChart3 } from "lucide-react";
import { cn } from "@/lib/utils";

export type NetworkAlertType = "tor" | "bot" | "proxy" | "distributed" | "file" | "vpn" | "api" | "geo" | "hijack" | "flood" | null;

interface NetworkAlertProps {
  type: NetworkAlertType;
  ip?: string;
  extra?: string;
  onDismiss?: () => void;
}

const ALERT_CONFIG: Record<NonNullable<NetworkAlertType>, {
  icon: React.ElementType;
  label: string;
  detail: string;
  color: string;
  badgeColor: string;
  dotColor: string;
  glow: string;
  tag: string;
}> = {
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
  proxy: {
    icon: Wifi,
    label: "Known Proxy Attack",
    detail: "Request routed through a known malicious proxy server",
    color: "from-orange-900/80 to-orange-800/60 border-orange-500/60",
    badgeColor: "bg-orange-600/30 border-orange-400/60 text-orange-300",
    dotColor: "bg-orange-400",
    glow: "shadow-[0_0_20px_rgba(234,88,12,0.3)]",
    tag: "PROXY ATTACK",
  },
  distributed: {
    icon: Globe,
    label: "Multi-IP Distributed Attack",
    detail: "Coordinated payload from multiple IPs — pattern clustering triggered",
    color: "from-rose-900/80 to-orange-900/60 border-rose-500/60",
    badgeColor: "bg-rose-600/30 border-rose-400/60 text-rose-300",
    dotColor: "bg-rose-400",
    glow: "shadow-[0_0_20px_rgba(244,63,94,0.3)]",
    tag: "DISTRIBUTED FLOOD",
  },
  file: {
    icon: FileWarning,
    label: "Malicious File Upload",
    detail: "Injected payload found during deep content scan — sandbox analysis triggered",
    color: "from-red-950/90 to-red-900/70 border-red-600/70",
    badgeColor: "bg-red-800/40 border-red-500/60 text-red-200",
    dotColor: "bg-red-300",
    glow: "shadow-[0_0_24px_rgba(220,38,38,0.5)]",
    tag: "MALICIOUS FILE",
  },
  vpn: {
    icon: Lock,
    label: "Insider VPN Policy Evasion",
    detail: "VPN detected — geo-location anomaly, Zero Trust validation failed",
    color: "from-amber-900/80 to-yellow-900/60 border-amber-500/60",
    badgeColor: "bg-amber-600/30 border-amber-400/60 text-amber-300",
    dotColor: "bg-amber-400",
    glow: "shadow-[0_0_20px_rgba(217,119,6,0.3)]",
    tag: "VPN EVASION",
  },
  api: {
    icon: Plug,
    label: "Plugin/API Exploit",
    detail: "Suspicious outbound API call intercepted — domain not on allowlist",
    color: "from-teal-900/80 to-cyan-900/60 border-teal-500/60",
    badgeColor: "bg-teal-600/30 border-teal-400/60 text-teal-300",
    dotColor: "bg-teal-400",
    glow: "shadow-[0_0_20px_rgba(20,184,166,0.3)]",
    tag: "API EXPLOIT",
  },
  geo: {
    icon: MapPin,
    label: "Geo-IP Country Block",
    detail: "Request origin from restricted/sanctioned region — country blacklist enforced",
    color: "from-rose-950/90 to-red-900/70 border-rose-600/60",
    badgeColor: "bg-rose-700/30 border-rose-400/60 text-rose-200",
    dotColor: "bg-rose-300",
    glow: "shadow-[0_0_24px_rgba(225,29,72,0.45)]",
    tag: "GEO BLOCK",
  },
  hijack: {
    icon: Key,
    label: "Session Token Hijacking",
    detail: "Stolen Bearer token detected — geo mismatch + fingerprint anomaly",
    color: "from-indigo-900/80 to-violet-900/60 border-indigo-500/60",
    badgeColor: "bg-indigo-600/30 border-indigo-400/60 text-indigo-300",
    dotColor: "bg-indigo-400",
    glow: "shadow-[0_0_20px_rgba(99,102,241,0.35)]",
    tag: "TOKEN HIJACK",
  },
  flood: {
    icon: BarChart3,
    label: "Prompt Flooding Attack",
    detail: "Context window exhaustion attempt — token limit exceeded",
    color: "from-yellow-900/80 to-amber-900/60 border-yellow-500/60",
    badgeColor: "bg-yellow-600/30 border-yellow-400/60 text-yellow-200",
    dotColor: "bg-yellow-400",
    glow: "shadow-[0_0_20px_rgba(234,179,8,0.35)]",
    tag: "TOKEN FLOOD",
  },
};

export function NetworkAlert({ type, ip, extra, onDismiss }: NetworkAlertProps) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (type) {
      setVisible(true);
      const t = setTimeout(() => {
        setVisible(false);
        setTimeout(() => onDismiss?.(), 400);
      }, 9000);
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
        visible ? "max-h-28 opacity-100 mb-2" : "max-h-0 opacity-0"
      )}
    >
      <div
        className={cn(
          "flex items-start gap-3 px-4 py-3 rounded-lg border bg-gradient-to-r backdrop-blur-sm text-sm",
          cfg.color,
          cfg.glow
        )}
      >
        {/* Pulsing dot */}
        <span className="relative flex h-3 w-3 shrink-0 mt-1">
          <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-75", cfg.dotColor)} />
          <span className={cn("relative inline-flex rounded-full h-3 w-3", cfg.dotColor)} />
        </span>

        <Icon className="w-4 h-4 text-white shrink-0 mt-0.5" />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-white">{cfg.label}</span>
            {ip && (
              <span className="font-mono text-xs text-white/70">from {ip}</span>
            )}
          </div>
          <p className="text-xs text-white/60 mt-0.5">{cfg.detail}</p>
          {extra && (
            <p className="text-xs text-white/50 font-mono mt-0.5">↳ {extra}</p>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <span className={cn("px-2 py-0.5 rounded border text-xs font-bold font-mono tracking-widest", cfg.badgeColor)}>
            ⛔ {cfg.tag}
          </span>
          <Shield className="w-4 h-4 text-white/40" />
        </div>
      </div>
    </div>
  );
}
