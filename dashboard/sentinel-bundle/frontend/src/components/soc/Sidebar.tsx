import { Link, useLocation } from "@tanstack/react-router";
import { Activity, ShieldAlert, Search, Brain, Zap, Briefcase, BarChart3, Lock, Plug } from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "SOC Overview", icon: Activity },
  { to: "/triage", label: "Alert Triage", icon: ShieldAlert },
  { to: "/investigate", label: "Investigation", icon: Search },
  { to: "/reasoning", label: "AI Reasoning", icon: Brain },
  { to: "/respond", label: "Response Center", icon: Zap },
  { to: "/incidents", label: "Incidents", icon: Briefcase },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/access", label: "Access Control", icon: Lock },
  { to: "/integrations", label: "Integrations", icon: Plug },
] as const;

export function Sidebar() {
  const loc = useLocation();
  return (
    <aside className="flex h-screen w-60 flex-col border-r border-border/60 bg-card/40 backdrop-blur">
      <div className="flex items-center gap-2 border-b border-border/60 px-4 py-4">
        <div className="relative flex h-8 w-8 items-center justify-center rounded bg-primary/15 text-primary glow-primary">
          <ShieldAlert className="h-4 w-4" />
        </div>
        <div>
          <div className="font-display text-sm font-semibold tracking-tight text-glow text-primary">SENTINEL</div>
          <div className="font-mono text-[9px] uppercase tracking-[0.25em] text-muted-foreground">soar · v2.6</div>
        </div>
      </div>
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 py-3">
        {NAV.map(({ to, label, icon: Icon }) => {
          const active = loc.pathname === to;
          return (
            <Link key={to} to={to} className={cn(
              "group flex items-center gap-3 rounded px-3 py-2 font-mono text-xs uppercase tracking-wider transition-colors",
              active
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground hover:bg-secondary/60 hover:text-foreground",
            )}>
              <Icon className={cn("h-3.5 w-3.5", active && "text-primary")} />
              <span>{label}</span>
              {active && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary pulse-dot" />}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border/60 p-3">
        <div className="rounded border border-border/60 bg-background/40 p-2.5">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Wazuh</span>
            <span className="flex items-center gap-1.5 text-[10px] text-[color:var(--success)]">
              <span className="h-1.5 w-1.5 rounded-full bg-[color:var(--success)] pulse-dot" />
              online
            </span>
          </div>
          <div className="mt-1.5 flex items-center justify-between">
            <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">LLM</span>
            <span className="flex items-center gap-1.5 text-[10px] text-[color:var(--success)]">
              <span className="h-1.5 w-1.5 rounded-full bg-[color:var(--success)] pulse-dot" />
              local · 7B
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
}
