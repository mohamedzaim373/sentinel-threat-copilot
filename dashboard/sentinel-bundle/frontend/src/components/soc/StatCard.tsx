import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export function StatCard({
  label, value, delta, icon, accent = "primary", children,
}: {
  label: string; value: ReactNode; delta?: string; icon?: ReactNode;
  accent?: "primary" | "critical" | "high" | "success"; children?: ReactNode;
}) {
  const ring = {
    primary: "before:bg-[color:var(--primary)]",
    critical: "before:bg-[color:var(--critical)]",
    high: "before:bg-[color:var(--high)]",
    success: "before:bg-[color:var(--success)]",
  }[accent];
  return (
    <div className={cn(
      "relative overflow-hidden rounded-lg border bg-card/60 p-4 backdrop-blur",
      "before:absolute before:left-0 before:top-0 before:h-full before:w-[3px] before:content-['']",
      ring,
    )}>
      <div className="flex items-start justify-between gap-3">
        <div className="text-[10px] font-mono uppercase tracking-[0.2em] text-muted-foreground">{label}</div>
        {icon && <div className="text-muted-foreground">{icon}</div>}
      </div>
      <div className="mt-2 font-display text-3xl font-semibold tabular-nums">{value}</div>
      {delta && <div className="mt-1 text-xs text-muted-foreground">{delta}</div>}
      {children}
    </div>
  );
}
