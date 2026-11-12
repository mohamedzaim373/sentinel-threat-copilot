import type { Severity } from "@/lib/soc-data";
import { cn } from "@/lib/utils";

const STYLES: Record<Severity, string> = {
  critical: "bg-[color:var(--critical)]/15 text-[color:var(--critical)] border-[color:var(--critical)]/40",
  high: "bg-[color:var(--high)]/15 text-[color:var(--high)] border-[color:var(--high)]/40",
  medium: "bg-[color:var(--medium)]/15 text-[color:var(--medium)] border-[color:var(--medium)]/40",
  low: "bg-[color:var(--low)]/15 text-[color:var(--low)] border-[color:var(--low)]/40",
  info: "bg-muted text-muted-foreground border-border",
};

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest", STYLES[severity], className)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current pulse-dot" />
      {severity}
    </span>
  );
}
