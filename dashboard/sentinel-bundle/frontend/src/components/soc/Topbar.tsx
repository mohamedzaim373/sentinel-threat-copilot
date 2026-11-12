import { Search, Bell, User } from "lucide-react";
import { useEffect, useState } from "react";

export function Topbar({ title, subtitle }: { title: string; subtitle?: string }) {
  const [time, setTime] = useState("--:--:--");
  useEffect(() => {
    const tick = () => setTime(new Date().toUTCString().slice(17, 25));
    tick();
    const i = setInterval(tick, 1000);
    return () => clearInterval(i);
  }, []);
  return (
    <header className="flex items-center justify-between border-b border-border/60 bg-background/60 px-6 py-3 backdrop-blur">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="font-display text-xl font-semibold tracking-tight">{title}</h1>
          <span className="rounded border border-[color:var(--success)]/40 bg-[color:var(--success)]/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-[color:var(--success)]">
            ● live
          </span>
        </div>
        {subtitle && <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 rounded border border-border/60 bg-card/60 px-3 py-1.5">
          <Search className="h-3.5 w-3.5 text-muted-foreground" />
          <input
            placeholder="Search alerts, IPs, rules…"
            className="w-72 bg-transparent font-mono text-xs outline-none placeholder:text-muted-foreground"
          />
          <kbd className="rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground">⌘K</kbd>
        </div>
        <div suppressHydrationWarning className="font-mono text-[11px] text-muted-foreground tabular-nums">
          {time} UTC
        </div>
        <button className="rounded border border-border/60 bg-card/60 p-2 text-muted-foreground hover:text-foreground">
          <Bell className="h-4 w-4" />
        </button>
        <div className="flex items-center gap-2 rounded border border-border/60 bg-card/60 px-2.5 py-1.5">
          <div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/15 text-primary">
            <User className="h-3 w-3" />
          </div>
          <div className="text-xs">
            <div className="font-medium">M. Hartmann</div>
            <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">soc · manager</div>
          </div>
        </div>
      </div>
    </header>
  );
}
