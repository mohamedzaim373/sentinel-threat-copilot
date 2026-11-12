import { createFileRoute } from "@tanstack/react-router";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { INCIDENTS } from "@/lib/soc-data";

export const Route = createFileRoute("/incidents")({ component: Incidents, head: () => ({ meta: [{ title: "Incidents · Sentinel" }] }) });

const STATUS_STYLE = {
  Open: "border-[color:var(--critical)]/40 bg-[color:var(--critical)]/10 text-[color:var(--critical)]",
  "In Progress": "border-[color:var(--high)]/40 bg-[color:var(--high)]/10 text-[color:var(--high)]",
  Resolved: "border-[color:var(--success)]/40 bg-[color:var(--success)]/10 text-[color:var(--success)]",
} as const;

function Incidents() {
  return (
    <Layout title="Incident Management" subtitle="SOC workflow · ticketing · ownership">
      <div className="grid grid-cols-3 gap-4">
        {(["Open", "In Progress", "Resolved"] as const).map(col => {
          const items = INCIDENTS.filter(i => i.status === col);
          return (
            <Panel key={col} title={`${col} · ${items.length}`}>
              <ul className="space-y-3">
                {items.map(inc => (
                  <li key={inc.id} className="rounded-lg border border-border/60 bg-background/40 p-3 hover:border-primary/60">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] uppercase tracking-widest text-primary">{inc.id}</span>
                      <SeverityBadge severity={inc.severity} />
                    </div>
                    <h3 className="mt-1.5 text-sm font-medium leading-snug text-foreground/90">{inc.title}</h3>
                    <div className="mt-2 flex items-center justify-between font-mono text-[10px] text-muted-foreground">
                      <span>{inc.alertCount} alerts</span>
                      <span>{new Date(inc.created).toUTCString().slice(5, 22)}</span>
                    </div>
                    <div className="mt-2 flex items-center justify-between border-t border-border/40 pt-2">
                      <span className="font-mono text-[10px] text-muted-foreground">assignee</span>
                      <span className="text-xs text-foreground/85">{inc.assignee}</span>
                    </div>
                  </li>
                ))}
                {items.length === 0 && <li className="py-6 text-center font-mono text-[11px] text-muted-foreground">— empty —</li>}
              </ul>
            </Panel>
          );
        })}
      </div>

      <Panel title="Activity timeline · INC-2026-0142" className="mt-4">
        <ol className="relative ml-3 space-y-3 border-l border-border/60 pl-5">
          {[
            ["09:12:04", "Sentinel ingested 12 brute-force alerts"],
            ["09:12:48", "Auto-promoted to incident · severity CRITICAL"],
            ["09:13:02", "M. Hartmann assigned · acknowledged in 14s"],
            ["09:13:48", "Responder executed PB-014 · IP blocked"],
            ["09:18:21", "Note added by L. Okafor: \"Forensic image acquired\""],
          ].map(([t, e], i) => (
            <li key={i} className="relative">
              <span className="absolute -left-[26px] top-1 h-2.5 w-2.5 rounded-full border-2 border-background bg-primary" />
              <div className="font-mono text-[11px]"><span className="text-muted-foreground">{t}</span> &nbsp; <span className="text-foreground/85">{e}</span></div>
            </li>
          ))}
        </ol>
      </Panel>
    </Layout>
  );
}
