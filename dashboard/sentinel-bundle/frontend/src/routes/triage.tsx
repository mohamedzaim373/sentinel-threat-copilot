import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { generateAlerts, type Severity } from "@/lib/soc-data";
import { ArrowUpRight, Layers } from "lucide-react";

export const Route = createFileRoute("/triage")({ component: Triage, head: () => ({ meta: [{ title: "Alert Triage · Sentinel" }] }) });

function Triage() {
  const all = useMemo(() => generateAlerts(120), []);
  const [sev, setSev] = useState<Severity | "all">("all");
  const [asset, setAsset] = useState("all");
  const [grouped, setGrouped] = useState(true);

  const assets = Array.from(new Set(all.map(a => a.asset)));
  const filtered = all.filter(a => (sev === "all" || a.severity === sev) && (asset === "all" || a.asset === asset));
  const display = grouped
    ? Object.values(filtered.reduce<Record<string, typeof all[number] & { dedup: number }>>((acc, a) => {
        const k = `${a.sourceIp}-${a.ruleId}`;
        if (!acc[k]) acc[k] = { ...a, dedup: 1 };
        else acc[k].dedup += 1;
        return acc;
      }, {}))
    : filtered;

  return (
    <Layout title="Alert Triage" subtitle="Sentinel scoring engine · ingestion + dedup + correlation">
      <Panel className="mb-4">
        <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
          <Filter label="Severity" value={sev} onChange={v => setSev(v as Severity | "all")}
            options={["all", "critical", "high", "medium", "low", "info"]} />
          <Filter label="Asset" value={asset} onChange={setAsset} options={["all", ...assets]} />
          <Filter label="Window" value="1h" onChange={() => {}} options={["15m", "1h", "24h", "7d"]} />
          <Filter label="Attack" value="all" onChange={() => {}} options={["all", "Brute Force", "C2", "Phishing", "RCE"]} />
          <button onClick={() => setGrouped(g => !g)}
            className={`ml-auto inline-flex items-center gap-1.5 rounded border px-2.5 py-1 uppercase tracking-widest ${grouped ? "border-primary/60 bg-primary/10 text-primary" : "border-border/60 text-muted-foreground"}`}>
            <Layers className="h-3 w-3" /> Dedup view
          </button>
        </div>
      </Panel>

      <Panel title={`Alert queue · ${display.length}`}>
        <div className="overflow-x-auto">
          <table className="w-full font-mono text-[11px]">
            <thead>
              <tr className="text-left text-muted-foreground">
                {["TS (UTC)", "Severity", "Score", "Source IP", "Asset", "Rule", "MITRE", "Description", grouped ? "Count" : "", ""].map(h => (
                  <th key={h} className="border-b border-border/40 px-3 py-2 text-[10px] uppercase tracking-widest">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {display.slice(0, 40).map((a: any) => (
                <tr key={a.id} className="border-b border-border/30 hover:bg-secondary/30">
                  <td className="px-3 py-2 text-muted-foreground tabular-nums">{new Date(a.ts).toUTCString().slice(17, 25)}</td>
                  <td className="px-3 py-2"><SeverityBadge severity={a.severity} /></td>
                  <td className="px-3 py-2 tabular-nums text-[color:var(--high)]">{a.score}</td>
                  <td className="px-3 py-2 text-foreground/80">{a.sourceIp}</td>
                  <td className="px-3 py-2 text-muted-foreground">{a.asset}</td>
                  <td className="px-3 py-2 text-foreground/60">{a.ruleId}</td>
                  <td className="px-3 py-2 text-primary">{a.mitre}</td>
                  <td className="px-3 py-2 text-foreground/70">{a.description}</td>
                  {grouped && <td className="px-3 py-2 text-muted-foreground tabular-nums">×{a.dedup}</td>}
                  <td className="px-3 py-2 text-right">
                    <button className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20">
                      Promote <ArrowUpRight className="h-3 w-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </Layout>
  );
}

function Filter({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <label className="flex items-center gap-2">
      <span className="text-[10px] uppercase tracking-widest text-muted-foreground">{label}</span>
      <select value={value} onChange={e => onChange(e.target.value)}
        className="rounded border border-border/60 bg-background/60 px-2 py-1 text-foreground outline-none focus:border-primary/60">
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </label>
  );
}
