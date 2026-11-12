import { createFileRoute } from "@tanstack/react-router";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";
import { Ban, UserX, Server, ListChecks, Play } from "lucide-react";
import { useState } from "react";

export const Route = createFileRoute("/respond")({ component: Respond, head: () => ({ meta: [{ title: "Response Center · Sentinel" }] }) });

const HISTORY = [
  { ts: "09:13:48", who: "M. Hartmann", action: "Block IP 185.220.101.42 @ fw-core", status: "ok" },
  { ts: "09:13:51", who: "auto", action: "Suspend account svc_deploy", status: "ok" },
  { ts: "09:14:02", who: "auto", action: "Snapshot web-prod-01 → s3://forensics/", status: "ok" },
  { ts: "09:14:33", who: "L. Okafor", action: "Quarantine k8s-edge-3", status: "pending" },
  { ts: "09:10:11", who: "auto", action: "Block IP 91.219.236.18", status: "ok" },
];

const PLAYBOOKS = [
  { id: "PB-014", name: "Brute-force containment", steps: 5, runs: 142 },
  { id: "PB-021", name: "C2 beacon eradication", steps: 8, runs: 67 },
  { id: "PB-009", name: "Phishing payload triage", steps: 6, runs: 211 },
  { id: "PB-031", name: "Insider data exfil", steps: 11, runs: 18 },
];

function Respond() {
  const [armed, setArmed] = useState<string | null>(null);
  return (
    <Layout title="Response Center" subtitle="Responder agent · semi-auto · Wazuh active-response API">
      <div className="grid grid-cols-12 gap-4">
        <Panel title="Suggested actions · INC-2026-0142" className="col-span-7">
          <div className="grid grid-cols-2 gap-3">
            <ActionCard icon={<Ban className="h-4 w-4" />} title="Block IP at perimeter" target="185.220.101.42 → fw-core" cta="Execute" critical
              armed={armed === "block"} onArm={() => setArmed("block")} />
            <ActionCard icon={<UserX className="h-4 w-4" />} title="Disable user account" target="svc_deploy · LDAP" cta="Suspend"
              armed={armed === "disable"} onArm={() => setArmed("disable")} />
            <ActionCard icon={<Server className="h-4 w-4" />} title="Isolate host" target="web-prod-01 → quarantine VLAN" cta="Isolate"
              armed={armed === "isolate"} onArm={() => setArmed("isolate")} />
            <ActionCard icon={<ListChecks className="h-4 w-4" />} title="Add IoC to blacklist" target="3 IPs · 2 hashes" cta="Push to TIP"
              armed={armed === "ioc"} onArm={() => setArmed("ioc")} />
          </div>

          <div className="mt-5 rounded border border-[color:var(--high)]/40 bg-[color:var(--high)]/5 p-3">
            <div className="font-mono text-[10px] uppercase tracking-widest text-[color:var(--high)]">Approval required</div>
            <p className="mt-1 text-xs text-foreground/85">Actions marked <span className="text-[color:var(--critical)]">critical</span> need a 2nd analyst signature when affecting production assets.</p>
          </div>
        </Panel>

        <Panel title="Playbooks" className="col-span-5">
          <ul className="space-y-2">
            {PLAYBOOKS.map(p => (
              <li key={p.id} className="flex items-center justify-between rounded border border-border/60 bg-background/40 px-3 py-2.5">
                <div>
                  <div className="font-mono text-[10px] uppercase tracking-widest text-primary">{p.id}</div>
                  <div className="text-sm text-foreground/90">{p.name}</div>
                  <div className="font-mono text-[10px] text-muted-foreground">{p.steps} steps · {p.runs} runs · 96% success</div>
                </div>
                <button className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 font-mono text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20">
                  <Play className="h-3 w-3" /> Run
                </button>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Response history · audit log" className="col-span-12">
          <table className="w-full font-mono text-[11px]">
            <thead>
              <tr className="text-left text-muted-foreground">
                {["Timestamp", "Operator", "Action", "Status", ""].map(h => (
                  <th key={h} className="border-b border-border/40 px-3 py-2 text-[10px] uppercase tracking-widest">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {HISTORY.map((h, i) => (
                <tr key={i} className="border-b border-border/30">
                  <td className="px-3 py-2 text-muted-foreground tabular-nums">{h.ts}</td>
                  <td className="px-3 py-2">{h.who === "auto" ? <span className="text-primary">auto · responder</span> : h.who}</td>
                  <td className="px-3 py-2 text-foreground/85">{h.action}</td>
                  <td className="px-3 py-2">
                    <span className={`rounded border px-2 py-0.5 text-[10px] uppercase tracking-widest ${h.status === "ok" ? "border-[color:var(--success)]/40 bg-[color:var(--success)]/10 text-[color:var(--success)]" : "border-[color:var(--high)]/40 bg-[color:var(--high)]/10 text-[color:var(--high)]"}`}>
                      {h.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right text-muted-foreground hover:text-foreground"><button>view</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </Layout>
  );
}

function ActionCard({ icon, title, target, cta, critical, armed, onArm }: { icon: React.ReactNode; title: string; target: string; cta: string; critical?: boolean; armed?: boolean; onArm: () => void }) {
  return (
    <div className={`rounded-lg border p-4 transition-all ${armed ? "border-[color:var(--critical)]/60 bg-[color:var(--critical)]/5 glow-critical" : "border-border/60 bg-background/40 hover:border-primary/60"}`}>
      <div className="flex items-center gap-2 text-foreground/90">{icon}<span className="text-sm font-medium">{title}</span>{critical && <span className="ml-auto rounded border border-[color:var(--critical)]/40 bg-[color:var(--critical)]/10 px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest text-[color:var(--critical)]">critical</span>}</div>
      <div className="mt-1 font-mono text-[11px] text-muted-foreground">{target}</div>
      <button onClick={onArm} className={`mt-3 w-full rounded py-1.5 font-mono text-[11px] uppercase tracking-widest transition-colors ${armed ? "bg-[color:var(--critical)] text-[color:var(--critical-foreground,white)]" : "bg-primary/15 text-primary hover:bg-primary/25"}`}>
        {armed ? "Confirm execute" : cta}
      </button>
    </div>
  );
}
