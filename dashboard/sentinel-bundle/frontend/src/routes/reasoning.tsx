import { createFileRoute } from "@tanstack/react-router";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { Brain, Sparkles } from "lucide-react";

export const Route = createFileRoute("/reasoning")({ component: Reasoning, head: () => ({ meta: [{ title: "AI Reasoning · Sentinel" }] }) });

function Reasoning() {
  return (
    <Layout title="AI Reasoning Panel" subtitle="Local LLM · llama-3-sentinel-7b · structured output">
      <div className="grid grid-cols-12 gap-4">
        <Panel title="Incident summary · INC-2026-0142" className="col-span-8">
          <div className="flex items-center gap-3">
            <SeverityBadge severity="critical" />
            <span className="font-mono text-[11px] text-muted-foreground">confidence</span>
            <div className="relative h-1.5 w-40 rounded-full bg-secondary">
              <div className="absolute left-0 top-0 h-full rounded-full bg-gradient-to-r from-primary to-[color:var(--success)]" style={{ width: "92%" }} />
            </div>
            <span className="font-mono text-xs text-[color:var(--success)]">92%</span>
          </div>

          <h3 className="mt-4 font-display text-xl font-semibold">Coordinated SSH brute-force escalating to lateral movement</h3>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-foreground/80">
            An external IP <code className="rounded bg-secondary/60 px-1 font-mono text-xs">185.220.101.42</code> initiated <strong>1,247 failed SSH attempts</strong> across 6 edge nodes within 38 seconds, then succeeded on <code className="rounded bg-secondary/60 px-1 font-mono text-xs">svc_deploy</code>. The session immediately spawned a Base64-encoded PowerShell payload that established outbound TLS to a known C2 endpoint. Behavior matches threat actor cluster <strong>UNC-2452 ↔ TA577</strong>.
          </p>

          <div className="mt-5 grid grid-cols-2 gap-3 font-mono text-[11px]">
            <KV k="Attack stage" v="Lateral movement (post-exploit)" />
            <KV k="Classification" v="Credential Access → Execution → C2" />
            <KV k="Primary technique" v="T1110.001 · Password Guessing" />
            <KV k="Secondary technique" v="T1059.001 · PowerShell" />
            <KV k="Risk score" v={<span className="text-[color:var(--critical)]">94 / 100</span>} />
            <KV k="Recommended SLA" v="Immediate · 5 min" />
          </div>

          <div className="mt-5 rounded-lg border border-primary/30 bg-primary/5 p-4">
            <div className="mb-2 flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-primary">
              <Sparkles className="h-3 w-3" /> Recommended response chain
            </div>
            <ol className="list-inside list-decimal space-y-1 font-mono text-[11px] text-foreground/85">
              <li>Block 185.220.101.42 at perimeter firewall (Wazuh active-response)</li>
              <li>Suspend account <code className="text-primary">svc_deploy</code> and force credential rotation</li>
              <li>Isolate <code className="text-primary">web-prod-01</code> from production VLAN</li>
              <li>Snapshot host volume for forensic acquisition</li>
              <li>Open ticket with IR team · attach this reasoning trace</li>
            </ol>
          </div>
        </Panel>

        <Panel title="Reasoning trace · live" className="col-span-4">
          <div className="space-y-3 font-mono text-[10.5px] leading-relaxed">
            <Trace step="01" title="Ingest" body="Received 1,247 alerts, ruleset 5710-5712. Grouped by (src_ip, asset)." />
            <Trace step="02" title="Hypothesis" body="Pattern matches credential-stuffing playbook PB-014. Rate exceeds threshold (T=200/min)." />
            <Trace step="03" title="Enrich" body="AbuseIPDB: 92/100. ASN AS43350 historically tied to Tor exit nodes." />
            <Trace step="04" title="Correlate" body="Within 15s window: successful auth + powershell.exe -EncodedCommand spawn." />
            <Trace step="05" title="Conclude" body="P(true positive) = 0.92. Escalate to INC, propose response chain." active />
          </div>
          <div className="mt-3 flex items-center gap-2 rounded border border-primary/30 bg-primary/5 px-2.5 py-1.5 font-mono text-[10px] text-primary">
            <Brain className="h-3 w-3" /> 7B local · 412 tokens · 1.8s
          </div>
        </Panel>
      </div>
    </Layout>
  );
}

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="rounded border border-border/60 bg-background/40 px-3 py-2">
      <div className="text-[9px] uppercase tracking-widest text-muted-foreground">{k}</div>
      <div className="mt-0.5 text-foreground/90">{v}</div>
    </div>
  );
}
function Trace({ step, title, body, active }: { step: string; title: string; body: string; active?: boolean }) {
  return (
    <div className={`rounded border px-2.5 py-2 ${active ? "border-primary/50 bg-primary/5" : "border-border/40 bg-background/30"}`}>
      <div className="flex items-center justify-between">
        <span className="text-muted-foreground">[{step}] <span className="text-foreground/90">{title}</span></span>
        {active && <span className="h-1.5 w-1.5 rounded-full bg-primary pulse-dot" />}
      </div>
      <p className="mt-1 text-foreground/70">{body}</p>
    </div>
  );
}
