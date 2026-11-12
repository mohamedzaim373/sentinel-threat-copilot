import { createFileRoute } from "@tanstack/react-router";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";
import { Activity, Brain, Database, Shield, Zap, Globe } from "lucide-react";

export const Route = createFileRoute("/integrations")({ component: Integrations, head: () => ({ meta: [{ title: "Integrations · Sentinel" }] }) });

const INTS = [
  { icon: Shield, name: "Wazuh Manager", desc: "Alert ingestion · active response", status: "connected", meta: "wazuh.corp.io · v4.9.1 · 318 agents" },
  { icon: Activity, name: "Elasticsearch", desc: "Log storage · queries", status: "connected", meta: "9 nodes · 4.2 TB · green" },
  { icon: Brain, name: "Local LLM", desc: "Sentinel-7B reasoning model", status: "connected", meta: "vLLM · GPU 0/1 · 86% util" },
  { icon: Globe, name: "AbuseIPDB", desc: "IP threat intelligence", status: "connected", meta: "Plan: enterprise · 4.1k/5k req" },
  { icon: Database, name: "Sentinel DB", desc: "Postgres · history & state", status: "connected", meta: "primary + 2 replicas · 421 GB" },
  { icon: Zap, name: "Slack #soc-alerts", desc: "Notification channel", status: "connected", meta: "webhook · 2.1k msgs/24h" },
  { icon: Globe, name: "MISP", desc: "Threat sharing platform", status: "degraded", meta: "last sync 41m ago · retrying" },
  { icon: Shield, name: "CrowdStrike Falcon", desc: "EDR telemetry", status: "disconnected", meta: "OAuth required" },
];

function Integrations() {
  return (
    <Layout title="Integration Layer" subtitle="External systems wired into the Sentinel pipeline">
      <Panel title="Pipeline" className="mb-4">
        <div className="flex items-center justify-between gap-3 overflow-x-auto py-2 font-mono text-[11px]">
          {["Wazuh", "Sentinel · score+correlate", "Investigator · LLM+enrich", "Responder · actions", "Dashboard UI"].map((s, i, arr) => (
            <div key={s} className="flex items-center gap-3">
              <div className="rounded border border-primary/40 bg-primary/10 px-3 py-1.5 text-primary">{s}</div>
              {i < arr.length - 1 && <span className="text-primary/60">→</span>}
            </div>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-3 gap-4">
        {INTS.map(({ icon: Icon, name, desc, status, meta }) => (
          <div key={name} className="rounded-lg border border-border/60 bg-card/50 p-4">
            <div className="flex items-start justify-between">
              <div className="flex h-10 w-10 items-center justify-center rounded bg-primary/15 text-primary"><Icon className="h-5 w-5" /></div>
              <span className={`rounded border px-2 py-0.5 font-mono text-[9px] uppercase tracking-widest ${
                status === "connected" ? "border-[color:var(--success)]/40 bg-[color:var(--success)]/10 text-[color:var(--success)]" :
                status === "degraded" ? "border-[color:var(--high)]/40 bg-[color:var(--high)]/10 text-[color:var(--high)]" :
                "border-border/60 bg-secondary/40 text-muted-foreground"
              }`}>{status}</span>
            </div>
            <h3 className="mt-3 font-display text-base font-semibold">{name}</h3>
            <p className="mt-0.5 text-xs text-muted-foreground">{desc}</p>
            <div className="mt-3 border-t border-border/40 pt-2 font-mono text-[10px] text-muted-foreground">{meta}</div>
          </div>
        ))}
      </div>
    </Layout>
  );
}
