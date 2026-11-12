import { createFileRoute } from "@tanstack/react-router";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { Globe, MapPin, Network, Clock } from "lucide-react";

export const Route = createFileRoute("/investigate")({ component: Investigate, head: () => ({ meta: [{ title: "Investigation · Sentinel" }] }) });

const TIMELINE = [
  { t: "09:12:04", e: "First failed SSH login from 185.220.101.42", k: "auth" },
  { t: "09:12:11", e: "12 additional failed logins (rate: 1.7/s)", k: "auth" },
  { t: "09:12:48", e: "Successful login as `svc_deploy`", k: "alert" },
  { t: "09:13:02", e: "PowerShell encoded command spawned", k: "exec" },
  { t: "09:13:19", e: "Outbound TCP/443 → 91.219.236.18 (known C2)", k: "c2" },
  { t: "09:13:42", e: "Sentinel auto-promoted alert to INC-2026-0142", k: "system" },
];

const RAW = `** Alert 1746440984.213409: - syslog,sshd,authentication_failures,
2026 May 05 09:12:04 web-prod-01->/var/log/auth.log
Rule: 5710 (level 5) -> 'sshd: Attempt to login using a non-existent user'
Src IP: 185.220.101.42
May  5 09:12:04 web-prod-01 sshd[28391]: Invalid user admin from 185.220.101.42 port 51234
May  5 09:12:04 web-prod-01 sshd[28391]: Failed password for invalid user admin from 185.220.101.42 port 51234 ssh2
May  5 09:12:04 web-prod-01 sshd[28391]: Connection closed by invalid user admin 185.220.101.42 port 51234 [preauth]`;

function Investigate() {
  return (
    <Layout title="Investigation Workspace" subtitle="ALT-44218 · web-prod-01 · 185.220.101.42 → svc_deploy">
      <div className="grid grid-cols-12 gap-4">
        <Panel title="Alert context" className="col-span-8">
          <div className="grid grid-cols-4 gap-4">
            <Field label="Alert ID" value="ALT-44218" />
            <Field label="Severity"><SeverityBadge severity="critical" /></Field>
            <Field label="Score" value={<span className="text-[color:var(--critical)] font-display text-xl">94</span>} />
            <Field label="Status" value="Investigating" />
            <Field label="Source IP" value="185.220.101.42" />
            <Field label="Destination" value="web-prod-01" />
            <Field label="Rule" value="5710 / 5712" />
            <Field label="MITRE" value="T1110.001" />
          </div>

          <div className="mt-5">
            <div className="mb-2 flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
              <Clock className="h-3 w-3" /> Correlated timeline · 38s window
            </div>
            <ol className="relative ml-3 space-y-3 border-l border-border/60 pl-5">
              {TIMELINE.map((row, i) => (
                <li key={i} className="relative">
                  <span className={`absolute -left-[26px] top-1 h-2.5 w-2.5 rounded-full border-2 border-background ${row.k === "alert" ? "bg-[color:var(--critical)]" : row.k === "c2" ? "bg-[color:var(--high)]" : row.k === "exec" ? "bg-[color:var(--medium)]" : row.k === "system" ? "bg-primary" : "bg-muted-foreground"}`} />
                  <div className="font-mono text-[11px] text-foreground/85">
                    <span className="text-muted-foreground">{row.t}</span> &nbsp; {row.e}
                  </div>
                </li>
              ))}
            </ol>
          </div>

          <div className="mt-5">
            <div className="mb-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Raw Wazuh log</div>
            <pre className="scanline overflow-x-auto rounded border border-border/60 bg-background/80 p-3 font-mono text-[10.5px] leading-relaxed text-foreground/80">
{RAW}
            </pre>
          </div>
        </Panel>

        <div className="col-span-4 space-y-4">
          <Panel title="IP enrichment">
            <div className="space-y-3 font-mono text-[11px]">
              <Row icon={<Globe className="h-3 w-3" />} k="IP" v="185.220.101.42" />
              <Row icon={<MapPin className="h-3 w-3" />} k="Geo" v="Frankfurt, DE" />
              <Row icon={<Network className="h-3 w-3" />} k="ASN" v="AS43350 NForce" />
              <Row k="WHOIS" v="zwiebelfreunde e.V." />
              <Row k="Reputation" v={<span className="text-[color:var(--critical)]">Malicious · 92/100</span>} />
              <Row k="Categories" v="Tor exit · Brute-force" />
              <Row k="History (90d)" v="471 hits across 38 assets" />
            </div>
            <div className="mt-3 flex gap-2">
              <button className="flex-1 rounded border border-[color:var(--critical)]/50 bg-[color:var(--critical)]/10 py-1.5 font-mono text-[10px] uppercase tracking-widest text-[color:var(--critical)] hover:bg-[color:var(--critical)]/20">Block</button>
              <button className="flex-1 rounded border border-border/60 bg-secondary/40 py-1.5 font-mono text-[10px] uppercase tracking-widest text-foreground/80 hover:bg-secondary/70">Pivot</button>
            </div>
          </Panel>

          <Panel title="Relationship graph">
            <RelationshipGraph />
          </Panel>
        </div>
      </div>
    </Layout>
  );
}

function Field({ label, value, children }: { label: string; value?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <div>
      <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="mt-0.5 font-mono text-xs text-foreground/90">{children ?? value}</div>
    </div>
  );
}
function Row({ icon, k, v }: { icon?: React.ReactNode; k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="flex items-center gap-1.5 text-muted-foreground">{icon}{k}</span>
      <span className="text-right text-foreground/85">{v}</span>
    </div>
  );
}

function RelationshipGraph() {
  return (
    <svg viewBox="0 0 320 220" className="h-56 w-full">
      <defs>
        <radialGradient id="node" cx="50%" cy="50%">
          <stop offset="0%" stopColor="oklch(0.78 0.18 180)" />
          <stop offset="100%" stopColor="oklch(0.4 0.1 200)" />
        </radialGradient>
      </defs>
      {[
        ["M160,110 L40,40", "h"], ["M160,110 L280,40", "h"],
        ["M160,110 L40,180", "h"], ["M160,110 L280,180", "h"],
        ["M160,110 L160,15", "h"],
      ].map((p, i) => (
        <path key={i} d={p[0]} stroke="oklch(0.78 0.18 180 / 35%)" strokeDasharray="3 3" fill="none" />
      ))}
      <circle cx="160" cy="110" r="22" fill="url(#node)" stroke="oklch(0.65 0.27 18)" strokeWidth="2" />
      <text x="160" y="114" textAnchor="middle" fontSize="9" fontFamily="monospace" fill="white">185.220.…</text>

      {[
        [40, 40, "web-prod-01"], [280, 40, "db-master"],
        [40, 180, "svc_deploy"], [280, 180, "91.219…(C2)"],
        [160, 15, "vpn-gw"],
      ].map(([x, y, l], i) => (
        <g key={i}>
          <circle cx={x as number} cy={y as number} r="14" fill="oklch(0.2 0.025 250)" stroke="oklch(0.78 0.18 180 / 60%)" />
          <text x={x as number} y={(y as number) + 26} textAnchor="middle" fontSize="8" fontFamily="monospace" fill="oklch(0.65 0.03 220)">{l}</text>
        </g>
      ))}
    </svg>
  );
}
