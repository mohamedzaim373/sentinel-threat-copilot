import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";
import { StatCard } from "@/components/soc/StatCard";
import { SeverityBadge } from "@/components/soc/SeverityBadge";
import { generateAlerts, SEVERITY_COLOR, type Severity } from "@/lib/soc-data";
import { AlertTriangle, ShieldAlert, Activity, Target } from "lucide-react";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, BarChart, Bar, CartesianGrid, Cell,
} from "recharts";

export const Route = createFileRoute("/")({
  component: Overview,
  head: () => ({ meta: [{ title: "SOC Overview · Sentinel" }, { name: "description", content: "Real-time SOC situational awareness powered by Sentinel + Wazuh." }] }),
});

const MITRE_GRID = [
  ["Initial Access", "T1190", 12],
  ["Execution", "T1059", 27],
  ["Persistence", "T1078", 8],
  ["Privilege Esc.", "T1068", 4],
  ["Defense Evasion", "T1027", 15],
  ["Credential Access", "T1110", 41],
  ["Discovery", "T1083", 9],
  ["Lateral Movement", "T1021", 6],
  ["Collection", "T1005", 3],
  ["C2", "T1071", 22],
  ["Exfiltration", "T1041", 5],
  ["Impact", "T1486", 2],
] as const;

function Overview() {
  const alerts = useMemo(() => generateAlerts(80), []);
  const [stream, setStream] = useState(alerts.slice(0, 8));
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  useEffect(() => {
    const i = setInterval(() => {
      setStream(prev => {
        const next = generateAlerts(1)[0];
        next.id = `ALT-${Math.floor(Math.random() * 99999)}`;
        next.ts = new Date().toISOString();
        return [next, ...prev].slice(0, 12);
      });
    }, 2200);
    return () => clearInterval(i);
  }, []);

  const sevDist = (["critical", "high", "medium", "low", "info"] as Severity[]).map(s => ({
    name: s, value: alerts.filter(a => a.severity === s).length, fill: SEVERITY_COLOR[s],
  }));

  const timeline = Array.from({ length: 24 }, (_, i) => ({
    h: `${i.toString().padStart(2, "0")}:00`,
    alerts: 20 + Math.round(Math.sin(i / 3) * 30 + Math.random() * 40),
    incidents: Math.round(Math.random() * 8),
  }));

  const topAssets = Object.entries(
    alerts.reduce<Record<string, number>>((acc, a) => { acc[a.asset] = (acc[a.asset] || 0) + a.count; return acc; }, {}),
  ).sort((a, b) => b[1] - a[1]).slice(0, 6);

  return (
    <Layout title="SOC Overview" subtitle="Real-time situational awareness · Wazuh ingest active">
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Active incidents" value="14" delta="↑ 3 last hour" accent="critical" icon={<AlertTriangle className="h-4 w-4" />} />
        <StatCard label="Alerts / 24h" value="2,481" delta="↓ 12% vs yesterday" accent="primary" icon={<Activity className="h-4 w-4" />} />
        <StatCard label="Assets monitored" value="318" delta="6 new today" accent="success" icon={<Target className="h-4 w-4" />} />
        <StatCard label="MTTR" value="11m 42s" delta="↓ 2m 18s" accent="high" icon={<ShieldAlert className="h-4 w-4" />} />
      </div>

      <div className="mt-4 grid grid-cols-3 gap-4">
        <Panel title="Event timeline · 24h" className="col-span-2">
          <div className="h-56">
            <ResponsiveContainer>
              <AreaChart data={timeline}>
                <defs>
                  <linearGradient id="gA" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="oklch(0.78 0.18 180)" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="oklch(0.78 0.18 180)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gB" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="oklch(0.65 0.27 18)" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="oklch(0.65 0.27 18)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="oklch(1 0 0 / 5%)" vertical={false} />
                <XAxis dataKey="h" stroke="oklch(0.65 0.03 220)" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="oklch(0.65 0.03 220)" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "oklch(0.2 0.025 250)", border: "1px solid oklch(0.3 0.03 240)", fontSize: 11, fontFamily: "monospace" }} />
                <Area type="monotone" dataKey="alerts" stroke="oklch(0.78 0.18 180)" fill="url(#gA)" strokeWidth={2} />
                <Area type="monotone" dataKey="incidents" stroke="oklch(0.65 0.27 18)" fill="url(#gB)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Severity distribution">
          <div className="h-56">
            <ResponsiveContainer>
              <BarChart data={sevDist} layout="vertical" margin={{ left: 0 }}>
                <CartesianGrid stroke="oklch(1 0 0 / 5%)" horizontal={false} />
                <XAxis type="number" stroke="oklch(0.65 0.03 220)" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="name" stroke="oklch(0.65 0.03 220)" fontSize={10} tickLine={false} axisLine={false} width={60} />
                <Tooltip contentStyle={{ background: "oklch(0.2 0.025 250)", border: "1px solid oklch(0.3 0.03 240)", fontSize: 11 }} cursor={{ fill: "oklch(1 0 0 / 4%)" }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {sevDist.map((d, i) => <Cell key={i} fill={d.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-3 gap-4">
        <Panel title="Live alert stream · Wazuh" className="col-span-2"
          action={<span className="font-mono text-[10px] text-muted-foreground">{stream.length} streaming</span>}>
          <ul className="divide-y divide-border/40">
            {stream.map(a => (
              <li key={a.id} className="grid grid-cols-12 items-center gap-3 py-2 font-mono text-[11px]">
                <span suppressHydrationWarning className="col-span-2 text-muted-foreground tabular-nums">{mounted ? new Date(a.ts).toUTCString().slice(17, 25) : "--:--:--"}</span>
                <span className="col-span-1"><SeverityBadge severity={a.severity} /></span>
                <span className="col-span-2 text-foreground/80">{a.sourceIp}</span>
                <span className="col-span-1 text-muted-foreground">→ {a.asset}</span>
                <span className="col-span-1 text-primary">{a.mitre}</span>
                <span className="col-span-4 truncate text-foreground/70">{a.description}</span>
                <span className="col-span-1 text-right text-[color:var(--high)] tabular-nums">{a.score}</span>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Top attacked assets">
          <ul className="space-y-2.5">
            {topAssets.map(([asset, count], i) => {
              const max = topAssets[0][1];
              const pct = (count / max) * 100;
              return (
                <li key={asset} className="font-mono text-xs">
                  <div className="mb-1 flex items-center justify-between">
                    <span className="text-foreground/80">{i + 1}. {asset}</span>
                    <span className="text-muted-foreground tabular-nums">{count}</span>
                  </div>
                  <div className="h-1 overflow-hidden rounded-full bg-secondary/60">
                    <div className="h-full rounded-full bg-gradient-to-r from-primary to-[color:var(--critical)]" style={{ width: `${pct}%` }} />
                  </div>
                </li>
              );
            })}
          </ul>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel title="MITRE ATT&CK · technique heatmap">
          <div className="grid grid-cols-6 gap-2">
            {MITRE_GRID.map(([name, id, count]) => {
              const intensity = Math.min(1, (count as number) / 41);
              return (
                <div key={id as string} className="rounded border border-border/60 p-2.5 transition-colors hover:border-primary/60"
                  style={{ background: `oklch(0.78 0.18 180 / ${intensity * 0.18 + 0.04})` }}>
                  <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">{id}</div>
                  <div className="mt-1 text-[11px] font-medium text-foreground/90">{name}</div>
                  <div className="mt-1 flex items-end justify-between">
                    <span className="font-mono text-[10px] text-muted-foreground">events</span>
                    <span className="font-display text-lg font-semibold text-primary tabular-nums">{count}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>
    </Layout>
  );
}
