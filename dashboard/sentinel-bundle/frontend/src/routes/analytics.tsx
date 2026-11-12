import { createFileRoute } from "@tanstack/react-router";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";
import { StatCard } from "@/components/soc/StatCard";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, BarChart, Bar, Cell } from "recharts";

export const Route = createFileRoute("/analytics")({ component: Analytics, head: () => ({ meta: [{ title: "Analytics · Sentinel" }] }) });

const TREND = Array.from({ length: 14 }, (_, i) => ({
  day: `D-${14 - i}`,
  alerts: 1200 + Math.round(Math.random() * 1500),
  incidents: 4 + Math.round(Math.random() * 18),
}));
const VULNS = [
  { cve: "CVE-2026-1182", c: 41 }, { cve: "CVE-2025-44219", c: 37 },
  { cve: "CVE-2026-0901", c: 24 }, { cve: "CVE-2025-39001", c: 18 },
  { cve: "CVE-2026-1144", c: 11 }, { cve: "CVE-2025-29871", c: 7 },
];
const ASSETS = [
  { a: "web-prod-01", c: 481 }, { a: "k8s-edge-3", c: 392 }, { a: "db-master", c: 244 },
  { a: "vpn-gw", c: 198 }, { a: "auth-svc", c: 142 }, { a: "win-dc-01", c: 98 },
];

function Analytics() {
  return (
    <Layout title="Analytics & Reporting" subtitle="Trends · MTTD/MTTR · vulnerability posture">
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="MTTD (7d avg)" value="2m 04s" delta="↓ 18s" accent="success" />
        <StatCard label="MTTR (7d avg)" value="11m 42s" delta="↓ 2m 18s" accent="primary" />
        <StatCard label="False positive rate" value="3.4%" delta="↓ 0.6%" accent="success" />
        <StatCard label="Auto-response rate" value="68%" delta="↑ 4%" accent="high" />
      </div>

      <div className="mt-4 grid grid-cols-3 gap-4">
        <Panel title="Attack trend · 14 days" className="col-span-2">
          <div className="h-64">
            <ResponsiveContainer>
              <LineChart data={TREND}>
                <CartesianGrid stroke="oklch(1 0 0 / 5%)" vertical={false} />
                <XAxis dataKey="day" stroke="oklch(0.65 0.03 220)" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis yAxisId="l" stroke="oklch(0.65 0.03 220)" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis yAxisId="r" orientation="right" stroke="oklch(0.65 0.27 18)" fontSize={10} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ background: "oklch(0.2 0.025 250)", border: "1px solid oklch(0.3 0.03 240)", fontSize: 11 }} />
                <Line yAxisId="l" type="monotone" dataKey="alerts" stroke="oklch(0.78 0.18 180)" strokeWidth={2} dot={false} />
                <Line yAxisId="r" type="monotone" dataKey="incidents" stroke="oklch(0.65 0.27 18)" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Top vulnerabilities">
          <div className="h-64">
            <ResponsiveContainer>
              <BarChart data={VULNS} layout="vertical" margin={{ left: 10 }}>
                <XAxis type="number" stroke="oklch(0.65 0.03 220)" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="cve" stroke="oklch(0.65 0.03 220)" fontSize={9} tickLine={false} axisLine={false} width={110} />
                <Tooltip contentStyle={{ background: "oklch(0.2 0.025 250)", border: "1px solid oklch(0.3 0.03 240)", fontSize: 11 }} cursor={{ fill: "oklch(1 0 0 / 4%)" }} />
                <Bar dataKey="c" radius={[0, 4, 4, 0]}>
                  {VULNS.map((_, i) => <Cell key={i} fill={`oklch(${0.78 - i * 0.05} 0.2 ${20 + i * 30})`} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <Panel title="Most targeted assets · 30d" className="mt-4">
        <div className="grid grid-cols-6 gap-3">
          {ASSETS.map(a => {
            const max = ASSETS[0].c;
            const intensity = a.c / max;
            return (
              <div key={a.a} className="rounded border border-border/60 p-3" style={{ background: `oklch(0.65 0.27 18 / ${intensity * 0.3})` }}>
                <div className="font-mono text-[10px] text-muted-foreground">{a.a}</div>
                <div className="mt-1 font-display text-2xl font-semibold tabular-nums">{a.c}</div>
                <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">attacks</div>
              </div>
            );
          })}
        </div>
      </Panel>
    </Layout>
  );
}
