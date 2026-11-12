import { createFileRoute } from "@tanstack/react-router";
import { Layout } from "@/components/soc/Layout";
import { Panel } from "@/components/soc/Panel";

export const Route = createFileRoute("/access")({ component: Access, head: () => ({ meta: [{ title: "Access Control · Sentinel" }] }) });

const USERS = [
  { name: "M. Hartmann", role: "SOC Manager", email: "m.hartmann@corp.io", last: "now" },
  { name: "L. Okafor", role: "Analyst", email: "l.okafor@corp.io", last: "12m ago" },
  { name: "S. Iyer", role: "Analyst", email: "s.iyer@corp.io", last: "3h ago" },
  { name: "R. Petrov", role: "Viewer", email: "r.petrov@corp.io", last: "1d ago" },
  { name: "responder-bot", role: "Service Account", email: "bot@sentinel", last: "now" },
];
const PERMS = [
  ["View dashboards", true, true, true],
  ["View raw Wazuh logs", true, true, false],
  ["Promote alerts to incidents", true, true, false],
  ["Execute response actions", true, false, false],
  ["Approve critical responses", true, false, false],
  ["Manage users & roles", true, false, false],
  ["Edit playbooks", true, false, false],
];

function Access() {
  return (
    <Layout title="Access Control" subtitle="RBAC · role-scoped permissions · audit-grade">
      <div className="grid grid-cols-12 gap-4">
        <Panel title="Users" className="col-span-7">
          <table className="w-full font-mono text-[11px]">
            <thead>
              <tr className="text-left text-muted-foreground">
                {["Name", "Role", "Email", "Last seen", ""].map(h => <th key={h} className="border-b border-border/40 px-3 py-2 text-[10px] uppercase tracking-widest">{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {USERS.map(u => (
                <tr key={u.email} className="border-b border-border/30">
                  <td className="px-3 py-2 text-foreground/90">{u.name}</td>
                  <td className="px-3 py-2"><span className="rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-[10px] uppercase tracking-widest text-primary">{u.role}</span></td>
                  <td className="px-3 py-2 text-muted-foreground">{u.email}</td>
                  <td className="px-3 py-2 text-muted-foreground">{u.last}</td>
                  <td className="px-3 py-2 text-right"><button className="text-foreground/70 hover:text-foreground">edit</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Permission matrix" className="col-span-5">
          <table className="w-full font-mono text-[11px]">
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="border-b border-border/40 px-3 py-2 text-[10px] uppercase tracking-widest">Permission</th>
                <th className="border-b border-border/40 px-2 py-2 text-center text-[10px] uppercase tracking-widest">Mgr</th>
                <th className="border-b border-border/40 px-2 py-2 text-center text-[10px] uppercase tracking-widest">Analyst</th>
                <th className="border-b border-border/40 px-2 py-2 text-center text-[10px] uppercase tracking-widest">Viewer</th>
              </tr>
            </thead>
            <tbody>
              {PERMS.map(([p, ...flags], i) => (
                <tr key={i} className="border-b border-border/30">
                  <td className="px-3 py-2 text-foreground/85">{p as string}</td>
                  {flags.map((f, j) => (
                    <td key={j} className="px-2 py-2 text-center">
                      <span className={f ? "text-[color:var(--success)]" : "text-muted-foreground/40"}>{f ? "●" : "○"}</span>
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </Layout>
  );
}
