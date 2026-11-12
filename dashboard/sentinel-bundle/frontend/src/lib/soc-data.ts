export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Alert {
  id: string;
  ts: string;
  sourceIp: string;
  destIp: string;
  asset: string;
  ruleId: string;
  description: string;
  severity: Severity;
  score: number;
  mitre: string;
  mitreName: string;
  count: number;
  status: "new" | "triaged" | "incident";
}

const MITRE = [
  ["T1110", "Brute Force"],
  ["T1078", "Valid Accounts"],
  ["T1059", "Command Execution"],
  ["T1486", "Data Encrypted"],
  ["T1071", "App Layer Protocol"],
  ["T1003", "OS Credential Dump"],
  ["T1566", "Phishing"],
  ["T1190", "Exploit Public App"],
];

const ASSETS = ["web-prod-01", "db-master", "k8s-edge-3", "vpn-gw", "fw-core", "auth-svc", "mail-relay", "win-dc-01"];
const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];

const rand = (() => { let s = 42; return () => (s = (s * 9301 + 49297) % 233280) / 233280; })();
const pick = <T,>(a: T[]) => a[Math.floor(rand() * a.length)];
const ip = () => `${10 + Math.floor(rand() * 240)}.${Math.floor(rand() * 256)}.${Math.floor(rand() * 256)}.${Math.floor(rand() * 256)}`;

export function generateAlerts(n = 60): Alert[] {
  const now = Date.now();
  return Array.from({ length: n }, (_, i) => {
    const sev = pick(SEV);
    const m = pick(MITRE);
    const score = sev === "critical" ? 80 + Math.floor(rand() * 20) :
                  sev === "high" ? 60 + Math.floor(rand() * 20) :
                  sev === "medium" ? 40 + Math.floor(rand() * 20) :
                  sev === "low" ? 20 + Math.floor(rand() * 20) : Math.floor(rand() * 20);
    return {
      id: `ALT-${(10000 + i).toString()}`,
      ts: new Date(now - i * 1000 * Math.floor(rand() * 600)).toISOString(),
      sourceIp: ip(),
      destIp: ip(),
      asset: pick(ASSETS),
      ruleId: `${5000 + Math.floor(rand() * 4000)}`,
      description: pick([
        "Multiple authentication failures",
        "Suspicious PowerShell invocation",
        "Outbound connection to known C2",
        "Privilege escalation attempt",
        "Anomalous file modification rate",
        "Unusual login geolocation",
        "Lateral movement pattern detected",
        "DNS tunneling indicators",
      ]),
      severity: sev,
      score,
      mitre: m[0],
      mitreName: m[1],
      count: 1 + Math.floor(rand() * 24),
      status: "new",
    };
  });
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
  info: "var(--muted-foreground)",
};

export interface Incident {
  id: string;
  title: string;
  status: "Open" | "In Progress" | "Resolved";
  severity: Severity;
  assignee: string;
  created: string;
  alertCount: number;
}

export const INCIDENTS: Incident[] = [
  { id: "INC-2026-0142", title: "Coordinated SSH brute-force against edge nodes", status: "In Progress", severity: "critical", assignee: "M. Hartmann", created: "2026-05-05T09:12:00Z", alertCount: 47 },
  { id: "INC-2026-0141", title: "Suspicious PowerShell on win-dc-01", status: "Open", severity: "high", assignee: "—", created: "2026-05-05T08:40:00Z", alertCount: 12 },
  { id: "INC-2026-0140", title: "Outbound C2 beacon from k8s-edge-3", status: "In Progress", severity: "critical", assignee: "L. Okafor", created: "2026-05-05T07:55:00Z", alertCount: 89 },
  { id: "INC-2026-0139", title: "Anomalous data egress on db-master", status: "Open", severity: "high", assignee: "S. Iyer", created: "2026-05-05T06:20:00Z", alertCount: 23 },
  { id: "INC-2026-0138", title: "Phishing payload delivered via mail-relay", status: "Resolved", severity: "medium", assignee: "M. Hartmann", created: "2026-05-04T22:11:00Z", alertCount: 6 },
];
