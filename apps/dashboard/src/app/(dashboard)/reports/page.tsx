"use client";
import { useQuery } from "@tanstack/react-query";
import { FileText, Download, Calendar } from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, LineChart, Line, Legend,
} from "recharts";
import { alertsApi, devicesApi } from "@/lib/api";

const weeklyData = [
  { week: "W1", critical: 3, high: 8, medium: 15, low: 22 },
  { week: "W2", critical: 1, high: 5, medium: 12, low: 18 },
  { week: "W3", critical: 5, high: 11, medium: 20, low: 30 },
  { week: "W4", critical: 2, high: 6, medium: 9, low: 14 },
];

const mitreData = [
  { tactic: "Exec", count: 24 },
  { tactic: "Persist", count: 18 },
  { tactic: "Priv Esc", count: 12 },
  { tactic: "Def Eva", count: 15 },
  { tactic: "Cred Acc", count: 9 },
  { tactic: "Lateral", count: 7 },
  { tactic: "Exfil", count: 5 },
  { tactic: "Impact", count: 3 },
];

export default function ReportsPage() {
  const { data: devices = [] } = useQuery({ queryKey: ["devices"], queryFn: () => devicesApi.list().then((r) => r.data) });
  const { data: alerts = [] } = useQuery({ queryKey: ["alerts", "all"], queryFn: () => alertsApi.list({ limit: 200 }).then((r) => r.data) });

  const resolved = alerts.filter((a: any) => a.status === "resolved").length;
  const falsePositive = alerts.filter((a: any) => a.status === "false_positive").length;
  const detectionRate = alerts.length > 0 ? Math.round(((alerts.length - falsePositive) / alerts.length) * 100) : 0;

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Security Reports</h2>
          <p className="text-sm text-slate-500">Monthly executive summary and KPIs</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 border border-[#1E2D47] text-slate-400 hover:text-white hover:border-blue-500 rounded-lg text-sm transition-colors">
          <Download className="w-4 h-4" /> Export PDF
        </button>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Total Endpoints", value: devices.length, color: "text-blue-400" },
          { label: "Total Alerts", value: alerts.length, color: "text-red-400" },
          { label: "Resolved", value: resolved, color: "text-emerald-400" },
          { label: "Detection Rate", value: `${detectionRate}%`, color: "text-purple-400" },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-4 text-center">
            <p className={`text-2xl font-bold ${color}`}>{value}</p>
            <p className="text-xs text-slate-500 mt-1">{label}</p>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Weekly Alert Trend</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={weeklyData} barSize={10}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1E2D47" />
              <XAxis dataKey="week" stroke="#475569" tick={{ fill: "#64748B", fontSize: 11 }} />
              <YAxis stroke="#475569" tick={{ fill: "#64748B", fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: "#0F1629", border: "1px solid #1E2D47", borderRadius: "8px" }} />
              <Legend wrapperStyle={{ fontSize: "11px" }} />
              <Bar dataKey="critical" fill="#EF4444" radius={[2, 2, 0, 0]} />
              <Bar dataKey="high" fill="#F97316" radius={[2, 2, 0, 0]} />
              <Bar dataKey="medium" fill="#F59E0B" radius={[2, 2, 0, 0]} />
              <Bar dataKey="low" fill="#10B981" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4">MITRE ATT&CK Coverage</h3>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={mitreData} layout="vertical" barSize={12}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1E2D47" horizontal={false} />
              <XAxis type="number" stroke="#475569" tick={{ fill: "#64748B", fontSize: 11 }} />
              <YAxis dataKey="tactic" type="category" stroke="#475569" tick={{ fill: "#64748B", fontSize: 11 }} width={55} />
              <Tooltip contentStyle={{ backgroundColor: "#0F1629", border: "1px solid #1E2D47", borderRadius: "8px" }} />
              <Bar dataKey="count" fill="#8B5CF6" radius={[0, 2, 2, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
