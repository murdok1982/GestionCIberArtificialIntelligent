"use client";
import { useQuery } from "@tanstack/react-query";
import {
  Monitor, AlertTriangle, Activity, Shield,
  TrendingUp, TrendingDown, Minus,
} from "lucide-react";
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import { alertsApi, devicesApi } from "@/lib/api";
import { formatRelativeTime, severityBadge, statusColor } from "@/lib/utils";
import type { Alert, Device } from "@/types";
import Link from "next/link";

// Mock chart data for demonstration
const alertsTrend = [
  { day: "Mon", critical: 2, high: 5, medium: 8, low: 12 },
  { day: "Tue", critical: 1, high: 3, medium: 6, low: 9 },
  { day: "Wed", critical: 4, high: 7, medium: 11, low: 15 },
  { day: "Thu", critical: 0, high: 2, medium: 5, low: 7 },
  { day: "Fri", critical: 3, high: 6, medium: 9, low: 13 },
  { day: "Sat", critical: 1, high: 1, medium: 3, low: 5 },
  { day: "Sun", critical: 2, high: 4, medium: 7, low: 10 },
];

const eventTypes = [
  { name: "Auth Events", count: 1420 },
  { name: "Network", count: 890 },
  { name: "Process", count: 650 },
  { name: "File System", count: 430 },
  { name: "Registry", count: 210 },
];

const alertStatusDist = [
  { name: "Open", value: 12, color: "#EF4444" },
  { name: "Investigating", value: 5, color: "#F59E0B" },
  { name: "Resolved", value: 34, color: "#10B981" },
  { name: "False Positive", value: 8, color: "#6B7280" },
];

function StatCard({
  title, value, subtitle, icon: Icon, color, trend,
}: {
  title: string;
  value: string | number;
  subtitle: string;
  icon: React.ElementType;
  color: string;
  trend?: "up" | "down" | "neutral";
}) {
  const TrendIcon = trend === "up" ? TrendingUp : trend === "down" ? TrendingDown : Minus;
  const trendColor = trend === "down" ? "text-emerald-400" : trend === "up" ? "text-red-400" : "text-slate-500";

  return (
    <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5 hover:border-[#2E4163] transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className={`p-2.5 rounded-lg ${color}`}>
          <Icon className="w-5 h-5" />
        </div>
        {trend && <TrendIcon className={`w-4 h-4 ${trendColor}`} />}
      </div>
      <div className="text-2xl font-bold text-white mb-1">{value}</div>
      <div className="text-sm font-medium text-slate-300">{title}</div>
      <div className="text-xs text-slate-500 mt-0.5">{subtitle}</div>
    </div>
  );
}

export default function DashboardPage() {
  const { data: devices = [] } = useQuery<Device[]>({
    queryKey: ["devices"],
    queryFn: () => devicesApi.list().then((r) => r.data),
    refetchInterval: 30000,
  });

  const { data: alerts = [] } = useQuery<Alert[]>({
    queryKey: ["alerts", "recent"],
    queryFn: () => alertsApi.list({ limit: 5 }).then((r) => r.data),
    refetchInterval: 15000,
  });

  const onlineDevices = devices.filter((d) => d.status === "online").length;
  const criticalAlerts = alerts.filter((a) => a.severity === "critical").length;
  const openAlerts = alerts.filter((a) => a.status === "open").length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="Total Endpoints"
          value={devices.length}
          subtitle={`${onlineDevices} online`}
          icon={Monitor}
          color="bg-blue-600/20 text-blue-400"
          trend="neutral"
        />
        <StatCard
          title="Critical Alerts"
          value={criticalAlerts}
          subtitle="Last 24 hours"
          icon={AlertTriangle}
          color="bg-red-600/20 text-red-400"
          trend={criticalAlerts > 0 ? "up" : "neutral"}
        />
        <StatCard
          title="Events Processed"
          value="3,601"
          subtitle="Last 24 hours"
          icon={Activity}
          color="bg-purple-600/20 text-purple-400"
          trend="down"
        />
        <StatCard
          title="Open Alerts"
          value={openAlerts}
          subtitle="Requiring attention"
          icon={Shield}
          color="bg-amber-600/20 text-amber-400"
          trend={openAlerts > 5 ? "up" : "neutral"}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alerts Trend */}
        <div className="lg:col-span-2 bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Alert Trends — Last 7 Days</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={alertsTrend}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1E2D47" />
              <XAxis dataKey="day" stroke="#475569" tick={{ fill: "#64748B", fontSize: 11 }} />
              <YAxis stroke="#475569" tick={{ fill: "#64748B", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ backgroundColor: "#0F1629", border: "1px solid #1E2D47", borderRadius: "8px" }}
                labelStyle={{ color: "#F1F5F9" }}
              />
              <Legend wrapperStyle={{ fontSize: "11px" }} />
              <Line type="monotone" dataKey="critical" stroke="#EF4444" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="high" stroke="#F97316" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="medium" stroke="#F59E0B" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="low" stroke="#10B981" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Alert Distribution */}
        <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4">Alert Status</h3>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={alertStatusDist} cx="50%" cy="50%" innerRadius={45} outerRadius={75} dataKey="value" paddingAngle={3}>
                {alertStatusDist.map((entry, idx) => (
                  <Cell key={idx} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: "#0F1629", border: "1px solid #1E2D47", borderRadius: "8px" }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1.5 mt-2">
            {alertStatusDist.map((entry) => (
              <div key={entry.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: entry.color }} />
                  <span className="text-slate-400">{entry.name}</span>
                </div>
                <span className="text-white font-medium">{entry.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl">
        <div className="flex items-center justify-between p-5 border-b border-[#1E2D47]">
          <h3 className="text-sm font-semibold text-white">Recent Alerts</h3>
          <Link href="/alerts" className="text-xs text-blue-400 hover:text-blue-300">View all →</Link>
        </div>
        <div className="divide-y divide-[#1E2D47]">
          {alerts.length === 0 ? (
            <div className="p-8 text-center text-slate-500 text-sm">No alerts — system is healthy</div>
          ) : (
            alerts.slice(0, 5).map((alert) => (
              <Link
                key={alert.id}
                href={`/alerts/${alert.id}`}
                className="flex items-center gap-4 p-4 hover:bg-[#0F1629] transition-colors group"
              >
                <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${severityBadge(alert.severity)}`}>
                  {alert.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white truncate group-hover:text-blue-300">{alert.title}</p>
                  {alert.mitre_tactic && (
                    <p className="text-xs text-slate-500">{alert.mitre_tactic} · {alert.mitre_technique}</p>
                  )}
                </div>
                <span className="text-xs text-slate-500 flex-shrink-0">{formatRelativeTime(alert.created_at)}</span>
              </Link>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
