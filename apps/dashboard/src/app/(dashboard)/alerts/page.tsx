"use client";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { Bell, Filter, RefreshCw, Brain, ChevronRight, Zap } from "lucide-react";
import { alertsApi } from "@/lib/api";
import { formatRelativeTime, severityBadge, statusColor } from "@/lib/utils";
import type { Alert, Severity, AlertStatus } from "@/types";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: AlertStatus[] = ["open", "investigating", "resolved", "false_positive"];

export default function AlertsPage() {
  const qc = useQueryClient();
  const [severity, setSeverity] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const { data: alerts = [], isLoading, refetch } = useQuery<Alert[]>({
    queryKey: ["alerts", severity, statusFilter],
    queryFn: () =>
      alertsApi
        .list({
          severity: severity !== "all" ? severity : undefined,
          status_filter: statusFilter !== "all" ? statusFilter : undefined,
          limit: 100,
        })
        .then((r) => r.data),
    refetchInterval: 15000,
  });

  const analyzeMutation = useMutation({
    mutationFn: (id: string) => alertsApi.analyze(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alerts"] }),
  });

  const counts: Record<string, number> = {
    all: alerts.length,
    ...Object.fromEntries(SEVERITIES.map((s) => [s, alerts.filter((a) => a.severity === s).length])),
  };

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Security Alerts</h2>
          <p className="text-sm text-slate-500">
            {alerts.filter((a) => a.status === "open").length} open ·{" "}
            {alerts.filter((a) => a.severity === "critical").length} critical
          </p>
        </div>
        <button onClick={() => refetch()} className="p-2 rounded-lg border border-[#1E2D47] text-slate-400 hover:text-slate-200 hover:bg-[#141B2D] transition-all">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="flex items-center gap-1.5">
          <Filter className="w-3.5 h-3.5 text-slate-500" />
          <span className="text-xs text-slate-500 mr-1">Severity:</span>
          {(["all", ...SEVERITIES] as string[]).map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors capitalize ${
                severity === s ? "bg-blue-600 text-white" : "bg-[#141B2D] border border-[#1E2D47] text-slate-400 hover:text-slate-200"
              }`}
            >
              {s === "all" ? `All (${counts.all})` : `${s} (${counts[s] ?? 0})`}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-slate-500">Status:</span>
          {(["all", ...STATUSES] as string[]).map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors capitalize ${
                statusFilter === s ? "bg-blue-600 text-white" : "bg-[#141B2D] border border-[#1E2D47] text-slate-400 hover:text-slate-200"
              }`}
            >
              {s.replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      {/* Alert list */}
      <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-slate-500">Loading alerts...</div>
        ) : alerts.length === 0 ? (
          <div className="p-12 text-center">
            <Bell className="w-10 h-10 text-slate-700 mx-auto mb-3" />
            <p className="text-slate-400 font-medium">No alerts match your filters</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1E2D47]">
                {["Severity", "Title", "Device", "MITRE", "Status", "AI Analysis", "Time", ""].map((h) => (
                  <th key={h} className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D47]">
              {alerts.map((alert) => (
                <tr key={alert.id} className={`hover:bg-[#0F1629] transition-colors group ${alert.severity === "critical" && alert.status === "open" ? "glow-critical" : ""}`}>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${severityBadge(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    <div className="flex items-center gap-1.5">
                      {alert.requires_approval && alert.pending_action && (
                        <Zap className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" title="Action pending approval" />
                      )}
                      <span className="text-sm text-white truncate">{alert.title}</span>
                    </div>
                    {alert.auto_action_taken && (
                      <span className="text-xs text-red-400">Auto-action taken</span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-hash text-xs text-slate-500">{alert.device_id.slice(0, 8)}…</td>
                  <td className="px-4 py-3">
                    {alert.mitre_technique ? (
                      <span className="font-mono text-xs text-purple-400">{alert.mitre_technique}</span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs capitalize ${statusColor(alert.status)}`}>
                      {alert.status.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {alert.llm_analysis ? (
                      <div className="flex items-center gap-1">
                        <Brain className="w-3.5 h-3.5 text-blue-400" />
                        <span className="text-xs text-blue-400">{Math.round((alert.llm_analysis.confidence ?? 0) * 100)}%</span>
                      </div>
                    ) : (
                      <button
                        onClick={() => analyzeMutation.mutate(alert.id)}
                        disabled={analyzeMutation.isPending}
                        className="text-xs text-slate-500 hover:text-blue-400 transition-colors"
                      >
                        + Analyze
                      </button>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500 whitespace-nowrap">{formatRelativeTime(alert.created_at)}</td>
                  <td className="px-4 py-3">
                    <Link href={`/alerts/${alert.id}`} className="opacity-0 group-hover:opacity-100 p-1.5 text-slate-400 hover:text-blue-400 rounded transition-all inline-flex">
                      <ChevronRight className="w-4 h-4" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
