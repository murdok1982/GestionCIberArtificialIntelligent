"use client";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams, useRouter } from "next/navigation";
import {
  AlertTriangle, Clock, Monitor, Brain, Shield,
  CheckCircle, XCircle, ChevronLeft, Zap,
} from "lucide-react";
import { alertsApi } from "@/lib/api";
import { formatDateTime, formatRelativeTime, severityBadge, cn } from "@/lib/utils";
import type { Alert, LLMAnalysis, Recommendation } from "@/types";

function RiskGauge({ confidence, riskLevel }: { confidence: number; riskLevel: string }) {
  const colors: Record<string, string> = {
    critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#10B981", info: "#6B7280",
  };
  const pct = Math.round(confidence * 100);
  const color = colors[riskLevel] ?? "#6B7280";

  return (
    <div className="flex items-center gap-4">
      <div className="relative w-16 h-16">
        <svg className="w-16 h-16 -rotate-90" viewBox="0 0 36 36">
          <circle cx="18" cy="18" r="15" fill="none" stroke="#1E2D47" strokeWidth="3" />
          <circle cx="18" cy="18" r="15" fill="none" stroke={color} strokeWidth="3"
            strokeDasharray={`${pct * 0.942} 94.2`} strokeLinecap="round" />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-xs font-bold" style={{ color }}>{pct}%</span>
        </div>
      </div>
      <div>
        <p className="text-xs text-slate-500">Confidence</p>
        <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${severityBadge(riskLevel)}`}>
          {riskLevel}
        </span>
      </div>
    </div>
  );
}

function ActionApproval({ alertId, pendingAction, onComplete }: {
  alertId: string;
  pendingAction: any;
  onComplete: () => void;
}) {
  const [justification, setJustification] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const handleApproval = async (approved: boolean) => {
    if (!justification.trim()) return;
    setSubmitting(true);
    try {
      await alertsApi.approveAction(alertId, {
        approved,
        justification,
        action_type: pendingAction.action_type,
        params: pendingAction.params,
      });
      onComplete();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Zap className="w-5 h-5 text-amber-400" />
        <h3 className="text-sm font-semibold text-amber-400">Action Pending Approval</h3>
      </div>
      <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
        <div>
          <span className="text-slate-500">Action</span>
          <p className="text-white font-mono">{pendingAction.action_type}</p>
        </div>
        <div>
          <span className="text-slate-500">Risk Level</span>
          <span className={`ml-2 px-2 py-0.5 rounded text-xs font-bold uppercase ${severityBadge(pendingAction.risk_level)}`}>
            {pendingAction.risk_level}
          </span>
        </div>
      </div>
      <p className="text-xs text-slate-400 mb-4 bg-[#0F1629] p-3 rounded">{pendingAction.justification}</p>
      <textarea
        value={justification}
        onChange={(e) => setJustification(e.target.value)}
        placeholder="Required: Enter your justification for this decision..."
        className="w-full h-20 px-3 py-2 bg-[#141B2D] border border-[#1E2D47] rounded-lg text-sm text-white placeholder-slate-600 focus:outline-none focus:border-amber-500 resize-none mb-3"
      />
      <div className="flex gap-3">
        <button
          disabled={!justification.trim() || submitting}
          onClick={() => handleApproval(true)}
          className="flex-1 flex items-center justify-center gap-2 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
        >
          <CheckCircle className="w-4 h-4" />
          Approve Action
        </button>
        <button
          disabled={!justification.trim() || submitting}
          onClick={() => handleApproval(false)}
          className="flex-1 flex items-center justify-center gap-2 py-2 bg-red-600/20 hover:bg-red-600/30 border border-red-500/30 disabled:opacity-50 disabled:cursor-not-allowed text-red-400 text-sm font-medium rounded-lg transition-colors"
        >
          <XCircle className="w-4 h-4" />
          Reject
        </button>
      </div>
    </div>
  );
}

function LLMAnalysisPanel({ analysis }: { analysis: LLMAnalysis }) {
  return (
    <div className="space-y-4">
      {/* Executive Summary */}
      <div className="bg-blue-600/10 border border-blue-500/20 rounded-xl p-4">
        <div className="flex items-center gap-2 mb-2">
          <Brain className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-semibold text-blue-400">AI Executive Summary</span>
          {analysis.is_imminent_danger && (
            <span className="px-2 py-0.5 bg-red-500 text-white text-xs font-bold rounded animate-pulse">
              IMMINENT DANGER
            </span>
          )}
        </div>
        <p className="text-sm text-slate-300">{analysis.executive_summary}</p>
      </div>

      {/* Risk + Confidence */}
      <RiskGauge confidence={analysis.confidence} riskLevel={analysis.risk_level} />

      {/* MITRE Mapping */}
      {analysis.mitre_mapping?.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-slate-500 uppercase mb-2">MITRE ATT&CK Mapping</h4>
          <div className="flex flex-wrap gap-2">
            {analysis.mitre_mapping.map((m, i) => (
              <div key={i} className="flex items-center gap-1.5 px-2.5 py-1.5 bg-purple-600/10 border border-purple-500/20 rounded-lg">
                <span className="text-xs font-mono text-purple-400">{m.technique_id}</span>
                <span className="text-xs text-slate-400">{m.technique}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings */}
      {analysis.findings?.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-slate-500 uppercase mb-2">Findings</h4>
          <div className="space-y-2">
            {analysis.findings.map((f) => (
              <div key={f.id} className="flex items-start gap-3 p-3 bg-[#0F1629] rounded-lg border border-[#1E2D47]">
                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase flex-shrink-0 ${severityBadge(f.severity)}`}>
                  {f.severity}
                </span>
                <div>
                  <p className="text-sm text-white font-medium">{f.title}</p>
                  <p className="text-xs text-slate-400">{f.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {analysis.recommendations?.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-slate-500 uppercase mb-2">Recommendations</h4>
          <div className="space-y-2">
            {analysis.recommendations.map((r, i) => (
              <div key={i} className="flex items-start gap-3 p-3 bg-[#0F1629] rounded-lg border border-[#1E2D47]">
                <span className="w-5 h-5 rounded-full bg-blue-600/20 text-blue-400 text-xs flex items-center justify-center flex-shrink-0 font-bold">
                  {r.priority}
                </span>
                <div className="flex-1">
                  <p className="text-sm text-white">{r.action}</p>
                  <p className="text-xs text-slate-400">{r.description}</p>
                </div>
                {r.requires_approval && (
                  <span className="text-xs text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded flex-shrink-0">Needs approval</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Forensic Next Steps */}
      {analysis.forensic_next_steps?.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold text-slate-500 uppercase mb-2">Forensic Next Steps</h4>
          <ol className="space-y-1">
            {analysis.forensic_next_steps.map((step, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-slate-400">
                <span className="text-blue-400 font-bold flex-shrink-0">{i + 1}.</span>
                {step}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const qc = useQueryClient();

  const { data: alert, isLoading } = useQuery<Alert>({
    queryKey: ["alert", id],
    queryFn: () => alertsApi.get(id).then((r) => r.data),
  });

  if (isLoading) return <div className="flex items-center justify-center h-64 text-slate-500">Loading...</div>;
  if (!alert) return <div className="text-red-400 p-8">Alert not found</div>;

  return (
    <div className="max-w-4xl mx-auto space-y-5 animate-fade-in">
      {/* Header */}
      <div>
        <button onClick={() => router.back()} className="flex items-center gap-1 text-sm text-slate-500 hover:text-slate-300 mb-3">
          <ChevronLeft className="w-4 h-4" /> Back to alerts
        </button>
        <div className="flex items-start gap-3">
          <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase flex-shrink-0 ${severityBadge(alert.severity)}`}>
            {alert.severity}
          </span>
          <div className="flex-1">
            <h1 className="text-xl font-bold text-white">{alert.title}</h1>
            <div className="flex items-center gap-4 mt-1">
              <span className="flex items-center gap-1 text-xs text-slate-500">
                <Clock className="w-3 h-3" /> {formatDateTime(alert.created_at)}
              </span>
              <span className="flex items-center gap-1 text-xs text-slate-500">
                <Monitor className="w-3 h-3" /> {alert.device_id}
              </span>
              {alert.mitre_tactic && (
                <span className="text-xs font-mono text-purple-400">{alert.mitre_tactic} › {alert.mitre_technique}</span>
              )}
            </div>
          </div>
        </div>
        <p className="text-sm text-slate-400 mt-3">{alert.description}</p>
      </div>

      {/* Pending Action Approval */}
      {alert.requires_approval && alert.pending_action && (
        <ActionApproval
          alertId={alert.id}
          pendingAction={alert.pending_action}
          onComplete={() => qc.invalidateQueries({ queryKey: ["alert", id] })}
        />
      )}

      {/* Auto-action banner */}
      {alert.auto_action_taken && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-sm text-red-400">
          <Shield className="w-4 h-4" />
          Autonomous action was taken due to imminent danger detection. Review audit logs for details.
        </div>
      )}

      {/* LLM Analysis */}
      {alert.llm_analysis ? (
        <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
          <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <Brain className="w-4 h-4 text-blue-400" />
            Gemma AI Analysis
          </h3>
          <LLMAnalysisPanel analysis={alert.llm_analysis} />
        </div>
      ) : (
        <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-8 text-center">
          <Brain className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="text-slate-500 text-sm">AI analysis pending or not available for this alert.</p>
        </div>
      )}
    </div>
  );
}
