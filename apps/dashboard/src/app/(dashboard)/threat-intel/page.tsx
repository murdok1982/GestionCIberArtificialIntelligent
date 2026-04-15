"use client";
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Globe, Search, AlertTriangle, ShieldCheck, Loader2 } from "lucide-react";
import { threatIntelApi } from "@/lib/api";
import type { IOCEnrichment } from "@/types";

type IOCType = "ip" | "hash" | "domain";

function RiskBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.round(score * 10));
  const color = pct >= 70 ? "bg-red-500" : pct >= 40 ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-[#1E2D47] rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-400 w-8">{score.toFixed(1)}</span>
    </div>
  );
}

export default function ThreatIntelPage() {
  const [iocType, setIocType] = useState<IOCType>("ip");
  const [value, setValue] = useState("");
  const [result, setResult] = useState<IOCEnrichment | null>(null);

  const enrichMutation = useMutation({
    mutationFn: () => threatIntelApi.enrich({ ioc_type: iocType, value: value.trim() }),
    onSuccess: (res) => setResult(res.data),
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) return;
    setResult(null);
    enrichMutation.mutate();
  };

  const placeholders: Record<IOCType, string> = {
    ip: "e.g. 192.168.1.1 or 1.2.3.4",
    hash: "MD5, SHA-1, or SHA-256 hash",
    domain: "e.g. malicious-domain.com",
  };

  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <div>
        <h2 className="text-lg font-semibold text-white">Threat Intelligence</h2>
        <p className="text-sm text-slate-500">Enrich IOCs via AbuseIPDB, VirusTotal, and campaign correlation</p>
      </div>

      {/* Search form */}
      <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
        <form onSubmit={handleSearch} className="space-y-4">
          <div className="flex gap-2">
            {(["ip", "hash", "domain"] as IOCType[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => { setIocType(t); setResult(null); setValue(""); }}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors uppercase ${iocType === t ? "bg-blue-600 text-white" : "bg-[#0F1629] border border-[#1E2D47] text-slate-400 hover:text-slate-200"}`}
              >
                {t}
              </button>
            ))}
          </div>
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={placeholders[iocType]}
                className="w-full pl-9 pr-4 py-2.5 bg-[#0F1629] border border-[#1E2D47] rounded-lg text-white placeholder-slate-600 focus:outline-none focus:border-blue-500 font-hash text-sm"
              />
            </div>
            <button
              type="submit"
              disabled={enrichMutation.isPending || !value.trim()}
              className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg font-medium text-sm transition-colors flex items-center gap-2"
            >
              {enrichMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
              Enrich
            </button>
          </div>
        </form>
      </div>

      {/* Result */}
      {enrichMutation.isError && (
        <div className="flex items-center gap-2 p-4 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-sm">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          Enrichment failed. Check API keys in settings.
        </div>
      )}

      {result && (
        <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5 space-y-4 animate-fade-in">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-mono text-white font-semibold">{result.value}</h3>
              <span className="text-xs text-slate-500 capitalize">{result.type} enrichment</span>
            </div>
            {result.risk_score >= 7 ? (
              <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 border border-red-500/30 rounded-lg">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span className="text-red-400 text-sm font-semibold">High Risk</span>
              </div>
            ) : result.risk_score >= 4 ? (
              <div className="flex items-center gap-2 px-3 py-1.5 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span className="text-amber-400 text-sm font-semibold">Medium Risk</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span className="text-emerald-400 text-sm font-semibold">Low Risk</span>
              </div>
            )}
          </div>

          <div>
            <p className="text-xs text-slate-500 mb-1.5">Risk Score (0–10)</p>
            <RiskBar score={result.risk_score} />
          </div>

          <div className="grid grid-cols-2 gap-3 text-sm">
            {result.abuse_confidence !== undefined && (
              <div className="bg-[#0F1629] rounded-lg p-3 border border-[#1E2D47]">
                <p className="text-xs text-slate-500 mb-0.5">Abuse Confidence</p>
                <p className="text-white font-semibold">{result.abuse_confidence}%</p>
              </div>
            )}
            {result.country && (
              <div className="bg-[#0F1629] rounded-lg p-3 border border-[#1E2D47]">
                <p className="text-xs text-slate-500 mb-0.5">Country</p>
                <p className="text-white font-semibold">{result.country}</p>
              </div>
            )}
            {result.isp && (
              <div className="bg-[#0F1629] rounded-lg p-3 border border-[#1E2D47]">
                <p className="text-xs text-slate-500 mb-0.5">ISP / Organization</p>
                <p className="text-white font-semibold">{result.isp}</p>
              </div>
            )}
            {result.is_tor !== undefined && (
              <div className="bg-[#0F1629] rounded-lg p-3 border border-[#1E2D47]">
                <p className="text-xs text-slate-500 mb-0.5">TOR Exit Node</p>
                <p className={result.is_tor ? "text-red-400 font-semibold" : "text-emerald-400 font-semibold"}>
                  {result.is_tor ? "Yes ⚠️" : "No"}
                </p>
              </div>
            )}
            {result.malicious !== undefined && (
              <div className="bg-[#0F1629] rounded-lg p-3 border border-[#1E2D47]">
                <p className="text-xs text-slate-500 mb-0.5">VirusTotal Detections</p>
                <p className={result.malicious > 0 ? "text-red-400 font-semibold" : "text-emerald-400 font-semibold"}>
                  {result.malicious} malicious
                </p>
              </div>
            )}
            {result.threat_label && (
              <div className="bg-[#0F1629] rounded-lg p-3 border border-[#1E2D47]">
                <p className="text-xs text-slate-500 mb-0.5">Threat Label</p>
                <p className="text-red-400 font-semibold">{result.threat_label}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Info panel */}
      <div className="text-xs text-slate-600 space-y-1">
        <p>• IP enrichment: AbuseIPDB (abuse confidence, TOR detection, country)</p>
        <p>• Hash enrichment: VirusTotal (malware detection ratio, threat classification)</p>
        <p>• Results cached for 1 hour to minimize API usage</p>
        <p>• Configure API keys in Settings → Integrations</p>
      </div>
    </div>
  );
}
