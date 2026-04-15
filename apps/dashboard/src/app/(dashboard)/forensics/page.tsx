"use client";
import { useState, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { Search, Upload, ShieldCheck, ShieldAlert, FileText, Download, RefreshCw } from "lucide-react";
import { forensicsApi } from "@/lib/api";
import { formatDateTime, formatFileSize, truncateHash } from "@/lib/utils";
import type { Evidence, EvidenceType } from "@/types";

const TYPE_ICONS: Record<EvidenceType, string> = {
  file: "📄", memory: "🧠", log: "📋", network_capture: "🌐", registry: "🗝️", process_dump: "⚙️",
};

function UploadModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [device_id, setDeviceId] = useState("");
  const [evidence_type, setEvidenceType] = useState<EvidenceType>("file");
  const [acquisition_method, setAcquisitionMethod] = useState("manual_upload");
  const [notes, setNotes] = useState("");
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file || !device_id.trim()) return;
    setUploading(true);
    setError("");
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("device_id", device_id.trim());
      fd.append("evidence_type", evidence_type);
      fd.append("acquisition_method", acquisition_method);
      if (notes) fd.append("notes", notes);
      await forensicsApi.uploadEvidence(fd);
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.response?.data?.detail || "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0F1629] border border-[#1E2D47] rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <h3 className="text-lg font-semibold text-white mb-4">Acquire Evidence</h3>
        {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
        <form onSubmit={handleUpload} className="space-y-3">
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">Device ID</label>
            <input value={device_id} onChange={(e) => setDeviceId(e.target.value)} placeholder="UUID of the source device" className="w-full px-3 py-2 bg-[#141B2D] border border-[#1E2D47] rounded-lg text-white text-sm placeholder-slate-600 focus:outline-none focus:border-blue-500" />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">Evidence Type</label>
            <select value={evidence_type} onChange={(e) => setEvidenceType(e.target.value as EvidenceType)} className="w-full px-3 py-2 bg-[#141B2D] border border-[#1E2D47] rounded-lg text-white text-sm focus:outline-none focus:border-blue-500">
              {(["file", "memory", "log", "network_capture", "registry", "process_dump"] as EvidenceType[]).map((t) => (
                <option key={t} value={t}>{TYPE_ICONS[t]} {t.replace("_", " ")}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">Acquisition Method</label>
            <input value={acquisition_method} onChange={(e) => setAcquisitionMethod(e.target.value)} className="w-full px-3 py-2 bg-[#141B2D] border border-[#1E2D47] rounded-lg text-white text-sm focus:outline-none focus:border-blue-500" />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">File</label>
            <input ref={fileRef} type="file" className="w-full text-sm text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:bg-blue-600/20 file:text-blue-400 file:text-xs cursor-pointer" />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">Notes (optional)</label>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} className="w-full px-3 py-2 bg-[#141B2D] border border-[#1E2D47] rounded-lg text-white text-sm placeholder-slate-600 focus:outline-none focus:border-blue-500 resize-none" />
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 py-2 border border-[#1E2D47] text-slate-400 rounded-lg hover:bg-[#141B2D] text-sm transition-colors">Cancel</button>
            <button type="submit" disabled={uploading || !device_id.trim()} className="flex-1 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors">
              {uploading ? "Uploading & hashing..." : "Acquire Evidence"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function ForensicsPage() {
  const qc = useQueryClient();
  const [showUpload, setShowUpload] = useState(false);

  const { data: evidence = [], isLoading, refetch } = useQuery<Evidence[]>({
    queryKey: ["evidence"],
    queryFn: () => forensicsApi.listEvidence().then((r) => r.data),
  });

  const verifyMutation = useMutation({
    mutationFn: (id: string) => forensicsApi.verifyIntegrity(id),
  });

  return (
    <div className="space-y-5 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Digital Forensics</h2>
          <p className="text-sm text-slate-500">{evidence.length} evidence items · All cryptographically verified</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => refetch()} className="p-2 rounded-lg border border-[#1E2D47] text-slate-400 hover:text-slate-200 hover:bg-[#141B2D] transition-all">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={() => setShowUpload(true)} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
            <Upload className="w-4 h-4" /> Acquire Evidence
          </button>
        </div>
      </div>

      <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-slate-500">Loading evidence...</div>
        ) : evidence.length === 0 ? (
          <div className="p-12 text-center">
            <Search className="w-10 h-10 text-slate-700 mx-auto mb-3" />
            <p className="text-slate-400 font-medium">No evidence collected yet</p>
            <p className="text-slate-600 text-sm mt-1">Acquire your first evidence artifact to begin</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1E2D47]">
                {["Type", "Filename", "SHA-256", "Size", "Method", "Acquired", "Integrity", ""].map((h) => (
                  <th key={h} className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D47]">
              {evidence.map((ev) => (
                <tr key={ev.id} className="hover:bg-[#0F1629] transition-colors group">
                  <td className="px-4 py-3 text-lg">{TYPE_ICONS[ev.evidence_type]}</td>
                  <td className="px-4 py-3">
                    <p className="text-sm text-white font-medium">{ev.filename}</p>
                    <p className="font-hash text-xs text-slate-600">{ev.id.slice(0, 8)}…</p>
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-hash text-xs text-emerald-400" title={ev.sha256_hash}>
                      {truncateHash(ev.sha256_hash)}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-400">{formatFileSize(ev.file_size)}</td>
                  <td className="px-4 py-3 text-xs text-slate-400">{ev.acquisition_method}</td>
                  <td className="px-4 py-3 text-xs text-slate-500">{formatDateTime(ev.acquired_at)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => verifyMutation.mutate(ev.id)}
                      disabled={verifyMutation.isPending}
                      className="flex items-center gap-1 text-xs text-slate-400 hover:text-emerald-400 transition-colors"
                      title="Verify SHA-256 against stored file"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" /> Verify
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <Link href={`/forensics/evidence/${ev.id}`} className="opacity-0 group-hover:opacity-100 text-xs text-blue-400 hover:text-blue-300 transition-all">
                      Chain →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showUpload && <UploadModal onClose={() => setShowUpload(false)} onSuccess={() => qc.invalidateQueries({ queryKey: ["evidence"] })} />}
    </div>
  );
}
