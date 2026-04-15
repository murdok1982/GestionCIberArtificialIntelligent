"use client";
import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { Monitor, Plus, Trash2, RefreshCw, Wifi, WifiOff, AlertTriangle, Copy, Check } from "lucide-react";
import { devicesApi } from "@/lib/api";
import { formatRelativeTime, getOSIcon, statusColor } from "@/lib/utils";
import type { Device, OSType } from "@/types";

const STATUS_ICONS: Record<string, React.ReactNode> = {
  online: <Wifi className="w-3.5 h-3.5 text-emerald-400" />,
  offline: <WifiOff className="w-3.5 h-3.5 text-slate-500" />,
  warning: <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />,
  critical: <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
};

function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    online: "bg-emerald-400",
    offline: "bg-slate-600",
    warning: "bg-amber-400",
    critical: "bg-red-400",
  };
  return (
    <span className={`inline-block w-2 h-2 rounded-full ${colors[status] ?? "bg-slate-600"} ${status === "online" ? "animate-pulse" : ""}`} />
  );
}

function AddDeviceModal({ onClose, onCreated }: { onClose: () => void; onCreated: (token: string, cmd: string) => void }) {
  const [hostname, setHostname] = useState("");
  const [os, setOs] = useState<OSType>("linux");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostname.trim()) return;
    setLoading(true);
    setError("");
    try {
      const res = await devicesApi.create({ hostname: hostname.trim(), os });
      onCreated(res.data.agent_token, res.data.install_command);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Failed to create device");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0F1629] border border-[#1E2D47] rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <h3 className="text-lg font-semibold text-white mb-4">Register New Device</h3>
        {error && <p className="text-red-400 text-sm mb-3">{error}</p>}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">Hostname</label>
            <input
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="server-prod-01"
              className="w-full px-3 py-2.5 bg-[#141B2D] border border-[#1E2D47] rounded-lg text-white placeholder-slate-600 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-sm text-slate-400 mb-1.5">Operating System</label>
            <select
              value={os}
              onChange={(e) => setOs(e.target.value as OSType)}
              className="w-full px-3 py-2.5 bg-[#141B2D] border border-[#1E2D47] rounded-lg text-white focus:outline-none focus:border-blue-500"
            >
              <option value="linux">🐧 Linux</option>
              <option value="windows">🪟 Windows</option>
              <option value="macos">🍎 macOS</option>
            </select>
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose} className="flex-1 py-2 border border-[#1E2D47] text-slate-400 rounded-lg hover:bg-[#141B2D] transition-colors text-sm">Cancel</button>
            <button type="submit" disabled={loading || !hostname.trim()} className="flex-1 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors text-sm font-medium">
              {loading ? "Creating..." : "Create & Get Token"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function TokenModal({ token, command, onClose }: { token: string; command: string; onClose: () => void }) {
  const [copied, setCopied] = useState<"token" | "cmd" | null>(null);
  const copy = async (text: string, type: "token" | "cmd") => {
    await navigator.clipboard.writeText(text);
    setCopied(type);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-[#0F1629] border border-[#1E2D47] rounded-2xl p-6 w-full max-w-lg shadow-2xl">
        <div className="flex items-center gap-2 mb-4">
          <div className="p-2 bg-amber-500/20 rounded-lg"><AlertTriangle className="w-4 h-4 text-amber-400" /></div>
          <h3 className="text-lg font-semibold text-white">Save Your Agent Token</h3>
        </div>
        <p className="text-sm text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2 mb-4">
          ⚠️ This token is shown only once. Copy it now — it cannot be retrieved later.
        </p>
        <div className="space-y-3">
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-slate-500">Agent Token</span>
              <button onClick={() => copy(token, "token")} className="text-xs text-blue-400 flex items-center gap-1">
                {copied === "token" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copied === "token" ? "Copied!" : "Copy"}
              </button>
            </div>
            <pre className="font-hash text-emerald-400 bg-[#141B2D] border border-[#1E2D47] rounded p-2 text-xs break-all whitespace-pre-wrap">{token}</pre>
          </div>
          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-slate-500">Install Command</span>
              <button onClick={() => copy(command, "cmd")} className="text-xs text-blue-400 flex items-center gap-1">
                {copied === "cmd" ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copied === "cmd" ? "Copied!" : "Copy"}
              </button>
            </div>
            <pre className="font-hash text-slate-300 bg-[#141B2D] border border-[#1E2D47] rounded p-2 text-xs break-all whitespace-pre-wrap">{command}</pre>
          </div>
        </div>
        <button onClick={onClose} className="w-full mt-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors">
          Done — I saved the token
        </button>
      </div>
    </div>
  );
}

export default function DevicesPage() {
  const qc = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [newToken, setNewToken] = useState<{ token: string; command: string } | null>(null);
  const [filter, setFilter] = useState<string>("all");

  const { data: devices = [], isLoading, refetch } = useQuery<Device[]>({
    queryKey: ["devices"],
    queryFn: () => devicesApi.list().then((r) => r.data),
    refetchInterval: 30000,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => devicesApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["devices"] }),
  });

  const filtered = filter === "all" ? devices : devices.filter((d) => d.status === filter);

  const handleCreated = (token: string, command: string) => {
    setShowAdd(false);
    setNewToken({ token, command });
    qc.invalidateQueries({ queryKey: ["devices"] });
  };

  const counts = {
    online: devices.filter((d) => d.status === "online").length,
    offline: devices.filter((d) => d.status === "offline").length,
    warning: devices.filter((d) => d.status === "warning").length,
    critical: devices.filter((d) => d.status === "critical").length,
  };

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-white">Monitored Endpoints</h2>
          <p className="text-sm text-slate-500">{devices.length} registered devices</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => refetch()} className="p-2 rounded-lg border border-[#1E2D47] text-slate-400 hover:text-slate-200 hover:bg-[#141B2D] transition-all">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button
            onClick={() => setShowAdd(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" /> Add Device
          </button>
        </div>
      </div>

      {/* Status filter pills */}
      <div className="flex gap-2 flex-wrap">
        {([["all", `All (${devices.length})`], ["online", `Online (${counts.online})`], ["offline", `Offline (${counts.offline})`], ["warning", `Warning (${counts.warning})`], ["critical", `Critical (${counts.critical})`]] as [string, string][]).map(([val, label]) => (
          <button
            key={val}
            onClick={() => setFilter(val)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${filter === val ? "bg-blue-600 text-white" : "bg-[#141B2D] border border-[#1E2D47] text-slate-400 hover:text-slate-200"}`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="bg-[#141B2D] border border-[#1E2D47] rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-slate-500">Loading devices...</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center">
            <Monitor className="w-10 h-10 text-slate-700 mx-auto mb-3" />
            <p className="text-slate-400 font-medium">No devices found</p>
            <p className="text-slate-600 text-sm mt-1">Add your first endpoint to start monitoring</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1E2D47]">
                {["Status", "Hostname", "OS", "IP Address", "Agent Version", "Last Seen", ""].map((h) => (
                  <th key={h} className="text-left text-xs font-medium text-slate-500 uppercase tracking-wider px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E2D47]">
              {filtered.map((device) => (
                <tr key={device.id} className="hover:bg-[#0F1629] transition-colors group">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <StatusDot status={device.status} />
                      <span className={`text-xs capitalize ${statusColor(device.status)}`}>{device.status}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Link href={`/devices/${device.id}`} className="text-sm text-white hover:text-blue-400 font-medium">
                      {device.hostname}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-sm">{getOSIcon(device.os)} <span className="text-slate-400 ml-1 capitalize">{device.os}</span></td>
                  <td className="px-4 py-3 font-hash text-slate-400 text-xs">{device.ip_address ?? "—"}</td>
                  <td className="px-4 py-3 font-hash text-slate-400 text-xs">{device.agent_version ?? "—"}</td>
                  <td className="px-4 py-3 text-xs text-slate-500">{formatRelativeTime(device.last_seen)}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => { if (confirm(`Remove ${device.hostname}?`)) deleteMutation.mutate(device.id); }}
                      className="opacity-0 group-hover:opacity-100 p-1.5 text-slate-600 hover:text-red-400 hover:bg-red-500/10 rounded transition-all"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showAdd && <AddDeviceModal onClose={() => setShowAdd(false)} onCreated={handleCreated} />}
      {newToken && <TokenModal token={newToken.token} command={newToken.command} onClose={() => setNewToken(null)} />}
    </div>
  );
}
