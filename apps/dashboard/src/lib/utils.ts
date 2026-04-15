import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import { formatDistanceToNow, format } from "date-fns";
import type { Severity } from "@/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return "Never";
  try {
    return formatDistanceToNow(new Date(dateStr), { addSuffix: true });
  } catch {
    return dateStr;
  }
}

export function formatDateTime(dateStr: string | null): string {
  if (!dateStr) return "—";
  try {
    return format(new Date(dateStr), "yyyy-MM-dd HH:mm:ss");
  } catch {
    return dateStr;
  }
}

export function formatFileSize(bytes: number | null): string {
  if (!bytes) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  return `${size.toFixed(1)} ${units[unit]}`;
}

export function severityColor(severity: Severity | string): string {
  const map: Record<string, string> = {
    critical: "text-red-400 bg-red-950 border-red-800",
    high: "text-orange-400 bg-orange-950 border-orange-800",
    medium: "text-amber-400 bg-amber-950 border-amber-800",
    low: "text-emerald-400 bg-emerald-950 border-emerald-800",
    info: "text-slate-400 bg-slate-800 border-slate-700",
  };
  return map[severity] ?? map.info;
}

export function severityBadge(severity: Severity | string): string {
  const map: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium: "bg-amber-500/20 text-amber-400 border border-amber-500/30",
    low: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
    info: "bg-slate-500/20 text-slate-400 border border-slate-500/30",
  };
  return map[severity] ?? map.info;
}

export function statusColor(status: string): string {
  const map: Record<string, string> = {
    online: "text-emerald-400",
    offline: "text-slate-500",
    warning: "text-amber-400",
    critical: "text-red-400",
    open: "text-red-400",
    investigating: "text-amber-400",
    resolved: "text-emerald-400",
    false_positive: "text-slate-400",
    active: "text-emerald-400",
    past_due: "text-red-400",
    canceled: "text-slate-400",
    trialing: "text-blue-400",
  };
  return map[status] ?? "text-slate-400";
}

export function truncateHash(hash: string, chars = 16): string {
  return `${hash.substring(0, chars)}...`;
}

export function getOSIcon(os: string): string {
  const map: Record<string, string> = {
    windows: "🪟",
    linux: "🐧",
    macos: "🍎",
  };
  return map[os] ?? "💻";
}
