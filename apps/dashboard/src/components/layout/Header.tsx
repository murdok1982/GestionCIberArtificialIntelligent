"use client";
import { Bell, RefreshCw } from "lucide-react";
import { usePathname } from "next/navigation";
import { useNotificationStore } from "@/store/notificationStore";

const pageTitles: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/devices": "Devices",
  "/alerts": "Alerts",
  "/forensics": "Forensics",
  "/threat-intel": "Threat Intelligence",
  "/billing": "Billing",
  "/settings": "Settings",
  "/reports": "Reports",
};

export function Header() {
  const pathname = usePathname();
  const { unreadCount, markAllAsRead } = useNotificationStore();

  const title = Object.entries(pageTitles).find(([key]) => pathname.startsWith(key))?.[1] ?? "CyberGuard";

  return (
    <header className="h-14 border-b border-[#1E2D47] bg-[#0F1629] flex items-center px-6 gap-4 flex-shrink-0">
      <h1 className="text-base font-semibold text-white flex-1">{title}</h1>

      <div className="flex items-center gap-2">
        <button
          onClick={() => window.location.reload()}
          className="p-2 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-[#141B2D] transition-all"
          title="Refresh"
        >
          <RefreshCw className="w-4 h-4" />
        </button>

        <button
          onClick={markAllAsRead}
          className="relative p-2 rounded-lg text-slate-500 hover:text-slate-300 hover:bg-[#141B2D] transition-all"
          title="Notifications"
        >
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500 severity-pulse" />
          )}
        </button>

        <div className="h-6 w-px bg-[#1E2D47]" />

        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-xs text-slate-500">Live</span>
        </div>
      </div>
    </header>
  );
}
