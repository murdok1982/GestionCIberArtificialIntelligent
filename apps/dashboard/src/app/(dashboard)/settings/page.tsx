"use client";
import { useState } from "react";
import { useAuthStore } from "@/store/authStore";
import { Settings, Key, Bell, Globe, Shield } from "lucide-react";

export default function SettingsPage() {
  const { user } = useAuthStore();
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="max-w-2xl space-y-6 animate-fade-in">
      <div>
        <h2 className="text-lg font-semibold text-white">Settings</h2>
        <p className="text-sm text-slate-500">Manage your account and organization preferences</p>
      </div>

      {/* Profile */}
      <section className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Settings className="w-4 h-4 text-blue-400" /> Profile
        </h3>
        <div className="space-y-3">
          <div>
            <label className="block text-xs text-slate-500 mb-1.5">Full Name</label>
            <input defaultValue={user?.full_name} className="w-full px-3 py-2 bg-[#0F1629] border border-[#1E2D47] rounded-lg text-white text-sm focus:outline-none focus:border-blue-500" />
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1.5">Email</label>
            <input defaultValue={user?.email} disabled className="w-full px-3 py-2 bg-[#0F1629] border border-[#1E2D47] rounded-lg text-slate-500 text-sm cursor-not-allowed" />
            <p className="text-xs text-slate-600 mt-1">Email cannot be changed. Contact support if needed.</p>
          </div>
          <div>
            <label className="block text-xs text-slate-500 mb-1.5">Role</label>
            <div className="px-3 py-2 bg-[#0F1629] border border-[#1E2D47] rounded-lg text-slate-400 text-sm capitalize">{user?.role}</div>
          </div>
        </div>
      </section>

      {/* Security */}
      <section className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-400" /> Security
        </h3>
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-slate-500 mb-1.5">Change Password</label>
            <div className="space-y-2">
              <input type="password" placeholder="Current password" className="w-full px-3 py-2 bg-[#0F1629] border border-[#1E2D47] rounded-lg text-white text-sm placeholder-slate-600 focus:outline-none focus:border-blue-500" />
              <input type="password" placeholder="New password (min. 12 chars)" className="w-full px-3 py-2 bg-[#0F1629] border border-[#1E2D47] rounded-lg text-white text-sm placeholder-slate-600 focus:outline-none focus:border-blue-500" />
            </div>
          </div>
          <div className="flex items-center justify-between py-2 border-t border-[#1E2D47]">
            <div>
              <p className="text-sm text-white">Multi-Factor Authentication</p>
              <p className="text-xs text-slate-500">TOTP (Google Authenticator, Authy)</p>
            </div>
            <div className={`px-3 py-1 rounded-full text-xs font-medium ${user?.mfa_enabled ? "bg-emerald-500/20 text-emerald-400" : "bg-slate-700/50 text-slate-400"}`}>
              {user?.mfa_enabled ? "Enabled" : "Disabled"}
            </div>
          </div>
        </div>
      </section>

      {/* Integrations */}
      <section className="bg-[#141B2D] border border-[#1E2D47] rounded-xl p-5">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Globe className="w-4 h-4 text-blue-400" /> Threat Intel Integrations
        </h3>
        <div className="space-y-3">
          {[
            { label: "AbuseIPDB API Key", placeholder: "API key from abuseipdb.com" },
            { label: "VirusTotal API Key", placeholder: "API key from virustotal.com" },
          ].map(({ label, placeholder }) => (
            <div key={label}>
              <label className="block text-xs text-slate-500 mb-1.5">{label}</label>
              <input type="password" placeholder={placeholder} className="w-full px-3 py-2 bg-[#0F1629] border border-[#1E2D47] rounded-lg text-white text-sm placeholder-slate-600 focus:outline-none focus:border-blue-500" />
            </div>
          ))}
        </div>
      </section>

      <div className="flex justify-end">
        <button onClick={handleSave} className={`px-6 py-2 rounded-lg text-sm font-medium transition-all ${saved ? "bg-emerald-600 text-white" : "bg-blue-600 hover:bg-blue-700 text-white"}`}>
          {saved ? "✓ Saved" : "Save Changes"}
        </button>
      </div>
    </div>
  );
}
