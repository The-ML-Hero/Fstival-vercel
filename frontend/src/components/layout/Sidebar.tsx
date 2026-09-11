"use client";

import React from "react";
import {
  LayoutDashboard,
  Layers,
  UploadCloud,
  ShieldAlert,
  Activity,
  AlertTriangle,
  GitFork,
  Sparkles,
  Wrench,
  History,
  Settings,
  ShieldCheck,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { ViewMode } from "@/types";

interface NavItem {
  id: ViewMode;
  label: string;
  icon: React.ElementType;
  badge?: number | string;
  badgeColor?: string;
}

export const Sidebar: React.FC = () => {
  const { activeView, setActiveView, findings } = useApp();

  const activeIssuesCount = findings.filter(
    (f) => f.status === "confirmed" && f.verification_status !== "fixed"
  ).length;

  const navItems: NavItem[] = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "api-overview", label: "APIs", icon: Layers },
    { id: "api-import", label: "Import", icon: UploadCloud },
    { id: "attack-center", label: "Attack Center", icon: ShieldAlert },
    { id: "live-simulation", label: "Live Simulation", icon: Activity },
    {
      id: "vulnerabilities",
      label: "Vulnerabilities",
      icon: AlertTriangle,
      badge: activeIssuesCount > 0 ? activeIssuesCount : undefined,
      badgeColor: "bg-rose-500 text-white",
    },
    { id: "attack-graph", label: "Attack Path", icon: GitFork },
    { id: "ai-analyst", label: "AI Analyst", icon: Sparkles },
    { id: "fix-center", label: "Fix Center", icon: Wrench },
    { id: "history", label: "History", icon: History },
    { id: "settings", label: "Settings", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#F5F5F7]/80 backdrop-blur-xl border-r border-black/[0.06] flex flex-col justify-between h-screen select-none">
      {/* Brand Header */}
      <div>
        <div className="p-6 flex items-center gap-3">
          <div className="w-8 h-8 rounded-apple bg-[#0071E3] text-white flex items-center justify-center shadow-[0_2px_8px_rgba(0,113,227,0.35)]">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-sm font-semibold text-[#1D1D1F] tracking-tight flex items-center gap-1.5">
              API Guardian
            </h1>
            <p className="text-[11px] text-[#86868B] font-medium tracking-tight">
              Security Simulator
            </p>
          </div>
        </div>

        {/* Navigation List */}
        <nav className="px-3 space-y-0.5 mt-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveView(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-apple text-xs font-medium transition-all duration-150 group ${
                  isActive
                    ? "bg-white text-[#1D1D1F] shadow-sm font-semibold"
                    : "text-[#6E6E73] hover:text-[#1D1D1F] hover:bg-black/[0.03]"
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon
                    className={`w-4 h-4 transition-colors ${
                      isActive ? "text-[#0071E3]" : "text-[#86868B] group-hover:text-[#1D1D1F]"
                    }`}
                  />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span
                    className={`text-[10px] font-bold px-1.5 py-0.2 rounded-full ${
                      item.badgeColor || "bg-black/[0.06] text-[#6E6E73]"
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer info capsule */}
      <div className="p-4 border-t border-black/[0.04] m-3 bg-white/60 rounded-apple border border-black/[0.04]">
        <div className="flex items-center justify-between text-[11px]">
          <span className="text-[#86868B]">Engine</span>
          <span className="font-semibold text-emerald-600 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Active v3.0
          </span>
        </div>
      </div>
    </aside>
  );
};
