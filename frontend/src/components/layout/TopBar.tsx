"use client";

import React from "react";
import { Search, Command, RefreshCw } from "lucide-react";
import { useApp } from "@/context/AppContext";

export const TopBar: React.FC = () => {
  const { project, securityScore, setIsCommandMenuOpen, refreshData } = useApp();

  return (
    <header className="h-14 bg-white/80 backdrop-blur-md border-b border-black/[0.06] px-6 flex items-center justify-between sticky top-0 z-30 select-none">
      {/* Left: Project & Environment */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-sm text-[#1D1D1F] tracking-tight">
            {project.name}
          </span>
          <span className="text-xs text-[#86868B]">/</span>
        </div>

        {/* Environment Badge */}
        <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200/80 text-xs font-medium">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          <span>Local Simulation</span>
        </div>
      </div>

      {/* Right: Security Score Capsule, Search & Refresh */}
      <div className="flex items-center gap-3">
        {/* Quick Search / Command Trigger */}
        <button
          onClick={() => setIsCommandMenuOpen(true)}
          className="flex items-center gap-2 px-3 py-1.5 text-xs text-[#6E6E73] bg-[#F5F5F7] hover:bg-[#EAEAEA] border border-black/[0.04] rounded-apple transition-colors"
        >
          <Search className="w-3.5 h-3.5 text-[#86868B]" />
          <span>Search or jump to...</span>
          <kbd className="hidden sm:inline-flex items-center gap-0.5 text-[10px] font-mono bg-white px-1.5 py-0.2 rounded border border-black/[0.08] text-[#86868B]">
            <Command className="w-2.5 h-2.5" /> K
          </kbd>
        </button>

        {/* Live Score Capsule */}
        <div className="flex items-center gap-2 px-3 py-1 bg-[#F5F5F7] rounded-full border border-black/[0.05]">
          <span className="text-xs text-[#6E6E73] font-medium">Security</span>
          <span className="text-xs font-bold text-emerald-600 bg-white px-2 py-0.5 rounded-full shadow-sm">
            {securityScore}
          </span>
        </div>

        {/* Refresh button */}
        <button
          onClick={refreshData}
          title="Refresh Data"
          className="p-1.5 text-[#86868B] hover:text-[#1D1D1F] hover:bg-[#F5F5F7] rounded-full transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      </div>
    </header>
  );
};
