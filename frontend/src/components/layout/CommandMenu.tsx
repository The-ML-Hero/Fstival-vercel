"use client";

import React, { useState } from "react";
import {
  Search,
  LayoutDashboard,
  Layers,
  UploadCloud,
  ShieldAlert,
  AlertTriangle,
  GitFork,
  Sparkles,
  Wrench,
  History,
  Settings,
  X,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { ViewMode } from "@/types";

export const CommandMenu: React.FC = () => {
  const {
    isCommandMenuOpen,
    setIsCommandMenuOpen,
    setActiveView,
    startSimulation,
    findings,
    setSelectedFinding,
  } = useApp();
  const [query, setQuery] = useState("");

  if (!isCommandMenuOpen) return null;

  const actions = [
    {
      id: "nav-dashboard",
      title: "Go to Dashboard",
      category: "Navigation",
      icon: LayoutDashboard,
      run: () => setActiveView("dashboard"),
    },
    {
      id: "nav-api",
      title: "View API Overview & Endpoints",
      category: "Navigation",
      icon: Layers,
      run: () => setActiveView("api-overview"),
    },
    {
      id: "nav-import",
      title: "Import OpenAPI Specification",
      category: "Navigation",
      icon: UploadCloud,
      run: () => setActiveView("api-import"),
    },
    {
      id: "action-sim",
      title: "Start Security Simulation",
      category: "Actions",
      icon: ShieldAlert,
      run: () => startSimulation(),
    },
    {
      id: "nav-vulns",
      title: "View Security Findings",
      category: "Navigation",
      icon: AlertTriangle,
      run: () => setActiveView("vulnerabilities"),
    },
    {
      id: "nav-graph",
      title: "Explore Attack Graph & Chains",
      category: "Navigation",
      icon: GitFork,
      run: () => setActiveView("attack-graph"),
    },
    {
      id: "nav-ai",
      title: "Ask AI Security Analyst",
      category: "Intelligence",
      icon: Sparkles,
      run: () => setActiveView("ai-analyst"),
    },
    {
      id: "nav-fix",
      title: "Verify Fixes in Fix Center",
      category: "Remediation",
      icon: Wrench,
      run: () => setActiveView("fix-center"),
    },
    {
      id: "nav-history",
      title: "Check Scan History & Regressions",
      category: "Navigation",
      icon: History,
      run: () => setActiveView("history"),
    },
    {
      id: "nav-settings",
      title: "Configure Settings & Security Gates",
      category: "Navigation",
      icon: Settings,
      run: () => setActiveView("settings"),
    },
  ];

  const filteredActions = actions.filter((a) =>
    a.title.toLowerCase().includes(query.toLowerCase())
  );

  const filteredFindings = findings.filter(
    (f) =>
      f.title.toLowerCase().includes(query.toLowerCase()) ||
      f.endpoint.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-24 p-4">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/30 backdrop-blur-md"
        onClick={() => setIsCommandMenuOpen(false)}
      />

      {/* Palette Container */}
      <div className="relative w-full max-w-xl bg-white rounded-apple-xl shadow-apple-modal border border-black/[0.08] overflow-hidden z-10 animate-scale-up">
        {/* Search Input */}
        <div className="flex items-center px-4 py-3 border-b border-black/[0.06] gap-3">
          <Search className="w-4 h-4 text-[#86868B]" />
          <input
            type="text"
            placeholder="Type a command or search findings..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            className="w-full text-sm text-[#1D1D1F] placeholder-[#86868B] bg-transparent outline-none"
          />
          <button
            onClick={() => setIsCommandMenuOpen(false)}
            className="text-[#86868B] hover:text-[#1D1D1F]"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results List */}
        <div className="max-h-80 overflow-y-auto p-2 space-y-4">
          <div>
            <div className="text-[11px] font-semibold text-[#86868B] uppercase tracking-wider px-3 py-1">
              Quick Actions
            </div>
            <div className="space-y-0.5">
              {filteredActions.map((action) => {
                const Icon = action.icon;
                return (
                  <button
                    key={action.id}
                    onClick={() => {
                      action.run();
                      setIsCommandMenuOpen(false);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 text-xs font-medium text-[#1D1D1F] hover:bg-[#F5F5F7] rounded-apple transition-colors text-left"
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className="w-4 h-4 text-[#0071E3]" />
                      <span>{action.title}</span>
                    </div>
                    <span className="text-[10px] text-[#86868B]">
                      {action.category}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {filteredFindings.length > 0 && (
            <div>
              <div className="text-[11px] font-semibold text-[#86868B] uppercase tracking-wider px-3 py-1">
                Findings
              </div>
              <div className="space-y-0.5">
                {filteredFindings.slice(0, 3).map((f) => (
                  <button
                    key={f.id}
                    onClick={() => {
                      setSelectedFinding(f);
                      setActiveView("vulnerabilities");
                      setIsCommandMenuOpen(false);
                    }}
                    className="w-full flex items-center justify-between px-3 py-2 text-xs font-medium text-[#1D1D1F] hover:bg-[#F5F5F7] rounded-apple transition-colors text-left"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <span className="font-mono text-[10px] bg-rose-100 text-rose-700 px-1.5 py-0.5 rounded">
                        {f.type}
                      </span>
                      <span className="truncate">{f.title}</span>
                    </div>
                    <span className="text-[10px] text-[#86868B] font-mono">
                      {f.endpoint}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
