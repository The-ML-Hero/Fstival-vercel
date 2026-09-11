"use client";

import React from "react";
import {
  ShieldAlert,
  Play,
  Wrench,
  ArrowRight,
  CheckCircle2,
  Clock,
  AlertTriangle,
  GitBranch,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { ScoreRing } from "@/components/ui/ScoreRing";
import { Button } from "@/components/ui/Button";
import { MetricCard } from "@/components/ui/MetricCard";

export const DashboardView: React.FC = () => {
  const {
    project,
    securityScore,
    findings,
    setActiveView,
    startSimulation,
    setSelectedFinding,
    attackPlanCount,
  } = useApp();

  const criticals = findings.filter(
    (f) => f.severity === "critical" && f.verification_status !== "fixed"
  ).length;
  const highs = findings.filter(
    (f) => f.severity === "high" && f.verification_status !== "fixed"
  ).length;
  const mediums = findings.filter(
    (f) => f.severity === "medium" && f.verification_status !== "fixed"
  ).length;
  const lows = findings.filter(
    (f) => f.severity === "low" && f.verification_status !== "fixed"
  ).length;

  const topCritical = findings.find(
    (f) => f.severity === "critical" && f.verification_status !== "fixed"
  );

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Top Welcome Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
            Good afternoon
          </h2>
          <h1 className="text-2xl font-bold text-[#1D1D1F] tracking-tight mt-0.5">
            {project.name}
          </h1>
        </div>

        {/* Quick Action Buttons */}
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setActiveView("attack-center")}
            icon={<ShieldAlert className="w-3.5 h-3.5 text-[#0071E3]" />}
          >
            View Attack Plan
          </Button>
          <Button
            variant="primary"
            size="sm"
            onClick={startSimulation}
            icon={<Play className="w-3.5 h-3.5" />}
          >
            Scan API
          </Button>
        </div>
      </div>

      {/* Main Score Hero & Severity Breakdown Card */}
      <div className="bg-white rounded-apple-2xl p-8 border border-black/[0.06] shadow-apple-card grid grid-cols-1 md:grid-cols-12 gap-8 items-center">
        {/* Left: Animated Score Ring */}
        <div className="md:col-span-5 flex flex-col items-center justify-center p-4 border-b md:border-b-0 md:border-r border-black/[0.06]">
          <ScoreRing score={securityScore} size={190} strokeWidth={14} />
        </div>

        {/* Right: Breakdown & Posture */}
        <div className="md:col-span-7 flex flex-col justify-center space-y-6">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
              Posture Breakdown
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-3">
              <div className="p-3.5 rounded-apple bg-[#F5F5F7] border border-black/[0.04] text-center">
                <span className="text-xl font-bold text-[#FF3B30]">{criticals}</span>
                <p className="text-[11px] text-[#6E6E73] font-medium mt-0.5">Critical</p>
              </div>
              <div className="p-3.5 rounded-apple bg-[#F5F5F7] border border-black/[0.04] text-center">
                <span className="text-xl font-bold text-[#FF9500]">{highs}</span>
                <p className="text-[11px] text-[#6E6E73] font-medium mt-0.5">High</p>
              </div>
              <div className="p-3.5 rounded-apple bg-[#F5F5F7] border border-black/[0.04] text-center">
                <span className="text-xl font-bold text-amber-600">{mediums}</span>
                <p className="text-[11px] text-[#6E6E73] font-medium mt-0.5">Medium</p>
              </div>
              <div className="p-3.5 rounded-apple bg-[#F5F5F7] border border-black/[0.04] text-center">
                <span className="text-xl font-bold text-[#34C759]">{lows}</span>
                <p className="text-[11px] text-[#6E6E73] font-medium mt-0.5">Low</p>
              </div>
            </div>
          </div>

          {/* Security Overview Alert Banner */}
          <div className="p-4 rounded-apple-lg bg-[#F5F5F7] border border-black/[0.06] flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-amber-100 text-amber-700 flex items-center justify-center flex-shrink-0">
                <AlertTriangle className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-semibold text-[#1D1D1F]">
                  {criticals > 0
                    ? `${criticals} critical issue needs immediate remediation`
                    : "Your API is mostly secure"}
                </h4>
                <p className="text-[11px] text-[#6E6E73]">
                  {topCritical
                    ? `BOLA vulnerability detected on ${topCritical.endpoint}`
                    : "Continuous simulation passed all major OWASP categories."}
                </p>
              </div>
            </div>

            {topCritical && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSelectedFinding(topCritical);
                  setActiveView("vulnerabilities");
                }}
              >
                Review Issue
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Grid: Recent Activity & Quick Navigation */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
        {/* Left: Recent Activity */}
        <div className="md:col-span-7 bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
          <div className="flex items-center justify-between border-b border-black/[0.04] pb-3">
            <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight">
              Recent Activity
            </h3>
            <button
              onClick={() => setActiveView("history")}
              className="text-xs text-[#0071E3] font-medium hover:underline flex items-center gap-1"
            >
              View Full History <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="w-7 h-7 rounded-full bg-blue-50 text-[#0071E3] flex items-center justify-center mt-0.5">
                <Play className="w-3.5 h-3.5" />
              </div>
              <div>
                <p className="text-xs font-medium text-[#1D1D1F]">
                  Security simulation completed
                </p>
                <p className="text-[11px] text-[#86868B] flex items-center gap-1 mt-0.5">
                  <Clock className="w-3 h-3" /> 2 minutes ago · 24 attacks executed
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-7 h-7 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mt-0.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
              </div>
              <div>
                <p className="text-xs font-medium text-[#1D1D1F]">
                  3 vulnerabilities fixed & verified
                </p>
                <p className="text-[11px] text-[#86868B] flex items-center gap-1 mt-0.5">
                  <Clock className="w-3 h-3" /> Yesterday · Score increased from 87 to 94
                </p>
              </div>
            </div>

            <div className="flex items-start gap-3">
              <div className="w-7 h-7 rounded-full bg-purple-50 text-purple-600 flex items-center justify-center mt-0.5">
                <GitBranch className="w-3.5 h-3.5" />
              </div>
              <div>
                <p className="text-xs font-medium text-[#1D1D1F]">
                  New OpenAPI specification parsed (v2.4)
                </p>
                <p className="text-[11px] text-[#86868B] flex items-center gap-1 mt-0.5">
                  <Clock className="w-3 h-3" /> 2 days ago · 9 endpoints mapped
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Quick Actions */}
        <div className="md:col-span-5 bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
          <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight border-b border-black/[0.04] pb-3">
            Quick Actions
          </h3>

          <div className="space-y-2.5">
            <button
              onClick={startSimulation}
              className="w-full p-3 rounded-apple bg-[#F5F5F7] hover:bg-[#EAEAEA] border border-black/[0.04] flex items-center justify-between text-left transition-colors group"
            >
              <div className="flex items-center gap-3">
                <Play className="w-4 h-4 text-[#0071E3]" />
                <div>
                  <span className="text-xs font-semibold text-[#1D1D1F] block">
                    Run Security Simulation
                  </span>
                  <span className="text-[11px] text-[#86868B]">
                    Execute {attackPlanCount} automated Bruno probes
                  </span>
                </div>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-[#86868B] group-hover:text-[#1D1D1F]" />
            </button>

            <button
              onClick={() => setActiveView("fix-center")}
              className="w-full p-3 rounded-apple bg-[#F5F5F7] hover:bg-[#EAEAEA] border border-black/[0.04] flex items-center justify-between text-left transition-colors group"
            >
              <div className="flex items-center gap-3">
                <Wrench className="w-4 h-4 text-emerald-600" />
                <div>
                  <span className="text-xs font-semibold text-[#1D1D1F] block">
                    Verify Fixes
                  </span>
                  <span className="text-[11px] text-[#86868B]">
                    Re-test patched endpoints for 403 checks
                  </span>
                </div>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-[#86868B] group-hover:text-[#1D1D1F]" />
            </button>

            <button
              onClick={() => setActiveView("attack-graph")}
              className="w-full p-3 rounded-apple bg-[#F5F5F7] hover:bg-[#EAEAEA] border border-black/[0.04] flex items-center justify-between text-left transition-colors group"
            >
              <div className="flex items-center gap-3">
                <GitBranch className="w-4 h-4 text-purple-600" />
                <div>
                  <span className="text-xs font-semibold text-[#1D1D1F] block">
                    Inspect Attack Path
                  </span>
                  <span className="text-[11px] text-[#86868B]">
                    Visualize multi-stage exploit graph
                  </span>
                </div>
              </div>
              <ArrowRight className="w-3.5 h-3.5 text-[#86868B] group-hover:text-[#1D1D1F]" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
