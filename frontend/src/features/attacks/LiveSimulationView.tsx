"use client";

import React, { useState } from "react";
import {
  Activity,
  CheckCircle2,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ArrowRight,
  ShieldAlert,
  Clock,
  Terminal,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { MOCK_SIMULATION_EXECUTIONS } from "@/lib/mock/mockData";

export const LiveSimulationView: React.FC = () => {
  const {
    isSimulating,
    simulationProgress,
    setActiveView,
    findings,
    setSelectedFinding,
    attackPlanCount,
    simulationAttacks,
    project,
  } = useApp();

  const [expandedLogs, setExpandedLogs] = useState(false);

  const currentAttacks =
    simulationAttacks && simulationAttacks.length > 0
      ? simulationAttacks
      : MOCK_SIMULATION_EXECUTIONS;

  const totalProbes = attackPlanCount || currentAttacks.length || 24;
  const completedCount = Math.round((simulationProgress / 100) * totalProbes);
  const detectedFinding = findings.find((f) => f.severity === "critical") || findings[0];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Simulation Header */}
      <div className="bg-white rounded-apple-2xl p-8 border border-black/[0.06] shadow-apple-card space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-[#86868B] flex items-center gap-1.5">
              {isSimulating ? (
                <>
                  <span className="w-2 h-2 rounded-full bg-[#0071E3] animate-pulse" />
                  Live Execution Active
                </>
              ) : (
                <>
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  Simulation Completed
                </>
              )}
            </span>
            <h1 className="text-2xl font-bold text-[#1D1D1F] tracking-tight">
              {isSimulating
                ? "Security simulation running..."
                : "Security simulation completed"}
            </h1>
          </div>

          <div className="text-right">
            <span className="text-2xl font-bold text-[#1D1D1F]">
              {completedCount} <span className="text-[#86868B] text-base font-normal">/ {totalProbes}</span>
            </span>
            <p className="text-xs text-[#6E6E73] font-medium">{simulationProgress}% Finished</p>
          </div>
        </div>

        {/* Minimal Apple-style Linear Progress Bar */}
        <div className="w-full bg-[#E5E5EA] h-2.5 rounded-full overflow-hidden">
          <div
            className="bg-[#0071E3] h-full rounded-full transition-all duration-500 ease-out"
            style={{ width: `${Math.max(4, simulationProgress)}%` }}
          />
        </div>
      </div>

      {/* Discovered Vulnerability Alert Card */}
      {detectedFinding && simulationProgress > 40 && (
        <div className="p-6 rounded-apple-xl bg-rose-50/70 border border-rose-200/80 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4 animate-slide-up">
          <div className="flex items-start gap-3.5">
            <div className="w-9 h-9 rounded-full bg-rose-100 text-rose-600 flex items-center justify-center flex-shrink-0 mt-0.5">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-rose-700 uppercase tracking-wider">
                  Critical Finding Discovered
                </span>
                <Badge variant="critical">BOLA</Badge>
              </div>
              <h3 className="text-sm font-bold text-[#1D1D1F] mt-0.5">
                {detectedFinding.title}
              </h3>
              <p className="text-xs font-mono text-[#6E6E73] mt-0.5">
                {detectedFinding.method} {detectedFinding.endpoint}
              </p>
            </div>
          </div>

          <Button
            variant="danger"
            size="sm"
            onClick={() => {
              setSelectedFinding(detectedFinding);
              setActiveView("vulnerabilities");
            }}
            icon={<ArrowRight className="w-3.5 h-3.5" />}
          >
            Investigate Finding
          </Button>
        </div>
      )}

      {/* Real-time Attack Feed */}
      <div className="bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
        <div className="flex items-center justify-between border-b border-black/[0.04] pb-3">
          <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight">
            Attack Execution Sequence
          </h3>
          <span className="text-xs text-[#86868B] font-mono">Bruno Runner v1.4</span>
        </div>

        <div className="divide-y divide-black/[0.04]">
          {currentAttacks.map((atk, index) => {
            const isFinished = index <= completedCount / 4;
            return (
              <div
                key={atk.id}
                className="py-3 flex items-center justify-between gap-4"
              >
                <div className="flex items-center gap-3">
                  {atk.status === "passed" ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 flex-shrink-0" />
                  ) : atk.status === "failed" ? (
                    <AlertTriangle className="w-4 h-4 text-rose-500 flex-shrink-0" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-black/20 flex-shrink-0" />
                  )}

                  <div>
                    <span className="text-xs font-semibold text-[#1D1D1F]">
                      {atk.category} Probe
                    </span>
                    <span className="text-xs font-mono text-[#86868B] ml-2">
                      {atk.method} {atk.endpoint}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <span className="text-[11px] font-mono text-[#86868B]">
                    {atk.duration_ms}ms
                  </span>
                  <Badge
                    variant={
                      atk.status === "passed"
                        ? "success"
                        : atk.status === "failed"
                        ? "critical"
                        : "gray"
                    }
                    size="sm"
                  >
                    {atk.status.toUpperCase()}
                  </Badge>
                </div>
              </div>
            );
          })}
        </div>

        {/* Expandable Technical Details */}
        <div className="pt-4 border-t border-black/[0.04]">
          <button
            onClick={() => setExpandedLogs(!expandedLogs)}
            className="text-xs font-semibold text-[#0071E3] hover:underline flex items-center gap-1.5"
          >
            <Terminal className="w-3.5 h-3.5" />
            {expandedLogs ? "Hide Technical Details" : "Show Technical Details"}
            {expandedLogs ? (
              <ChevronUp className="w-3.5 h-3.5" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5" />
            )}
          </button>

          {expandedLogs && (
            <div className="mt-3 p-4 bg-[#1D1D1F] text-white/90 rounded-apple font-mono text-xs overflow-x-auto space-y-1.5 animate-fade-in">
              <p className="text-emerald-400">
                [BrunoRunner] Initializing collection runner for {project.name}...
              </p>
              <p className="text-white/70">
                [SafetyValidator] Verified local environment target ({project.target_base_url || "127.0.0.1"})
              </p>
              {currentAttacks.slice(0, 4).map((atk, idx) => (
                <React.Fragment key={atk.id || idx}>
                  <p className="text-white/70">
                    [Step {idx + 1}] {atk.method} {atk.endpoint} (Token: [REDACTED]) -&gt; HTTP{" "}
                    {atk.status === "failed" ? "200 OK (Unexpected)" : "403 Forbidden"} ({atk.duration_ms || 24}ms)
                  </p>
                  {atk.status === "failed" && (
                    <p className="text-rose-400">
                      [Assertion Error] Expected 403 Forbidden, Received 200 OK ({atk.category} Detected)
                    </p>
                  )}
                </React.Fragment>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
