"use client";

import React, { useState } from "react";
import {
  History,
  TrendingUp,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  GitCompare,
  ArrowRight,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { Badge } from "@/components/ui/Badge";
import { MetricCard } from "@/components/ui/MetricCard";
import { MOCK_HISTORY } from "@/lib/mock/mockData";

export const SecurityHistoryView: React.FC = () => {
  const { securityScore } = useApp();
  const [selectedScan, setSelectedScan] = useState<string>("run-today");

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
          Audit &amp; Trend Analytics
        </h2>
        <h1 className="text-2xl font-bold text-[#1D1D1F] tracking-tight mt-0.5">
          Security History
        </h1>
        <p className="text-xs text-[#6E6E73] mt-1">
          Chronological security posture history, score trends, and cross-scan regression tracking.
        </p>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <MetricCard
          label="Current Health Score"
          value={`${securityScore}/100`}
          subtext="Posture rating"
          trend="+12 pts this week"
          trendPositive={true}
          icon={<TrendingUp className="w-4 h-4 text-emerald-500" />}
        />
        <MetricCard
          label="Total Scans Executed"
          value="4"
          subtext="Last scan 2 mins ago"
          icon={<History className="w-4 h-4" />}
        />
        <MetricCard
          label="Regressions Detected"
          value="0"
          subtext="No re-opened issues"
          trend="Clean"
          trendPositive={true}
          icon={<ShieldCheck className="w-4 h-4 text-blue-500" />}
        />
      </div>

      {/* Historical Score Progression Trend */}
      <div className="bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
        <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight">
          Score Progression Timeline
        </h3>

        {/* Minimal Apple Bar Chart */}
        <div className="flex items-end justify-between gap-4 h-44 pt-6 px-4 pb-2 border-b border-black/[0.06]">
          {MOCK_HISTORY.slice().reverse().map((scan) => {
            const heightPercent = Math.max(20, scan.security_score);
            return (
              <div
                key={scan.run_id}
                className="flex-1 flex flex-col items-center gap-2 group cursor-pointer"
                onClick={() => setSelectedScan(scan.run_id)}
              >
                <span className="text-[11px] font-bold text-[#1D1D1F] group-hover:text-[#0071E3] transition-colors">
                  {scan.security_score}
                </span>
                <div className="w-full max-w-[48px] bg-[#F5F5F7] rounded-t-apple overflow-hidden h-32 flex items-end">
                  <div
                    className="w-full bg-[#0071E3] rounded-t-apple group-hover:bg-[#0077ED] transition-all duration-300"
                    style={{ height: `${heightPercent}%` }}
                  />
                </div>
                <span className="text-[10px] text-[#86868B] text-center font-medium">
                  {scan.scanned_at.split(",")[0]}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Chronological Scan Timeline List */}
      <div className="bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
        <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight">
          Scan Event Timeline
        </h3>

        <div className="divide-y divide-black/[0.04]">
          {MOCK_HISTORY.map((item) => (
            <div
              key={item.run_id}
              className="py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-start gap-3.5">
                <div className="w-8 h-8 rounded-full bg-blue-50 text-[#0071E3] flex items-center justify-center mt-0.5">
                  <History className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-[#1D1D1F]">
                      {item.scanned_at}
                    </span>
                    <Badge
                      variant={item.ci_gate_status === "passed" ? "success" : "critical"}
                      size="sm"
                    >
                      CI GATE: {item.ci_gate_status.toUpperCase()}
                    </Badge>
                  </div>
                  <p className="text-xs text-[#6E6E73] mt-0.5">
                    {item.critical_count} Critical · {item.high_count} High · {item.fixed_count} Fixed
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <div className="text-right">
                  <span className="text-xs text-[#86868B] block">Score</span>
                  <span className="text-sm font-bold text-emerald-600">
                    {item.security_score} / 100
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
