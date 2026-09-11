"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  Play,
  KeyRound,
  UserCheck,
  FileCode2,
  Workflow,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Info,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Modal } from "@/components/ui/Modal";
import { MOCK_ATTACK_CATEGORIES } from "@/lib/mock/mockData";

export const AttackCenterView: React.FC = () => {
  const { project, startSimulation, setActiveView, attackCategories, attackPlanCount } = useApp();
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);

  const currentCategories =
    attackCategories && attackCategories.length > 0 ? attackCategories : MOCK_ATTACK_CATEGORIES;

  const getIcon = (iconName: string) => {
    switch (iconName) {
      case "ShieldAlert":
        return ShieldAlert;
      case "KeyRound":
        return KeyRound;
      case "UserCheck":
        return UserCheck;
      case "FileCode2":
        return FileCode2;
      case "Workflow":
        return Workflow;
      case "Zap":
        return Zap;
      default:
        return ShieldAlert;
    }
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header & Main Launch CTA */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
            Automated Simulation Engine
          </h2>
          <h1 className="text-2xl font-bold text-[#1D1D1F] tracking-tight mt-0.5">
            Attack Center
          </h1>
          <p className="text-xs text-[#6E6E73] mt-1">
            Test your API for real-world security weaknesses using adaptive attack planning.
          </p>
        </div>

        <Button
          variant="primary"
          onClick={() => setIsConfirmModalOpen(true)}
          icon={<Play className="w-4 h-4" />}
        >
          Start Security Simulation
        </Button>
      </div>

      {/* Categorized Test Suites Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {currentCategories.map((cat) => {
          const Icon = getIcon(cat.icon);
          return (
            <div
              key={cat.category}
              className="bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card hover:shadow-apple-hover transition-all duration-200 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between">
                  <div className="w-10 h-10 rounded-apple bg-[#F5F5F7] text-[#1D1D1F] flex items-center justify-center">
                    <Icon className="w-5 h-5 text-[#0071E3]" />
                  </div>
                  <Badge variant={cat.severity}>{cat.severity.toUpperCase()}</Badge>
                </div>

                <h3 className="text-sm font-bold text-[#1D1D1F] mt-4 tracking-tight">
                  {cat.name}
                </h3>
                <p className="text-xs text-[#6E6E73] mt-1 line-clamp-2">
                  {cat.description}
                </p>
              </div>

              <div className="pt-6 border-t border-black/[0.04] mt-6 flex items-center justify-between">
                <span className="text-xs text-[#86868B] font-medium">
                  {cat.attack_count} automated tests
                </span>
                <span
                  className={`text-xs font-semibold ${
                    cat.potential_issues > 0 ? "text-amber-600" : "text-emerald-600"
                  }`}
                >
                  {cat.potential_issues > 0
                    ? `${cat.potential_issues} potential issue`
                    : "No issues"}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Confirmation Modal */}
      <Modal
        isOpen={isConfirmModalOpen}
        onClose={() => setIsConfirmModalOpen(false)}
        title="Confirm Security Simulation"
        subtitle="Controlled execution through local Bruno runner"
        maxWidth="md"
      >
        <div className="space-y-4">
          <div className="bg-[#F5F5F7] rounded-apple p-4 space-y-2.5 text-xs">
            <div className="flex justify-between">
              <span className="text-[#86868B]">Target API:</span>
              <span className="font-semibold text-[#1D1D1F]">{project.name}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#86868B]">Environment:</span>
              <span className="font-semibold text-emerald-600">Local (Controlled)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#86868B]">Test Mode:</span>
              <span className="font-semibold text-[#1D1D1F]">Adaptive &amp; Workflow-aware</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#86868B]">Planned Attacks:</span>
              <span className="font-semibold text-[#0071E3]">{attackPlanCount} Scenarios</span>
            </div>
          </div>

          <div className="flex items-center gap-2 text-[11px] text-[#6E6E73] bg-blue-50/60 p-3 rounded-apple border border-blue-100">
            <Info className="w-4 h-4 text-[#0071E3] flex-shrink-0" />
            <span>
              All requests are executed within safety guardrails with sensitive tokens automatically masked.
            </span>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsConfirmModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={() => {
                setIsConfirmModalOpen(false);
                startSimulation();
              }}
              icon={<Play className="w-3.5 h-3.5" />}
            >
              Start Simulation
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
