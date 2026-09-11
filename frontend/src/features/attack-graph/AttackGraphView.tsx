"use client";

import React, { useState } from "react";
import {
  GitFork,
  ArrowRight,
  ShieldAlert,
  User,
  Server,
  AlertTriangle,
  Database,
  Flame,
  Info,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { Drawer } from "@/components/ui/Drawer";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { MOCK_ATTACK_GRAPH, MOCK_ATTACK_CHAINS } from "@/lib/mock/mockData";
import { GraphNode } from "@/types";
import { generateDynamicAttackGraph } from "@/lib/dynamicGenerator";

export const AttackGraphView: React.FC = () => {
  const { setActiveView, setSelectedFinding, findings, endpoints, project } = useApp();
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const dynamicData =
    endpoints && endpoints.length > 0 && findings && findings.length > 0
      ? generateDynamicAttackGraph(findings, endpoints, project.name)
      : { graph: MOCK_ATTACK_GRAPH, chains: MOCK_ATTACK_CHAINS };

  const activeChain = dynamicData.chains[0] || MOCK_ATTACK_CHAINS[0];

  const getNodeIcon = (type: string) => {
    switch (type) {
      case "role":
        return User;
      case "endpoint":
        return Server;
      case "vulnerability":
        return AlertTriangle;
      case "resource":
        return Database;
      case "impact":
        return Flame;
      default:
        return Info;
    }
  };

  const getNodeColor = (type: string) => {
    switch (type) {
      case "role":
        return "bg-blue-50 border-blue-200 text-blue-700";
      case "endpoint":
        return "bg-purple-50 border-purple-200 text-purple-700";
      case "vulnerability":
        return "bg-rose-50 border-rose-200 text-rose-700";
      case "resource":
        return "bg-amber-50 border-amber-200 text-amber-700";
      case "impact":
        return "bg-red-100 border-red-300 text-red-900";
      default:
        return "bg-gray-50 border-gray-200 text-gray-700";
    }
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
            Compound Attack Path Analysis
          </h2>
          <h1 className="text-2xl font-bold text-[#1D1D1F] tracking-tight mt-0.5">
            Attack Path
          </h1>
          <p className="text-xs text-[#6E6E73] mt-1">
            Visualizes multi-stage exploit chains connecting caller roles, vulnerable endpoints, and sensitive data assets.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="critical">2 Critical Chains</Badge>
          <Badge variant="gray">7 Exploit Nodes</Badge>
        </div>
      </div>

      {/* Interactive System Flow Diagram Card */}
      <div className="bg-white rounded-apple-2xl p-8 border border-black/[0.06] shadow-apple-card space-y-6">
        <div className="flex items-center justify-between border-b border-black/[0.04] pb-4">
          <div>
            <h3 className="text-sm font-semibold text-[#1D1D1F]">
              Primary Exploit Chain: {activeChain.title}
            </h3>
            <p className="text-xs text-[#86868B] mt-0.5">
              Click any node in the path to inspect its blast radius and parameters.
            </p>
          </div>
          <span className="text-xs font-bold text-rose-600 bg-rose-50 px-3 py-1 rounded-full border border-rose-200">
            Chain Risk: {activeChain.overall_risk} / 100
          </span>
        </div>

        {/* Graph Horizontal Flow */}
        <div className="flex flex-wrap items-center justify-center gap-4 py-8 overflow-x-auto">
          {activeChain.nodes.map((node, idx) => {
            const Icon = getNodeIcon(node.type);
            const isSelected = selectedNode?.id === node.id;

            return (
              <React.Fragment key={node.id}>
                <button
                  onClick={() => setSelectedNode(node)}
                  className={`p-4 rounded-apple-xl border-2 transition-all flex flex-col items-center text-center min-w-[140px] max-w-[180px] ${
                    isSelected
                      ? "ring-4 ring-[#0071E3]/20 border-[#0071E3] scale-105 shadow-apple-hover"
                      : getNodeColor(node.type)
                  }`}
                >
                  <Icon className="w-6 h-6 mb-2" />
                  <span className="text-[10px] font-bold uppercase tracking-wider opacity-75">
                    {node.type}
                  </span>
                  <span className="text-xs font-bold text-[#1D1D1F] mt-1 leading-snug">
                    {node.label}
                  </span>
                </button>

                {idx < MOCK_ATTACK_CHAINS[0].nodes.length - 1 && (
                  <div className="text-[#86868B] flex flex-col items-center flex-shrink-0">
                    <ArrowRight className="w-5 h-5" />
                    <span className="text-[9px] font-medium text-[#86868B] mt-0.5">
                      exploits
                    </span>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>

        <div className="p-4 bg-[#F5F5F7] rounded-apple border border-black/[0.04] text-xs text-[#6E6E73] flex items-center gap-3">
          <Info className="w-4 h-4 text-[#0071E3] flex-shrink-0" />
          <span>
            <strong>Impact Assessment:</strong> This chain allows unprivileged authenticated users to access sensitive tenant records without detection.
          </span>
        </div>
      </div>

      {/* Secondary Chain Card */}
      <div className="bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
        <div className="flex items-center justify-between border-b border-black/[0.04] pb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#1D1D1F]">
              Chain 2: Privilege Escalation to Full System Administration
            </h3>
            <p className="text-xs text-[#86868B] mt-0.5">
              Standard User → PUT /users/&#123;id&#125; → Mass Assignment → System Administrator
            </p>
          </div>
          <span className="text-xs font-bold text-amber-600 bg-amber-50 px-2.5 py-0.5 rounded-full border border-amber-200">
            Risk: 92 / 100
          </span>
        </div>

        <div className="flex items-center gap-3 overflow-x-auto py-2">
          {MOCK_ATTACK_CHAINS[1].nodes.map((node, idx) => (
            <React.Fragment key={node.id}>
              <div className="px-3 py-2 bg-[#F5F5F7] rounded-apple text-xs font-medium text-[#1D1D1F] border border-black/[0.04]">
                {node.label}
              </div>
              {idx < MOCK_ATTACK_CHAINS[1].nodes.length - 1 && (
                <ArrowRight className="w-3.5 h-3.5 text-[#86868B]" />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Node Detail Side Drawer */}
      <Drawer
        isOpen={!!selectedNode}
        onClose={() => setSelectedNode(null)}
        title={selectedNode?.label || "Node Details"}
        subtitle={`Type: ${selectedNode?.type.toUpperCase()}`}
      >
        {selectedNode && (
          <div className="space-y-6">
            <div className="space-y-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
                Node Overview
              </h4>
              <p className="text-xs text-[#1D1D1F] leading-relaxed">
                {selectedNode.type === "vulnerability"
                  ? "This node represents the core Broken Object Level Authorization flaw allowing cross-tenant data harvesting."
                  : selectedNode.type === "impact"
                  ? "Direct HIPAA privacy violation resulting from uncontrolled endpoint access."
                  : `Represents active element '${selectedNode.label}' in the application security perimeter.`}
              </p>
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
                Estimated Reach &amp; Blast Radius
              </h4>
              <div className="p-3 bg-[#F5F5F7] rounded-apple space-y-1.5 text-xs">
                <div className="flex justify-between">
                  <span className="text-[#86868B]">Reach:</span>
                  <span className="font-semibold text-[#1D1D1F]">All Tenant Records (~10,000+)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#86868B]">Confidence:</span>
                  <span className="font-semibold text-emerald-600">85% High</span>
                </div>
              </div>
            </div>

            <Button
              variant="primary"
              className="w-full"
              onClick={() => {
                setSelectedNode(null);
                setActiveView("vulnerabilities");
              }}
            >
              View Related Vulnerability
            </Button>
          </div>
        )}
      </Drawer>
    </div>
  );
};
