"use client";

import React, { useState } from "react";
import {
  Settings,
  ShieldCheck,
  Cpu,
  Globe,
  Sliders,
  Check,
  Lock,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { Button } from "@/components/ui/Button";

export const SettingsView: React.FC = () => {
  const { project, setProject, addToast } = useApp();
  const [environment, setEnvironment] = useState<string>("local");
  const [aiProvider, setAiProvider] = useState<string>("fallback");
  const [targetAuthorized, setTargetAuthorized] = useState<boolean>(true);
  const [failOnCritical, setFailOnCritical] = useState<boolean>(true);
  const [minScore, setMinScore] = useState<number>(80);

  const handleSave = () => {
    setProject((prev) => ({
      ...prev,
      target_authorized: targetAuthorized,
    }));
    addToast("Settings successfully saved!", "success");
  };

  return (
    <div className="max-w-3xl space-y-8 animate-fade-in">
      {/* Header */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
          Configuration &amp; Policies
        </h2>
        <h1 className="text-2xl font-bold text-[#1D1D1F] tracking-tight mt-0.5">
          Settings
        </h1>
        <p className="text-xs text-[#6E6E73] mt-1">
          Manage local execution parameters, AI providers, and CI/CD security gate thresholds.
        </p>
      </div>

      {/* 1. Project & Target URL */}
      <div className="bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
        <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight border-b border-black/[0.04] pb-3 flex items-center gap-2">
          <Globe className="w-4 h-4 text-[#0071E3]" />
          Target API Configuration
        </h3>

        <div className="space-y-3 text-xs">
          <div>
            <label className="font-medium text-[#1D1D1F] block mb-1">
              Project Name
            </label>
            <input
              type="text"
              value={project.name}
              readOnly
              className="w-full p-2.5 rounded-apple bg-[#F5F5F7] border border-black/[0.06] text-[#1D1D1F]"
            />
          </div>

          <div>
            <label className="font-medium text-[#1D1D1F] block mb-1">
              Target Base URL
            </label>
            <input
              type="text"
              value={project.target_base_url || "http://localhost:8000/demo"}
              readOnly
              className="w-full p-2.5 rounded-apple bg-[#F5F5F7] border border-black/[0.06] text-[#1D1D1F] font-mono"
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <div>
              <span className="font-medium text-[#1D1D1F] block">
                Target Authorization Safety Switch
              </span>
              <span className="text-[#86868B] text-[11px]">
                Enforces safety validation before executing security tests
              </span>
            </div>
            <input
              type="checkbox"
              checked={targetAuthorized}
              onChange={(e) => setTargetAuthorized(e.target.checked)}
              className="w-4 h-4 text-[#0071E3] rounded"
            />
          </div>
        </div>
      </div>

      {/* 2. AI Provider Selection */}
      <div className="bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
        <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight border-b border-black/[0.04] pb-3 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-[#AF52DE]" />
          AI Intelligence Provider
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { id: "fallback", name: "Deterministic (Default)", desc: "Rule-based OWASP logic" },
            { id: "openai", name: "OpenAI GPT-4o", desc: "Cloud API provider" },
            { id: "ollama", name: "Ollama (Local LLM)", desc: "100% On-premise air-gapped" },
          ].map((provider) => (
            <button
              key={provider.id}
              onClick={() => setAiProvider(provider.id)}
              className={`p-3.5 rounded-apple border text-left transition-all ${
                aiProvider === provider.id
                  ? "bg-[#0071E3]/5 border-[#0071E3] ring-2 ring-[#0071E3]/20"
                  : "bg-[#F5F5F7] border-black/[0.04] hover:bg-[#EAEAEA]"
              }`}
            >
              <span className="text-xs font-bold text-[#1D1D1F] block">
                {provider.name}
              </span>
              <span className="text-[11px] text-[#86868B] mt-0.5 block">
                {provider.desc}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* 3. CI/CD Security Gate Thresholds */}
      <div className="bg-white rounded-apple-xl p-6 border border-black/[0.06] shadow-apple-card space-y-4">
        <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight border-b border-black/[0.04] pb-3 flex items-center gap-2">
          <Sliders className="w-4 h-4 text-[#34C759]" />
          CI/CD Security Gate Policy
        </h3>

        <div className="space-y-4 text-xs">
          <div className="flex items-center justify-between">
            <div>
              <span className="font-medium text-[#1D1D1F] block">
                Fail Build on Confirmed Critical
              </span>
              <span className="text-[#86868B] text-[11px]">
                Returns non-zero exit code if any critical vulnerability is active
              </span>
            </div>
            <input
              type="checkbox"
              checked={failOnCritical}
              onChange={(e) => setFailOnCritical(e.target.checked)}
              className="w-4 h-4 text-[#0071E3] rounded"
            />
          </div>

          <div>
            <div className="flex justify-between font-medium text-[#1D1D1F] mb-1">
              <span>Minimum Security Score for Passing Gate:</span>
              <span className="font-bold text-[#0071E3]">{minScore} / 100</span>
            </div>
            <input
              type="range"
              min="50"
              max="100"
              value={minScore}
              onChange={(e) => setMinScore(Number(e.target.value))}
              className="w-full accent-[#0071E3]"
            />
          </div>
        </div>
      </div>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button variant="primary" onClick={handleSave} icon={<Check className="w-4 h-4" />}>
          Save Settings
        </Button>
      </div>
    </div>
  );
};
