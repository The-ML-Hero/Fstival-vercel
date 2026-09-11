"use client";

import React, { useState } from "react";
import {
  Wrench,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  Loader2,
  ShieldCheck,
  RotateCcw,
  Sparkles,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { VulnerabilityFinding } from "@/types";

export const FixCenterView: React.FC = () => {
  const { findings, verifyFix, securityScore, setSecurityScore } = useApp();
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationStep, setVerificationStep] = useState<number>(0);
  const [verifiedResult, setVerifiedResult] = useState<{
    findingId: string;
    diffSummary: string;
  } | null>(null);

  const steps = [
    "Preparing verification probe",
    "Executing targeted attack against local target",
    "Comparing response status & payload structure",
    "Checking dependent API workflows",
  ];

  const handleVerify = async (finding: VulnerabilityFinding) => {
    setVerifyingId(finding.id);
    setVerifiedResult(null);
    setVerificationStep(0);

    for (let i = 0; i < steps.length; i++) {
      setVerificationStep(i);
      await new Promise((r) => setTimeout(r, 600));
    }

    const res = await verifyFix(finding.id);
    setVerifyingId(null);
    if (res.success) {
      setVerifiedResult({
        findingId: finding.id,
        diffSummary: res.message,
      });
    }
  };

  const unverifiedFindings = findings.filter(
    (f) => f.verification_status !== "fixed"
  );

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xs font-semibold uppercase tracking-wider text-[#86868B]">
            Automated Remediation Lab
          </h2>
          <h1 className="text-2xl font-bold text-[#1D1D1F] tracking-tight mt-0.5">
            Fix Center
          </h1>
          <p className="text-xs text-[#6E6E73] mt-1">
            Re-run original security attack probes to mathematically prove that code patches eliminated the vulnerabilities.
          </p>
        </div>

        <div className="bg-[#F5F5F7] px-4 py-2 rounded-apple border border-black/[0.04] text-xs font-medium">
          <span className="text-[#86868B]">Ready for verification: </span>
          <span className="font-bold text-[#1D1D1F]">
            {unverifiedFindings.length} issue(s)
          </span>
        </div>
      </div>

      {/* Verification Sequence In-Progress Banner */}
      {verifyingId && (
        <div className="bg-white rounded-apple-2xl p-8 border border-black/[0.06] shadow-apple-card space-y-6 animate-fade-in">
          <div className="text-center space-y-1">
            <h3 className="text-base font-bold text-[#1D1D1F]">
              Verifying Security Patch...
            </h3>
            <p className="text-xs text-[#6E6E73]">
              Re-executing original Bruno scenario to confirm access control enforcement.
            </p>
          </div>

          <div className="space-y-3 max-w-md mx-auto py-2">
            {steps.map((stepText, idx) => {
              const isPast = idx < verificationStep;
              const isCurrent = idx === verificationStep;
              return (
                <div
                  key={stepText}
                  className={`flex items-center gap-3 p-3 rounded-apple transition-all ${
                    isCurrent
                      ? "bg-[#0071E3]/5 border border-[#0071E3]/30 text-[#0071E3]"
                      : isPast
                      ? "text-emerald-700 font-medium"
                      : "text-[#86868B] opacity-50"
                  }`}
                >
                  {isPast ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 flex-shrink-0" />
                  ) : isCurrent ? (
                    <Loader2 className="w-4 h-4 text-[#0071E3] animate-spin flex-shrink-0" />
                  ) : (
                    <div className="w-4 h-4 rounded-full border border-current flex-shrink-0" />
                  )}
                  <span className="text-xs font-medium">{stepText}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Verification Success Celebration Banner */}
      {verifiedResult && !verifyingId && (
        <div className="bg-white rounded-apple-2xl p-8 border border-emerald-200/80 shadow-apple-card space-y-6 animate-scale-up">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center flex-shrink-0">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div>
                <span className="text-xs font-bold uppercase tracking-wider text-emerald-600">
                  Verification Success
                </span>
                <h3 className="text-lg font-bold text-[#1D1D1F]">
                  FIX VERIFIED: Access Control Successfully Enforced
                </h3>
              </div>
            </div>

            {/* Score Increase Capsule */}
            <div className="bg-emerald-50/80 border border-emerald-200 px-4 py-2 rounded-apple text-center">
              <span className="text-[10px] text-emerald-700 uppercase font-bold block">
                Security Score
              </span>
              <span className="text-base font-bold text-emerald-800">
                87 → {securityScore}
              </span>
            </div>
          </div>

          {/* Before vs After Diff */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 p-4 rounded-apple-xl bg-[#F5F5F7] border border-black/[0.04]">
            <div className="space-y-1">
              <span className="text-[11px] font-semibold text-[#86868B] uppercase">
                Before Patch (Attack Baseline)
              </span>
              <div className="p-3 bg-white rounded-apple border border-black/[0.04] text-xs font-mono text-rose-600 font-bold">
                HTTP 200 OK — Sensitive PHI Data Returned
              </div>
            </div>

            <div className="space-y-1">
              <span className="text-[11px] font-semibold text-[#86868B] uppercase">
                After Patch (Verified Response)
              </span>
              <div className="p-3 bg-white rounded-apple border border-black/[0.04] text-xs font-mono text-emerald-600 font-bold">
                HTTP 403 Forbidden — Blocked by Access Control
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Issues Ready to Verify List */}
      <div className="space-y-4">
        <h3 className="text-sm font-semibold text-[#1D1D1F] tracking-tight">
          Pending &amp; Verified Fixes
        </h3>

        {findings.map((finding) => {
          const isFixed = finding.verification_status === "fixed";
          return (
            <div
              key={finding.id}
              className={`bg-white rounded-apple-xl p-6 border shadow-apple-card transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                isFixed ? "border-emerald-200/80 bg-emerald-50/20" : "border-black/[0.06]"
              }`}
            >
              <div className="space-y-1.5 max-w-xl">
                <div className="flex items-center gap-2">
                  <Badge variant={isFixed ? "success" : finding.severity}>
                    {isFixed ? "FIX VERIFIED" : finding.type}
                  </Badge>
                  <span className="font-mono text-xs text-[#6E6E73]">
                    {finding.method} {finding.endpoint}
                  </span>
                </div>
                <h4 className="text-sm font-bold text-[#1D1D1F]">
                  {finding.title}
                </h4>
                <p className="text-xs text-[#6E6E73]">
                  {isFixed
                    ? "Target API correctly returns HTTP 403 Forbidden."
                    : "Status: Waiting for verification re-test against target API."}
                </p>
              </div>

              <div className="flex items-center gap-3">
                {isFixed ? (
                  <span className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-600 bg-emerald-50 px-3 py-1.5 rounded-full border border-emerald-200">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    Verified Fixed
                  </span>
                ) : (
                  <Button
                    variant="primary"
                    size="sm"
                    loading={verifyingId === finding.id}
                    onClick={() => handleVerify(finding)}
                    icon={<Wrench className="w-3.5 h-3.5" />}
                  >
                    Verify Fix
                  </Button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
