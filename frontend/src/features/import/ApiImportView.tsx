"use client";

import React, { useState, useRef } from "react";
import {
  UploadCloud,
  FileCode,
  FolderDown,
  CheckCircle2,
  ArrowRight,
  Sparkles,
  Loader2,
  FileText,
  AlertCircle,
} from "lucide-react";
import { useApp } from "@/context/AppContext";
import { Button } from "@/components/ui/Button";
import { Tabs } from "@/components/ui/Tabs";

export const ApiImportView: React.FC = () => {
  const { setActiveView, addToast, startSimulation, importAndAnalyzeSpec, importStats } = useApp();
  const [activeTab, setActiveTab] = useState<string>("upload");
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [isComplete, setIsComplete] = useState<boolean>(false);
  const [jsonText, setJsonText] = useState<string>("");
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [selectedFileName, setSelectedFileName] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const brunoInputRef = useRef<HTMLInputElement>(null);

  const steps = [
    "Reading & validating API specification",
    "Ingesting endpoints & data constraints into backend",
    "Mapping resource entities & dependencies",
    "Discovering stateful multi-step workflows",
    "Generating prioritized OWASP attack plans",
  ];

  const handleFile = (file: File) => {
    if (!file) return;
    setSelectedFileName(file.name);
    setErrorMessage(null);

    const reader = new FileReader();
    reader.onload = async (e) => {
      const content = e.target?.result as string;
      if (!content || !content.trim()) {
        setErrorMessage("The selected file is empty.");
        addToast("The selected file is empty.", "error");
        return;
      }
      await executeImport(content, file.name);
    };
    reader.onerror = () => {
      setErrorMessage("Failed to read the selected file.");
      addToast("Failed to read file.", "error");
    };
    reader.readAsText(file);
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFile(files[0]);
    }
  };

  const executeImport = async (content: string, title?: string) => {
    setIsProcessing(true);
    setIsComplete(false);
    setErrorMessage(null);
    setCurrentStep(0);

    // Step 0: Reading & validating
    setCurrentStep(0);
    await new Promise((r) => setTimeout(r, 400));

    try {
      // Step 1: Ingesting into backend
      setCurrentStep(1);
      
      // Step 2, 3, 4 with timer alongside real async backend call
      const stepTimer = setInterval(() => {
        setCurrentStep((prev) => (prev < 4 ? prev + 1 : prev));
      }, 700);

      const stats = await importAndAnalyzeSpec(content, title);
      clearInterval(stepTimer);

      setCurrentStep(4);
      await new Promise((r) => setTimeout(r, 400));

      setIsProcessing(false);
      setIsComplete(true);
      addToast(
        `Successfully imported! Generated ${stats.attacks_count} attack plans across ${stats.endpoints_count} endpoints.`,
        "success"
      );
    } catch (err: any) {
      setIsProcessing(false);
      const msg = err.message || "Failed to analyze API specification in backend.";
      setErrorMessage(msg);
      addToast(msg, "error");
    }
  };

  const handlePasteSubmit = async () => {
    if (!jsonText.trim()) {
      setErrorMessage("Please paste an OpenAPI specification (JSON or YAML) before submitting.");
      addToast("Specification text is empty.", "error");
      return;
    }
    await executeImport(jsonText, "Pasted API Specification");
  };

  const loadSampleSpec = async (type: "ecommerce" | "healthcare") => {
    setIsProcessing(true);
    setErrorMessage(null);
    try {
      const specUrl =
        type === "ecommerce"
          ? "/samples/vulnerable_ecommerce_api.yaml"
          : "/samples/secure_healthcare_api.yaml";

      // Try fetching from public samples, or provide inline YAML
      let content = "";
      try {
        const res = await fetch(specUrl);
        if (res.ok) {
          content = await res.text();
        }
      } catch {
        // Fallback handled below
      }

      if (!content) {
        // High quality fallback OpenAPI specification
        if (type === "ecommerce") {
          content = `openapi: 3.0.1
info:
  title: ShopEasy Vulnerable E-Commerce API
  description: E-Commerce API with deliberate flaws for security testing
  version: 1.0.0
paths:
  /users/{id}:
    get:
      summary: Get user profile
      security:
        - BearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: User profile
  /orders:
    post:
      summary: Create new order
      security:
        - BearerAuth: []
      responses:
        "200":
          description: Order created
  /orders/{order_id}:
    get:
      summary: View order
      security:
        - BearerAuth: []
      parameters:
        - name: order_id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Order details
  /orders/{order_id}/pay:
    post:
      summary: Pay for order
      security:
        - BearerAuth: []
      parameters:
        - name: order_id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Payment successful
  /admin/users:
    get:
      summary: List all users (admin)
      security:
        - BearerAuth: []
      responses:
        "200":
          description: List of all users
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer`;
        } else {
          content = `openapi: 3.0.0
info:
  title: MediSecure Clinical Platform API
  description: Healthcare clinical and triage records API
  version: 1.0.0
paths:
  /patients:
    post:
      summary: Register patient
      security:
        - BearerAuth: []
      responses:
        "201":
          description: Patient created
  /patients/{patient_id}:
    get:
      summary: Fetch patient chart
      security:
        - BearerAuth: []
      parameters:
        - name: patient_id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: Patient chart
  /appointments:
    post:
      summary: Schedule consultation
      security:
        - BearerAuth: []
      responses:
        "200":
          description: Consultation scheduled
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer`;
        }
      }

      await executeImport(
        content,
        type === "ecommerce"
          ? "ShopEasy Vulnerable E-Commerce API"
          : "MediSecure Clinical Platform API"
      );
    } catch (err: any) {
      setIsProcessing(false);
      setErrorMessage(err.message || "Failed to load sample specification.");
      addToast("Failed to load sample specification.", "error");
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-8 animate-fade-in py-4">
      {/* Hidden File Inputs */}
      <input
        type="file"
        ref={fileInputRef}
        accept=".yaml,.yml,.json"
        onChange={handleFileInputChange}
        className="hidden"
      />
      <input
        type="file"
        ref={brunoInputRef}
        accept=".json,.bru"
        onChange={handleFileInputChange}
        className="hidden"
      />

      {/* Header */}
      <div className="text-center space-y-2">
        <div className="w-12 h-12 rounded-apple-xl bg-[#0071E3]/10 text-[#0071E3] flex items-center justify-center mx-auto shadow-sm">
          <UploadCloud className="w-6 h-6" />
        </div>
        <h1 className="text-2xl font-bold text-[#1D1D1F] tracking-tight">
          Connect your API
        </h1>
        <p className="text-xs text-[#6E6E73] max-w-md mx-auto">
          Import an OpenAPI specification, Swagger 2.0/3.x document, or Bruno collection to automatically generate intelligent attack plans.
        </p>
      </div>

      {errorMessage && (
        <div className="flex items-center gap-3 p-4 bg-red-50/80 border border-red-200 text-red-700 rounded-apple text-xs">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {!isProcessing && !isComplete && (
        <div className="bg-white rounded-apple-2xl p-8 border border-black/[0.06] shadow-apple-card space-y-6">
          <div className="flex justify-center">
            <Tabs
              tabs={[
                { id: "upload", label: "Upload OpenAPI" },
                { id: "bruno", label: "Bruno Collection" },
                { id: "paste", label: "Paste YAML / JSON" },
              ]}
              activeTab={activeTab}
              onChange={setActiveTab}
            />
          </div>

          {activeTab === "upload" && (
            <div className="space-y-4">
              <div
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setIsDragging(true);
                }}
                onDragLeave={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setIsDragging(false);
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setIsDragging(false);
                  if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                    handleFile(e.dataTransfer.files[0]);
                  }
                }}
                className={`border-2 border-dashed rounded-apple-xl p-12 text-center transition-all cursor-pointer group ${
                  isDragging
                    ? "border-[#0071E3] bg-[#0071E3]/5 scale-[1.01]"
                    : "border-[#E5E5EA] hover:border-[#0071E3] bg-[#FBFBFD] hover:bg-[#F5F5F7]"
                }`}
              >
                <FileCode className="w-10 h-10 text-[#86868B] group-hover:text-[#0071E3] mx-auto mb-3 transition-colors" />
                <p className="text-sm font-semibold text-[#1D1D1F]">
                  {selectedFileName ? selectedFileName : "Drag and drop your OpenAPI / Swagger file here"}
                </p>
                <p className="text-xs text-[#86868B] mt-1">
                  Supports .yaml, .yml, and .json up to 25MB
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-4"
                  onClick={(e) => {
                    e.stopPropagation();
                    fileInputRef.current?.click();
                  }}
                >
                  Browse File
                </Button>
              </div>

              {/* Sample Specs Quick-Load */}
              <div className="pt-2 border-t border-black/[0.04]">
                <p className="text-[11px] font-medium text-[#86868B] mb-2 text-center">
                  Or quickly load one of our bundled demonstration specifications:
                </p>
                <div className="flex flex-wrap items-center justify-center gap-2">
                  <button
                    type="button"
                    onClick={() => loadSampleSpec("ecommerce")}
                    className="text-xs px-3 py-1.5 rounded-full bg-[#F5F5F7] hover:bg-[#EAEAEA] text-[#1D1D1F] border border-black/[0.06] transition-colors flex items-center gap-1.5"
                  >
                    <FileText className="w-3.5 h-3.5 text-[#0071E3]" />
                    Vulnerable E-Commerce API (8 Endpoints)
                  </button>
                  <button
                    type="button"
                    onClick={() => loadSampleSpec("healthcare")}
                    className="text-xs px-3 py-1.5 rounded-full bg-[#F5F5F7] hover:bg-[#EAEAEA] text-[#1D1D1F] border border-black/[0.06] transition-colors flex items-center gap-1.5"
                  >
                    <FileText className="w-3.5 h-3.5 text-emerald-600" />
                    Secure Healthcare API
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === "bruno" && (
            <div
              onClick={() => brunoInputRef.current?.click()}
              className="border-2 border-dashed border-[#E5E5EA] hover:border-[#0071E3] bg-[#FBFBFD] hover:bg-[#F5F5F7] rounded-apple-xl p-12 text-center transition-all cursor-pointer group"
            >
              <FolderDown className="w-10 h-10 text-[#86868B] group-hover:text-[#0071E3] mx-auto mb-3 transition-colors" />
              <p className="text-sm font-semibold text-[#1D1D1F]">
                Select Bruno Collection File
              </p>
              <p className="text-xs text-[#86868B] mt-1">
                Upload bruno.json or individual .bru collection request
              </p>
              <Button
                variant="outline"
                size="sm"
                className="mt-4"
                onClick={(e) => {
                  e.stopPropagation();
                  brunoInputRef.current?.click();
                }}
              >
                Select File
              </Button>
            </div>
          )}

          {activeTab === "paste" && (
            <div className="space-y-4">
              <textarea
                value={jsonText}
                onChange={(e) => setJsonText(e.target.value)}
                placeholder="openapi: 3.0.0&#10;info:&#10;  title: Your Custom API&#10;  version: 1.0.0&#10;paths:&#10;  /orders:&#10;    post:&#10;      summary: Create order..."
                rows={10}
                className="w-full text-xs font-mono p-4 rounded-apple border border-[#E5E5EA] bg-[#FBFBFD] focus:outline-none focus:ring-2 focus:ring-[#0071E3]/30"
              />
              <Button
                variant="primary"
                className="w-full"
                onClick={handlePasteSubmit}
              >
                Parse &amp; Ingest Specification
              </Button>
            </div>
          )}
        </div>
      )}

      {/* Processing Animation */}
      {isProcessing && (
        <div className="bg-white rounded-apple-2xl p-8 border border-black/[0.06] shadow-apple-card space-y-6 text-center animate-fade-in">
          <div className="space-y-2">
            <h3 className="text-base font-semibold text-[#1D1D1F]">
              Analyzing your API with Backend Security Engine...
            </h3>
            <p className="text-xs text-[#6E6E73]">
              API Guardian is extracting operations, inferring roles, tracing workflows, and generating OWASP attack plans.
            </p>
          </div>

          {/* Stepper Flow */}
          <div className="space-y-3 max-w-md mx-auto text-left py-4">
            {steps.map((stepText, idx) => {
              const isPast = idx < currentStep;
              const isCurrent = idx === currentStep;
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

      {/* Completion Screen */}
      {isComplete && (
        <div className="bg-white rounded-apple-2xl p-8 border border-black/[0.06] shadow-apple-card space-y-6 text-center animate-scale-up">
          <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mx-auto">
            <CheckCircle2 className="w-6 h-6" />
          </div>

          <div className="space-y-1">
            <h3 className="text-lg font-bold text-[#1D1D1F]">
              Your API has been successfully imported!
            </h3>
            <p className="text-xs text-[#6E6E73] max-w-md mx-auto leading-relaxed">
              Discovered{" "}
              <span className="font-semibold text-[#1D1D1F]">
                {importStats?.endpoints_count ?? 9} endpoints
              </span>
              ,{" "}
              <span className="font-semibold text-[#1D1D1F]">
                {importStats?.resources_count ?? 5} resources
              </span>
              ,{" "}
              <span className="font-semibold text-[#1D1D1F]">
                {importStats?.workflows_count ?? 2} business workflows
              </span>
              , and generated{" "}
              <span className="font-semibold text-[#0071E3]">
                {importStats?.attacks_count ?? 24} automated attack scenarios
              </span>
              .
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <Button
              variant="outline"
              onClick={() => setActiveView("api-overview")}
              icon={<ArrowRight className="w-3.5 h-3.5" />}
            >
              Explore API Catalog
            </Button>
            <Button
              variant="outline"
              onClick={() => setActiveView("attack-center")}
            >
              View Attack Center
            </Button>
            <Button
              variant="primary"
              onClick={startSimulation}
              icon={<Sparkles className="w-3.5 h-3.5" />}
            >
              Start Security Simulation
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};
