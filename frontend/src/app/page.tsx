"use client";

import React from "react";
import { useApp } from "@/context/AppContext";
import { DashboardView } from "@/features/dashboard/DashboardView";
import { ApiOverviewView } from "@/features/api/ApiOverviewView";
import { ApiImportView } from "@/features/import/ApiImportView";
import { AttackCenterView } from "@/features/attacks/AttackCenterView";
import { LiveSimulationView } from "@/features/attacks/LiveSimulationView";
import { VulnerabilityListView } from "@/features/vulnerabilities/VulnerabilityListView";
import { AttackGraphView } from "@/features/attack-graph/AttackGraphView";
import { AiAnalystPanel } from "@/features/ai-analyst/AiAnalystPanel";
import { FixCenterView } from "@/features/fix-center/FixCenterView";
import { SecurityHistoryView } from "@/features/history/SecurityHistoryView";
import { SettingsView } from "@/features/settings/SettingsView";

export default function Home() {
  const { activeView } = useApp();

  switch (activeView) {
    case "dashboard":
      return <DashboardView />;
    case "api-overview":
      return <ApiOverviewView />;
    case "api-import":
      return <ApiImportView />;
    case "attack-center":
      return <AttackCenterView />;
    case "live-simulation":
      return <LiveSimulationView />;
    case "vulnerabilities":
      return <VulnerabilityListView />;
    case "attack-graph":
      return <AttackGraphView />;
    case "ai-analyst":
      return <AiAnalystPanel />;
    case "fix-center":
      return <FixCenterView />;
    case "history":
      return <SecurityHistoryView />;
    case "settings":
      return <SettingsView />;
    default:
      return <DashboardView />;
  }
}
