"use client";

import React from "react";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { CommandMenu } from "./CommandMenu";
import { ToastContainer } from "../ui/Toast";

export const AppShell: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  return (
    <div className="flex h-screen w-full bg-[#FBFBFD] overflow-hidden text-[#1D1D1F] font-sans antialiased">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Content View */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-y-auto p-8 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>

      {/* Global Utilities */}
      <CommandMenu />
      <ToastContainer />
    </div>
  );
};
