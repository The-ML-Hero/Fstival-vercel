"use client";

import React from "react";
import { CheckCircle2, AlertCircle, Info, X } from "lucide-react";
import { useApp } from "@/context/AppContext";

export const ToastContainer: React.FC = () => {
  const { toasts, removeToast } = useApp();

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 pointer-events-none max-w-sm w-full">
      {toasts.map((toast) => {
        let Icon = Info;
        let iconColor = "text-blue-500";
        let bgStyle = "bg-white/95 border-black/[0.08] shadow-apple-hover";

        if (toast.type === "success") {
          Icon = CheckCircle2;
          iconColor = "text-emerald-500";
        } else if (toast.type === "error") {
          Icon = AlertCircle;
          iconColor = "text-rose-500";
        }

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto flex items-start gap-3 p-3.5 rounded-apple-lg border backdrop-blur-xl ${bgStyle} transition-all duration-200 animate-slide-up`}
          >
            <Icon className={`w-5 h-5 flex-shrink-0 mt-0.5 ${iconColor}`} />
            <div className="flex-1 text-xs font-medium text-[#1D1D1F] leading-snug">
              {toast.message}
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="text-[#86868B] hover:text-[#1D1D1F] p-0.5 rounded"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
