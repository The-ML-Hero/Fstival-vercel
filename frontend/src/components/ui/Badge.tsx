import React from "react";
import { clsx } from "clsx";
import { SeverityLevel } from "@/types";

interface BadgeProps {
  children: React.ReactNode;
  variant?: "default" | "critical" | "high" | "medium" | "low" | "success" | "blue" | "gray" | "method";
  method?: string;
  className?: string;
  size?: "sm" | "md";
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = "default",
  method,
  className,
  size = "md",
}) => {
  let computedVariant = variant;

  if (method) {
    computedVariant = "method";
  }

  const baseStyles = "inline-flex items-center font-medium rounded-full tracking-tight";
  const sizeStyles = {
    sm: "text-[11px] px-2 py-0.5 leading-none",
    md: "text-xs px-2.5 py-1",
  };

  const variantStyles = {
    default: "bg-[#F5F5F7] text-[#1D1D1F] border border-black/[0.06]",
    critical: "bg-[#FF3B30]/10 text-[#D70015] border border-[#FF3B30]/20 font-semibold",
    high: "bg-[#FF9500]/10 text-[#C93400] border border-[#FF9500]/20 font-semibold",
    medium: "bg-[#FFCC00]/15 text-[#8F6B00] border border-[#FFCC00]/30 font-medium",
    low: "bg-[#34C759]/10 text-[#248A3D] border border-[#34C759]/20 font-medium",
    success: "bg-[#34C759]/10 text-[#248A3D] border border-[#34C759]/20 font-medium",
    blue: "bg-[#0071E3]/10 text-[#0071E3] border border-[#0071E3]/20 font-medium",
    gray: "bg-black/[0.04] text-[#6E6E73] border border-black/[0.04]",
    method: "font-mono font-bold text-[11px] px-2 py-0.5",
  };

  let methodColor = "bg-blue-50 text-blue-700 border border-blue-200";
  if (method) {
    const m = method.toUpperCase();
    if (m === "GET") methodColor = "bg-sky-50 text-sky-700 border border-sky-200/80";
    else if (m === "POST") methodColor = "bg-emerald-50 text-emerald-700 border border-emerald-200/80";
    else if (m === "PUT") methodColor = "bg-amber-50 text-amber-700 border border-amber-200/80";
    else if (m === "PATCH") methodColor = "bg-indigo-50 text-indigo-700 border border-indigo-200/80";
    else if (m === "DELETE") methodColor = "bg-rose-50 text-rose-700 border border-rose-200/80";
  }

  return (
    <span
      className={clsx(
        baseStyles,
        sizeStyles[size],
        computedVariant === "method" ? methodColor : variantStyles[computedVariant],
        className
      )}
    >
      {children}
    </span>
  );
};
