import React from "react";
import { clsx } from "clsx";

interface MetricCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: React.ReactNode;
  trend?: string;
  trendPositive?: boolean;
  className?: string;
  onClick?: () => void;
}

export const MetricCard: React.FC<MetricCardProps> = ({
  label,
  value,
  subtext,
  icon,
  trend,
  trendPositive,
  className,
  onClick,
}) => {
  return (
    <div
      onClick={onClick}
      className={clsx(
        "bg-white rounded-apple-lg border border-black/[0.06] p-5 shadow-apple-card transition-all duration-200",
        onClick && "cursor-pointer hover:shadow-apple-hover hover:border-black/[0.12] active:scale-[0.99]",
        className
      )}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-[#6E6E73] uppercase tracking-wider">
          {label}
        </span>
        {icon && <div className="text-[#86868B]">{icon}</div>}
      </div>

      <div className="mt-2 flex items-baseline gap-2">
        <span className="text-3xl font-bold tracking-tight text-[#1D1D1F]">
          {value}
        </span>
        {trend && (
          <span
            className={clsx(
              "text-xs font-semibold px-1.5 py-0.5 rounded-full",
              trendPositive
                ? "bg-emerald-50 text-emerald-700"
                : "bg-rose-50 text-rose-700"
            )}
          >
            {trend}
          </span>
        )}
      </div>

      {subtext && (
        <p className="mt-1 text-xs text-[#86868B] font-normal tracking-tight">
          {subtext}
        </p>
      )}
    </div>
  );
};
