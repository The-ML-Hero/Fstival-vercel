import React from "react";
import { clsx } from "clsx";

interface TabItem {
  id: string;
  label: string;
  count?: number;
}

interface TabsProps {
  tabs: TabItem[];
  activeTab: string;
  onChange: (tabId: string) => void;
  className?: string;
}

export const Tabs: React.FC<TabsProps> = ({
  tabs,
  activeTab,
  onChange,
  className,
}) => {
  return (
    <div
      className={clsx(
        "inline-flex p-1 bg-[#F5F5F7] rounded-apple border border-black/[0.04] gap-1",
        className
      )}
    >
      {tabs.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            className={clsx(
              "px-3.5 py-1.5 text-xs font-medium rounded-apple-sm transition-all duration-150 flex items-center gap-1.5 select-none",
              isActive
                ? "bg-white text-[#1D1D1F] shadow-sm font-semibold"
                : "text-[#6E6E73] hover:text-[#1D1D1F] hover:bg-black/[0.02]"
            )}
          >
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span
                className={clsx(
                  "text-[10px] px-1.5 py-0.2 rounded-full font-mono",
                  isActive
                    ? "bg-[#F5F5F7] text-[#1D1D1F]"
                    : "bg-black/[0.05] text-[#86868B]"
                )}
              >
                {tab.count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
};
