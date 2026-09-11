"use client";

import React from "react";

interface ScoreRingProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  showLabel?: boolean;
}

export const ScoreRing: React.FC<ScoreRingProps> = ({
  score,
  size = 180,
  strokeWidth = 12,
  showLabel = true,
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const clampedScore = Math.max(0, Math.min(100, score));
  const offset = circumference - (clampedScore / 100) * circumference;

  // Determine Apple color based on score
  let strokeColor = "#34C759"; // Green
  let labelText = "Excellent";
  let labelColor = "text-emerald-600";

  if (clampedScore < 60) {
    strokeColor = "#FF3B30"; // Red
    labelText = "Critical Action Required";
    labelColor = "text-rose-600";
  } else if (clampedScore < 80) {
    strokeColor = "#FF9500"; // Orange
    labelText = "Attention Needed";
    labelColor = "text-amber-600";
  } else if (clampedScore < 90) {
    strokeColor = "#0071E3"; // Blue
    labelText = "Good Posture";
    labelColor = "text-blue-600";
  }

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="transform -rotate-90">
          {/* Background Ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#E5E5EA"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Animated Progress Ring */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              transition: "stroke-dashoffset 1s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.5s ease",
            }}
          />
        </svg>

        {/* Center Score Text */}
        <div className="absolute flex flex-col items-center justify-center text-center select-none">
          <span className="text-5xl font-bold tracking-tight text-[#1D1D1F]">
            {clampedScore}
          </span>
          <span className="text-xs font-medium uppercase tracking-wider text-[#86868B] mt-0.5">
            Security Score
          </span>
        </div>
      </div>

      {showLabel && (
        <div className={`mt-3 text-sm font-semibold tracking-tight ${labelColor}`}>
          {labelText}
        </div>
      )}
    </div>
  );
};
