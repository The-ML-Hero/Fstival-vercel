import React from "react";
import { clsx } from "clsx";

interface SkeletonProps {
  className?: string;
  width?: string | number;
  height?: string | number;
  rounded?: "sm" | "md" | "lg" | "full";
}

export const Skeleton: React.FC<SkeletonProps> = ({
  className,
  width,
  height,
  rounded = "md",
}) => {
  const roundedClass = {
    sm: "rounded-apple-sm",
    md: "rounded-apple",
    lg: "rounded-apple-lg",
    full: "rounded-full",
  }[rounded];

  return (
    <div
      style={{ width, height }}
      className={clsx(
        "animate-pulse bg-[#E5E5EA]/70",
        roundedClass,
        className
      )}
    />
  );
};
