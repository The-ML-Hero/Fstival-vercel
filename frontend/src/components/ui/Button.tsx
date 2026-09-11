import React from "react";
import { clsx } from "clsx";

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "outline" | "danger" | "ghost";
  size?: "sm" | "md" | "lg";
  loading?: boolean;
  icon?: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  className,
  variant = "primary",
  size = "md",
  loading = false,
  disabled = false,
  icon,
  ...props
}) => {
  const baseStyles =
    "inline-flex items-center justify-center font-medium rounded-apple transition-all duration-150 active:scale-[0.98] select-none disabled:opacity-50 disabled:pointer-events-none focus:outline-none focus-visible:ring-2 focus-visible:ring-apple-blue/50";

  const sizeStyles = {
    sm: "text-xs px-3 py-1.5 gap-1.5",
    md: "text-sm px-4 py-2 gap-2",
    lg: "text-base px-5 py-2.5 gap-2.5 font-semibold",
  };

  const variantStyles = {
    primary:
      "bg-[#0071E3] hover:bg-[#0077ED] text-white shadow-[0_1px_2px_rgba(0,113,227,0.3)] hover:shadow-[0_2px_8px_rgba(0,113,227,0.4)]",
    secondary:
      "bg-[#F5F5F7] hover:bg-[#EAEAEA] text-[#1D1D1F] border border-black/[0.05]",
    outline:
      "bg-white hover:bg-[#F5F5F7] text-[#1D1D1F] border border-[#E5E5EA] shadow-sm",
    danger:
      "bg-[#FF3B30] hover:bg-[#FF453A] text-white shadow-[0_1px_2px_rgba(255,59,48,0.3)]",
    ghost:
      "bg-transparent hover:bg-black/[0.04] text-[#1D1D1F]",
  };

  return (
    <button
      className={clsx(
        baseStyles,
        sizeStyles[size],
        variantStyles[variant],
        className
      )}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <svg
          className="animate-spin h-4 w-4 text-current"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8v8H4z"
          />
        </svg>
      ) : (
        icon
      )}
      {children}
    </button>
  );
};
