import React from "react";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface MetricCardProps {
  label: string;
  value: string | number;
  unit?: string;
  subtext?: string;
  icon?: LucideIcon;
  variant?: "white" | "aqua" | "coral" | "navy";
  className?: string;
  trend?: {
    value: string;
    isPositive?: boolean;
  };
}

export function MetricCard({
  label,
  value,
  unit,
  subtext,
  icon: Icon,
  variant = "white",
  className,
  trend,
}: MetricCardProps) {
  const cardStyles = {
    white: "bg-white text-[#1D3557]",
    aqua: "bg-[#A8DADC] text-[#1D3557]",
    coral: "bg-[#F1FAEE] border-[#E63946] shadow-[4px_4px_0px_#E63946]",
    navy: "bg-[#1D3557] text-[#F1FAEE]",
  }[variant];

  const iconBg = {
    white: "bg-[#F1FAEE] text-[#457B9D] border-[#1D3557]",
    aqua: "bg-white text-[#1D3557] border-[#1D3557]",
    coral: "bg-[#ffe4e6] text-[#E63946] border-[#E63946]",
    navy: "bg-[#457B9D] text-white border-white/40",
  }[variant];

  return (
    <div
      className={cn(
        "rounded-xl border-2 border-[#1D3557] shadow-[4px_4px_0px_#1D3557] p-4 flex flex-col justify-between transition-transform duration-100 min-w-0 w-full",
        cardStyles,
        className
      )}
    >
      <div className="flex items-start justify-between gap-2 min-w-0">
        <span
          className={cn(
            "text-[11px] font-heading font-extrabold uppercase tracking-wider truncate",
            variant === "navy" ? "text-[#A8DADC]" : "text-[#457B9D]"
          )}
        >
          {label}
        </span>
        {Icon && (
          <div
            className={cn(
              "w-8 h-8 rounded-lg border-2 flex items-center justify-center shrink-0 shadow-[2px_2px_0px_#1D3557]",
              iconBg
            )}
          >
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>

      <div className="mt-3 min-w-0">
        <div className="flex items-baseline gap-2 min-w-0">
          <span className="font-mono text-2xl sm:text-3xl font-extrabold tracking-tight truncate">
            {value}
          </span>
          {unit && (
            <span
              className={cn(
                "text-xs font-mono font-bold uppercase shrink-0",
                variant === "navy" ? "text-[#A8DADC]" : "text-[#457B9D]"
              )}
            >
              {unit}
            </span>
          )}
        </div>

        <div className="mt-2 flex items-center justify-between text-[11px] gap-2">
          {subtext && (
            <span
              className={cn(
                "font-medium truncate",
                variant === "navy" ? "text-slate-300" : "text-slate-600"
              )}
            >
              {subtext}
            </span>
          )}
          {trend && (
            <span
              className={cn(
                "font-mono font-bold px-1.5 py-0.5 rounded border border-[#1D3557] text-[10px]",
                trend.isPositive
                  ? "bg-[#dcfce7] text-[#166534]"
                  : "bg-[#ffe4e6] text-[#E63946]"
              )}
            >
              {trend.value}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
