import React from "react";
import { cn } from "@/lib/utils";

export type StatusType = "operational" | "active" | "standby" | "warning" | "critical" | "offline";

interface StatusIndicatorProps {
  status: StatusType;
  label?: string;
  pulse?: boolean;
  className?: string;
}

export function StatusIndicator({
  status,
  label,
  pulse = true,
  className,
}: StatusIndicatorProps) {
  const configs = {
    operational: {
      dot: "bg-[#10b981]",
      border: "border-[#1D3557]",
      badge: "bg-[#F1FAEE] text-[#1D3557] border-[#1D3557]",
      pulseColor: "bg-[#10b981]/40",
      defaultLabel: "OPERATIONAL",
    },
    active: {
      dot: "bg-[#457B9D]",
      border: "border-[#1D3557]",
      badge: "bg-[#A8DADC] text-[#1D3557] border-[#1D3557]",
      pulseColor: "bg-[#457B9D]/40",
      defaultLabel: "ACTIVE",
    },
    standby: {
      dot: "bg-[#f59e0b]",
      border: "border-[#1D3557]",
      badge: "bg-[#fffbeb] text-[#92400e] border-[#1D3557]",
      pulseColor: "bg-[#f59e0b]/40",
      defaultLabel: "STANDBY",
    },
    warning: {
      dot: "bg-[#f97316]",
      border: "border-[#1D3557]",
      badge: "bg-[#ffedd5] text-[#9a3412] border-[#1D3557]",
      pulseColor: "bg-[#f97316]/40",
      defaultLabel: "WARNING",
    },
    critical: {
      dot: "bg-[#E63946]",
      border: "border-[#1D3557]",
      badge: "bg-[#ffe4e6] text-[#E63946] border-[#1D3557]",
      pulseColor: "bg-[#E63946]/40",
      defaultLabel: "CRITICAL",
    },
    offline: {
      dot: "bg-[#94a3b8]",
      border: "border-[#1D3557]",
      badge: "bg-[#f1f5f9] text-[#475569] border-[#1D3557]",
      pulseColor: "bg-transparent",
      defaultLabel: "OFFLINE",
    },
  }[status];

  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 px-2.5 py-1 rounded-md border-2 font-mono text-[11px] font-bold shadow-[2px_2px_0px_#1D3557]",
        configs.badge,
        className
      )}
    >
      <span className="relative flex h-2.5 w-2.5 shrink-0">
        {pulse && (
          <span
            className={cn(
              "animate-ping absolute inline-flex h-full w-full rounded-full opacity-75",
              configs.pulseColor
            )}
          />
        )}
        <span
          className={cn(
            "relative inline-flex rounded-full h-2.5 w-2.5 border border-[#1D3557]",
            configs.dot
          )}
        />
      </span>
      <span>{label || configs.defaultLabel}</span>
    </div>
  );
}

