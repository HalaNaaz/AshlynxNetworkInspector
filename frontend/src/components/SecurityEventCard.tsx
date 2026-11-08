import React from "react";
import { ShieldAlert, Shield, AlertTriangle, Info } from "lucide-react";
import { cn } from "@/lib/utils";

export interface SecurityEventItem {
  id: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  timestamp: string;
  sourceIp?: string;
  destinationIp?: string;
  category: string;
}

interface SecurityEventCardProps {
  event: SecurityEventItem;
  className?: string;
}

export function SecurityEventCard({ event, className }: SecurityEventCardProps) {
  const severityConfig = {
    CRITICAL: {
      border: "border-[#E63946]",
      bg: "bg-[#ffe4e6]",
      badge: "bg-[#E63946] text-white",
      icon: ShieldAlert,
      iconColor: "text-[#E63946]",
    },
    HIGH: {
      border: "border-[#f97316]",
      bg: "bg-[#ffedd5]",
      badge: "bg-[#f97316] text-white",
      icon: AlertTriangle,
      iconColor: "text-[#f97316]",
    },
    MEDIUM: {
      border: "border-[#457B9D]",
      bg: "bg-[#A8DADC]/40",
      badge: "bg-[#457B9D] text-white",
      icon: Shield,
      iconColor: "text-[#457B9D]",
    },
    LOW: {
      border: "border-[#1D3557]",
      bg: "bg-white",
      badge: "bg-[#A8DADC] text-[#1D3557]",
      icon: Info,
      iconColor: "text-[#1D3557]",
    },
    INFO: {
      border: "border-[#1D3557]/40",
      bg: "bg-white",
      badge: "bg-[#F1FAEE] text-[#1D3557]",
      icon: Info,
      iconColor: "text-[#457B9D]",
    },
  }[event.severity];

  const Icon = severityConfig.icon;

  return (
    <div
      className={cn(
        "rounded-lg border-2 p-3.5 shadow-[3px_3px_0px_#1D3557] flex flex-col justify-between transition-transform duration-100",
        severityConfig.bg,
        severityConfig.border,
        className
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <Icon className={cn("w-4 h-4 shrink-0", severityConfig.iconColor)} />
          <h4 className="font-heading font-extrabold text-xs sm:text-sm text-[#1D3557]">
            {event.title}
          </h4>
        </div>
        <span
          className={cn(
            "text-[9px] font-mono font-extrabold px-2 py-0.5 rounded border border-[#1D3557] shadow-[1px_1px_0px_#1D3557] uppercase",
            severityConfig.badge
          )}
        >
          {event.severity}
        </span>
      </div>

      <p className="text-xs text-[#1D3557] mt-2 font-medium leading-relaxed">
        {event.description}
      </p>

      <div className="mt-3 pt-2 border-t border-[#1D3557]/20 flex flex-wrap items-center justify-between text-[10px] font-mono text-[#457B9D] gap-2">
        <div className="flex items-center gap-2">
          {event.sourceIp && (
            <span>
              SRC: <strong className="text-[#1D3557]">{event.sourceIp}</strong>
            </span>
          )}
          {event.destinationIp && (
            <span>
              DST: <strong className="text-[#1D3557]">{event.destinationIp}</strong>
            </span>
          )}
        </div>
        <span>{event.timestamp}</span>
      </div>
    </div>
  );
}

