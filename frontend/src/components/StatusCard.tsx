import React from "react";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface StatusCardProps {
  title: string;
  status: "operational" | "standby" | "offline" | "warning";
  statusText: string;
  description: string;
  icon: LucideIcon;
  badge?: string;
  metadata?: { label: string; value: string | number }[];
  className?: string;
}

export function StatusCard({
  title,
  status,
  statusText,
  description,
  icon: Icon,
  badge,
  metadata,
  className,
}: StatusCardProps) {
  const statusStyles = {
    operational: {
      dot: "bg-[#10b981]",
      badge: "bg-[#F1FAEE] text-[#1D3557] border-[#1D3557]",
      iconBg: "bg-[#A8DADC] text-[#1D3557] border-[#1D3557]",
    },
    standby: {
      dot: "bg-[#f59e0b]",
      badge: "bg-[#fffbeb] text-[#92400e] border-[#1D3557]",
      iconBg: "bg-[#fffbeb] text-[#92400e] border-[#1D3557]",
    },
    offline: {
      dot: "bg-[#E63946]",
      badge: "bg-[#ffe4e6] text-[#E63946] border-[#1D3557]",
      iconBg: "bg-[#ffe4e6] text-[#E63946] border-[#1D3557]",
    },
    warning: {
      dot: "bg-[#f97316]",
      badge: "bg-[#ffedd5] text-[#9a3412] border-[#1D3557]",
      iconBg: "bg-[#ffedd5] text-[#9a3412] border-[#1D3557]",
    },
  }[status];

  return (
    <div
      className={cn(
        "rounded-xl border-2 border-[#1D3557] bg-white p-4 shadow-[4px_4px_0px_#1D3557] flex flex-col justify-between transition-transform duration-100",
        className
      )}
    >
      <div>
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div
              className={cn(
                "w-8 h-8 rounded-lg border-2 flex items-center justify-center shrink-0 shadow-[2px_2px_0px_#1D3557]",
                statusStyles.iconBg
              )}
            >
              <Icon className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-heading font-extrabold text-xs sm:text-sm uppercase text-[#1D3557]">
                {title}
              </h3>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span
                  className={cn(
                    "w-2 h-2 rounded-full border border-[#1D3557]",
                    statusStyles.dot
                  )}
                />
                <span className="text-[10px] font-mono font-bold text-[#1D3557]">
                  {statusText}
                </span>
              </div>
            </div>
          </div>
          {badge && (
            <span
              className={cn(
                "text-[9px] font-mono font-extrabold px-1.5 py-0.5 rounded border shadow-[1px_1px_0px_#1D3557] uppercase",
                statusStyles.badge
              )}
            >
              {badge}
            </span>
          )}
        </div>

        <p className="text-xs text-[#457B9D] mt-3 font-medium leading-relaxed">
          {description}
        </p>
      </div>

      {metadata && metadata.length > 0 && (
        <div className="mt-3 pt-3 border-t-2 border-[#1D3557]/20 grid grid-cols-2 gap-2 text-[11px] font-mono">
          {metadata.map((item, idx) => (
            <div key={idx} className="flex flex-col">
              <span className="text-[#457B9D] uppercase text-[10px] font-bold">
                {item.label}
              </span>
              <span className="text-[#1D3557] font-bold truncate">
                {item.value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
