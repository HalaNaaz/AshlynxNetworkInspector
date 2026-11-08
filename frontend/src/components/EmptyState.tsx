import React, { ReactNode } from "react";
import { LucideIcon, Inbox } from "lucide-react";
import { cn } from "@/lib/utils";

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: LucideIcon;
  action?: ReactNode;
  badge?: string;
  className?: string;
}

export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  action,
  badge,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "p-8 sm:p-12 text-center rounded-xl border-2 border-dashed border-[#1D3557]/40 bg-[#F1FAEE]/60 flex flex-col items-center justify-center my-2",
        className
      )}
    >
      <div className="w-12 h-12 rounded-xl border-2 border-[#1D3557] bg-white flex items-center justify-center text-[#457B9D] shadow-[3px_3px_0px_#1D3557] mb-3">
        <Icon className="w-6 h-6" />
      </div>

      {badge && (
        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-[#1D3557] bg-[#A8DADC] text-[#1D3557] shadow-[2px_2px_0px_#1D3557] mb-2 uppercase">
          {badge}
        </span>
      )}

      <h4 className="font-heading font-extrabold text-sm sm:text-base text-[#1D3557]">
        {title}
      </h4>

      <p className="text-xs text-[#457B9D] max-w-sm mt-1 leading-relaxed">
        {description}
      </p>

      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

