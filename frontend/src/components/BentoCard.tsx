import React, { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface BentoCardProps {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  variant?: "white" | "aqua" | "soft" | "navy";
  colSpan?: "col-span-1" | "col-span-2" | "col-span-3" | "col-span-4" | "col-span-5" | "col-span-6" | "col-span-7" | "col-span-8" | "col-span-9" | "col-span-12";
  dotGrid?: boolean;
  className?: string;
  bodyClassName?: string;
  interactive?: boolean;
  onClick?: () => void;
}

export function BentoCard({
  title,
  subtitle,
  action,
  children,
  variant = "white",
  colSpan,
  dotGrid = false,
  className,
  bodyClassName,
  interactive = false,
  onClick,
}: BentoCardProps) {
  const variantStyles = {
    white: "bg-white text-[#1D3557]",
    aqua: "bg-[#A8DADC] text-[#1D3557]",
    soft: "bg-[#F1FAEE] text-[#1D3557]",
    navy: "bg-[#1D3557] text-[#F1FAEE] border-[#1D3557]",
  }[variant];

  return (
    <div
      onClick={onClick}
      className={cn(
        "rounded-xl border-2 border-[#1D3557] shadow-[4px_4px_0px_#1D3557] flex flex-col overflow-hidden transition-all duration-150 min-w-0 w-full",
        variantStyles,
        interactive && "cursor-pointer hover:-translate-x-0.5 hover:-translate-y-0.5 hover:shadow-[5px_5px_0px_#1D3557]",
        dotGrid && "bg-dot-grid",
        colSpan,
        className
      )}
    >
      {(title || action) && (
        <div
          className={cn(
            "px-4 py-3 border-b-2 border-[#1D3557] flex flex-wrap items-center justify-between gap-2.5 sm:gap-3 shrink-0 min-w-0",
            variant === "aqua" ? "bg-[#A8DADC]/80" : variant === "navy" ? "bg-[#1D3557]" : "bg-white/90"
          )}
        >
          <div className="min-w-0 flex-1">
            {title && (
              <h3 className="font-heading font-extrabold text-xs sm:text-sm tracking-wider uppercase text-[#1D3557] truncate">
                {variant === "navy" ? (
                  <span className="text-[#F1FAEE]">{title}</span>
                ) : (
                  title
                )}
              </h3>
            )}
            {subtitle && (
              <p
                className={cn(
                  "text-[11px] font-medium leading-tight mt-0.5 line-clamp-2",
                  variant === "navy" ? "text-[#A8DADC]" : "text-[#457B9D]"
                )}
              >
                {subtitle}
              </p>
            )}
          </div>
          {action && <div className="flex flex-wrap items-center gap-1.5 shrink-0 min-w-0">{action}</div>}
        </div>
      )}

      <div className={cn("p-4 flex-1 flex flex-col min-w-0 w-full overflow-hidden", bodyClassName)}>
        {children}
      </div>
    </div>
  );
}

