import React from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  isRetrying?: boolean;
  className?: string;
}

export function ErrorState({
  title = "Backend Service Unavailable",
  message,
  onRetry,
  isRetrying = false,
  className,
}: ErrorStateProps) {
  return (
    <div
      className={cn(
        "p-5 rounded-xl border-2 border-[#E63946] bg-[#ffe4e6] shadow-[4px_4px_0px_#E63946] text-[#1D3557]",
        className
      )}
    >
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="w-9 h-9 rounded-lg border-2 border-[#E63946] bg-white text-[#E63946] flex items-center justify-center shrink-0 shadow-[2px_2px_0px_#E63946]">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <h4 className="font-heading font-extrabold text-sm text-[#E63946]">
              {title}
            </h4>
            <p className="text-xs text-[#1D3557] font-medium mt-0.5 leading-relaxed">
              {message}
            </p>
          </div>
        </div>

        {onRetry && (
          <button
            onClick={onRetry}
            disabled={isRetrying}
            className="btn-danger flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-mono font-bold shrink-0 self-end sm:self-auto"
          >
            <RefreshCw
              className={cn("w-3.5 h-3.5", isRetrying && "animate-spin")}
            />
            {isRetrying ? "Reconnecting..." : "Retry Connection"}
          </button>
        )}
      </div>
    </div>
  );
}
