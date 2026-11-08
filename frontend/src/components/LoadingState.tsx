import React from "react";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface LoadingStateProps {
  message?: string;
  subtext?: string;
  className?: string;
}

export function LoadingState({
  message = "Loading system telemetry...",
  subtext = "Querying Ashlynx Network Inspector backend services",
  className,
}: LoadingStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center p-12 text-center rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557]",
        className
      )}
    >
      <div className="w-10 h-10 rounded-lg border-2 border-[#1D3557] bg-[#A8DADC] flex items-center justify-center text-[#1D3557] shadow-[2px_2px_0px_#1D3557] mb-3 animate-spin">
        <Loader2 className="w-5 h-5" />
      </div>
      <h3 className="font-heading font-extrabold text-sm text-[#1D3557]">
        {message}
      </h3>
      {subtext && (
        <p className="text-xs text-[#457B9D] mt-1 font-medium">{subtext}</p>
      )}
    </div>
  );
}
