"use client";

import React from "react";
import { usePathname } from "next/navigation";
import { RefreshCw, Radio, User, ChevronRight, Menu } from "lucide-react";
import { StatusIndicator } from "./StatusIndicator";
import { cn } from "@/lib/utils";

interface AppHeaderProps {
  backendOnline: boolean;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  lastUpdated?: Date | null;
  onToggleSidebar?: () => void;
}

export function AppHeader({
  backendOnline,
  onRefresh,
  isRefreshing = false,
  lastUpdated,
  onToggleSidebar,
}: AppHeaderProps) {
  const pathname = usePathname();

  // Route to title map
  const pageTitles: Record<string, { title: string; crumb: string }> = {
    "/": { title: "NETWORK OVERVIEW", crumb: "Overview" },
    "/scanner": { title: "PORT SCANNER", crumb: "Port Scanner" },
    "/traffic": { title: "TRAFFIC ANALYZER", crumb: "Traffic Analyzer" },
    "/interfaces": { title: "NETWORK INTERFACES", crumb: "Network Interfaces" },
    "/discovery": { title: "HOST DISCOVERY", crumb: "Host Discovery" },
    "/history": { title: "SCAN HISTORY", crumb: "Scan History" },
    "/events": { title: "SECURITY EVENTS", crumb: "Security Events" },
    "/reports": { title: "SECURITY REPORTS", crumb: "Reports" },
    "/settings": { title: "SETTINGS & GUARDRAILS", crumb: "Settings" },
  };

  const current = pageTitles[pathname] || {
    title: "WORKSTATION",
    crumb: pathname.replace("/", ""),
  };

  return (
    <header className="h-16 border-b-2 border-[#1D3557] bg-white px-4 sm:px-6 flex items-center justify-between sticky top-0 z-20 shadow-[0px_2px_0px_rgba(29,53,87,0.05)]">
      {/* Left: Mobile Toggle & Breadcrumbs */}
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="md:hidden p-1.5 rounded border-2 border-[#1D3557] bg-white text-[#1D3557] shadow-[2px_2px_0px_#1D3557]"
          >
            <Menu className="w-4 h-4" />
          </button>
        )}

        <div className="flex flex-col">
          <div className="flex items-center gap-1.5 text-[10px] font-mono text-[#457B9D] uppercase tracking-wider">
            <span>ANI</span>
            <ChevronRight className="w-3 h-3 text-[#1D3557]" />
            <span className="font-bold text-[#1D3557]">{current.crumb}</span>
          </div>
          <h1 className="font-heading font-extrabold text-sm sm:text-base text-[#1D3557] tracking-tight leading-none">
            {current.title}
          </h1>
        </div>
      </div>

      {/* Right: Telemetry & Actions */}
      <div className="flex items-center gap-3 sm:gap-4 text-xs font-mono">
        {/* Backend Connectivity Status */}
        <div className="hidden sm:flex items-center gap-2">
          <StatusIndicator
            status={backendOnline ? "operational" : "critical"}
            label={backendOnline ? "API: 127.0.0.1 (CONNECTED)" : "API: DISCONNECTED"}
            pulse={backendOnline}
          />
        </div>

        {/* Polling / Refresh Button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="btn-secondary flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-bold"
            title="Poll fresh system telemetry"
          >
            <RefreshCw
              className={cn("w-3.5 h-3.5", isRefreshing && "animate-spin text-[#457B9D]")}
            />
            <span className="hidden md:inline">
              {isRefreshing ? "Polling..." : "Poll Now"}
            </span>
          </button>
        )}

        {/* User Profile Section */}
        <div className="flex items-center gap-2 pl-3 border-l-2 border-[#1D3557]/20">
          <div className="w-8 h-8 rounded-lg border-2 border-[#1D3557] bg-[#A8DADC] text-[#1D3557] flex items-center justify-center font-mono font-bold text-xs shadow-[2px_2px_0px_#1D3557]">
            <User className="w-4 h-4" />
          </div>
          <div className="hidden lg:flex flex-col leading-tight">
            <span className="font-heading font-extrabold text-xs text-[#1D3557]">
              SEC_ANALYST
            </span>
            <span className="text-[10px] text-[#457B9D] font-bold">
              ADMIN TIER
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}

