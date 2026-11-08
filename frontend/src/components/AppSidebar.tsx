"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Radar,
  Activity,
  Network,
  Compass,
  History,
  ShieldAlert,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

const navItems: NavItem[] = [
  { name: "Overview", href: "/", icon: LayoutDashboard },
  { name: "Port Scanner", href: "/scanner", icon: Radar, badge: "Engine A" },
  { name: "Traffic Analyzer", href: "/traffic", icon: Activity, badge: "Engine B" },
  { name: "Network Interfaces", href: "/interfaces", icon: Network },
  { name: "Host Discovery", href: "/discovery", icon: Compass, badge: "Engine C" },
  { name: "Scan History", href: "/history", icon: History },
  { name: "Security Events", href: "/events", icon: ShieldAlert },
  { name: "Reports", href: "/reports", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
];

interface AppSidebarProps {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

export function AppSidebar({
  collapsed = false,
  onToggleCollapse,
}: AppSidebarProps) {
  const pathname = usePathname();

  return (
    <aside
      className={cn(
        "bg-white border-r-2 border-[#1D3557] flex flex-col shrink-0 min-h-screen transition-all duration-200 z-30 select-none shadow-[2px_0px_0px_rgba(29,53,87,0.05)]",
        collapsed ? "w-20" : "w-64"
      )}
    >
      {/* Brand Header */}
      <div className="h-16 px-4 border-b-2 border-[#1D3557] flex items-center justify-between bg-[#F1FAEE]">
        <Link href="/" className="flex items-center gap-2.5 overflow-hidden">
          <div className="w-9 h-9 rounded-lg border-2 border-[#1D3557] bg-[#457B9D] flex items-center justify-center text-white font-mono font-extrabold text-base shadow-[2px_2px_0px_#1D3557] shrink-0">
            A
          </div>
          {!collapsed && (
            <div className="leading-tight">
              <span className="font-heading font-extrabold text-sm tracking-wider uppercase text-[#1D3557] block">
                ASHLYNX
              </span>
              <span className="text-[10px] font-mono font-bold text-[#457B9D] tracking-widest block uppercase">
                NETWORK INSPECTOR
              </span>
            </div>
          )}
        </Link>

        {onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            aria-label="Toggle Sidebar"
            className="w-7 h-7 rounded border-2 border-[#1D3557] bg-white flex items-center justify-center text-[#1D3557] hover:bg-[#A8DADC] shadow-[2px_2px_0px_#1D3557] transition-colors"
          >
            {collapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="p-3 space-y-1.5 flex-1 overflow-y-auto">
        {!collapsed && (
          <div className="px-3 py-1.5 text-[10px] font-heading font-extrabold tracking-widest text-[#457B9D] uppercase">
            Workstation
          </div>
        )}

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive =
            item.href === "/"
              ? pathname === "/"
              : pathname.startsWith(item.href);

          return (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.name : undefined}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-heading font-bold transition-all duration-100",
                isActive
                  ? "bg-[#457B9D] text-white border-2 border-[#1D3557] shadow-[3px_3px_0px_#1D3557] -translate-x-0.5 -translate-y-0.5"
                  : "text-[#1D3557] hover:bg-[#F1FAEE] hover:border-2 hover:border-[#1D3557]/40 border-2 border-transparent"
              )}
            >
              <Icon
                className={cn(
                  "w-4 h-4 shrink-0",
                  isActive ? "text-white" : "text-[#457B9D]"
                )}
              />
              {!collapsed && (
                <div className="flex-1 flex items-center justify-between">
                  <span>{item.name}</span>
                  {item.badge && (
                    <span
                      className={cn(
                        "text-[9px] font-mono font-bold px-1.5 py-0.2 rounded border",
                        isActive
                          ? "bg-[#A8DADC] text-[#1D3557] border-[#1D3557]"
                          : "bg-[#F1FAEE] text-[#457B9D] border-[#1D3557]/30"
                      )}
                    >
                      {item.badge}
                    </span>
                  )}
                </div>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Security Context Status Card in Footer */}
      {!collapsed && (
        <div className="p-3.5 m-3 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] shadow-[3px_3px_0px_#1D3557]">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#457B9D]" />
            <span className="font-heading font-extrabold text-xs text-[#1D3557]">
              Security Guardrails
            </span>
          </div>
          <p className="text-[10px] text-[#457B9D] mt-1 font-medium leading-relaxed">
            Safe-mode active. Binding restricted to localhost 127.0.0.1. No raw payloads persisted.
          </p>
        </div>
      )}
    </aside>
  );
}

