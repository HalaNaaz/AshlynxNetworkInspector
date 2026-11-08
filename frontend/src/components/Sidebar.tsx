"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Radar,
  Activity,
  Settings,
  ShieldAlert,
  Server,
} from "lucide-react";

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

const navItems: NavItem[] = [
  {
    name: "Dashboard",
    href: "/",
    icon: LayoutDashboard,
  },
  {
    name: "Port Scanner",
    href: "/scanner",
    icon: Radar,
    badge: "Engine A",
  },
  {
    name: "Traffic Analyzer",
    href: "/traffic",
    icon: Activity,
    badge: "Engine B",
  },
  {
    name: "Settings",
    href: "/settings",
    icon: Settings,
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 border-r border-slate-800/80 bg-[#070b12] flex flex-col shrink-0 min-h-screen">
      {/* Brand Header */}
      <div className="h-14 px-5 border-b border-slate-800/80 flex items-center gap-3 bg-[#090d16]">
        <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-mono font-bold text-sm">
          A
        </div>
        <div>
          <div className="text-xs font-bold tracking-wider text-slate-100 font-mono uppercase">
            ASHLYNX INSPECTOR
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-cyan-400 font-mono">ANI v0.1.0</span>
            <span className="text-[9px] px-1 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">
              PHASE 1
            </span>
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="p-3 space-y-1 flex-1">
        <div className="px-3 py-2 text-[10px] font-mono tracking-widest text-slate-500 uppercase">
          Core Engines
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-colors ${
                isActive
                  ? "bg-cyan-950/40 text-cyan-400 border border-cyan-800/50"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? "text-cyan-400" : "text-slate-500"
                  }`}
                />
                <span>{item.name}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                    isActive
                      ? "text-cyan-300 border-cyan-700/60 bg-cyan-900/30"
                      : "text-slate-500 border-slate-800 bg-slate-900"
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Security Context Notice */}
      <div className="p-4 border-t border-slate-800/80 bg-[#080d15] text-[11px] text-slate-400 space-y-2">
        <div className="flex items-center gap-2 text-slate-300 font-semibold font-mono text-xs">
          <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
          <span>Security Guardrails</span>
        </div>
        <p className="text-[10px] text-slate-500 leading-normal">
          Non-destructive reconnaissance. Scans bounded to authorized ranges. No raw payload retention.
        </p>
        <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
          <Server className="w-3 h-3 text-emerald-400" />
          <span>Binding: Localhost 127.0.0.1</span>
        </div>
      </div>
    </aside>
  );
}

