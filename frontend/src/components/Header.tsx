"use client";

import React from "react";
import { Shield, RefreshCw, Radio, Terminal } from "lucide-react";

interface HeaderProps {
  backendOnline: boolean;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  lastUpdated?: Date | null;
}

export function Header({
  backendOnline,
  onRefresh,
  isRefreshing = false,
  lastUpdated,
}: HeaderProps) {
  return (
    <header className="h-14 border-b border-slate-800/80 bg-[#0b0f17]/80 backdrop-blur px-6 flex items-center justify-between sticky top-0 z-20">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-cyan-400">
          <Shield className="w-5 h-5 text-cyan-400" />
          <span className="text-xs font-mono tracking-widest text-slate-400 uppercase">
            Security Operations Console
          </span>
        </div>
      </div>

      <div className="flex items-center gap-4 text-xs font-mono">
        <div className="flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900/60 border border-slate-800/80">
          <Radio
            className={`w-3.5 h-3.5 ${
              backendOnline ? "text-emerald-400 animate-pulse" : "text-rose-500"
            }`}
          />
          <span className="text-slate-400">API:</span>
          <span
            className={
              backendOnline
                ? "text-emerald-400 font-semibold"
                : "text-rose-400 font-semibold"
            }
          >
            {backendOnline ? "127.0.0.1:8000 (CONNECTED)" : "DISCONNECTED"}
          </span>
        </div>

        {lastUpdated && (
          <span className="text-slate-500 hidden sm:inline">
            Updated: {lastUpdated.toLocaleTimeString()}
          </span>
        )}

        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700/50 transition-colors disabled:opacity-50"
            title="Refresh system metrics"
          >
            <RefreshCw
              className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-cyan-400" : ""}`}
            />
            <span className="hidden sm:inline">Poll Now</span>
          </button>
        )}
      </div>
    </header>
  );
}

