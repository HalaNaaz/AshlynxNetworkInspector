"use client";

import React, { useState } from "react";
import { Settings as SettingsIcon, Server, Shield, Sliders, Database, Save, Check } from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoCard } from "@/components/BentoCard";
import { BentoGrid } from "@/components/BentoGrid";
import { StatusIndicator } from "@/components/StatusIndicator";
import { useNetworkData } from "@/hooks/useNetworkData";
import { apiClient } from "@/lib/api";

export default function SettingsPage() {
  const { health } = useNetworkData(0);
  const [backendUrl, setBackendUrl] = useState(apiClient.getBaseUrl());
  const [maxConcurrency, setMaxConcurrency] = useState("50");
  const [scanTimeout, setScanTimeout] = useState("1.5");
  const [captureBuffer, setCaptureBuffer] = useState("1000");
  const [savedNotice, setSavedNotice] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  };

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-5xl mx-auto">
        {/* Page Hero Banner */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <SettingsIcon className="w-4 h-4 text-[#457B9D]" />
              <span>CONFIGURATION & GUARDRAILS</span>
            </div>
            <h1 className="font-heading font-extrabold text-2xl text-[#1D3557] tracking-tight">
              PLATFORM SETTINGS
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Manage API connectivity, security ranges, and engine operational parameters.
            </p>
          </div>

          <StatusIndicator
            status="operational"
            label={`VERSION: v${health?.version || "0.1.0"}`}
          />
        </div>

        {savedNotice && (
          <div className="p-3.5 rounded-lg border-2 border-[#10b981] bg-[#dcfce7] shadow-[3px_3px_0px_#10b981] flex items-center gap-2 text-xs font-mono font-bold text-[#166534]">
            <Check className="w-4 h-4" />
            <span>Settings cached locally in session.</span>
          </div>
        )}

        <form onSubmit={handleSave} className="space-y-6">
          {/* API Gateway Connection Bento Card */}
          <BentoCard
            title="API GATEWAY CONNECTION"
            subtitle="FastAPI backend host and service resolution"
            dotGrid
            action={
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-[#1D3557] bg-[#F1FAEE] text-[#1D3557]">
                CORE BINDING: 127.0.0.1
              </span>
            }
          >
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
              <div className="space-y-1.5">
                <label className="block font-bold text-[#1D3557]">
                  Backend API Base URL
                </label>
                <input
                  type="text"
                  value={backendUrl}
                  onChange={(e) => setBackendUrl(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]"
                />
                <span className="text-[10px] text-[#457B9D] block font-sans">
                  Configured through NEXT_PUBLIC_API_BASE_URL.
                </span>
              </div>

              <div className="space-y-1.5">
                <label className="block font-bold text-[#1D3557]">
                  Host Environment & Python
                </label>
                <div className="px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-bold">
                  {health?.operating_system || "Host Environment"} • Python {health?.python_version || "3.x"}
                </div>
                <span className="text-[10px] text-[#457B9D] block font-sans">
                  Reported by backend diagnostics endpoint.
                </span>
              </div>
            </div>
          </BentoCard>

          {/* Engine A & Engine B Defaults Bento Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Engine A: Scanner Defaults */}
            <BentoCard
              title="ENGINE A: SCANNER DEFAULTS"
              subtitle="Default socket latency and thread boundaries"
              variant="white"
            >
              <div className="space-y-4 font-mono text-xs">
                <div className="space-y-1.5">
                  <label className="block font-bold text-[#1D3557]">
                    Socket Timeout (seconds)
                  </label>
                  <input
                    type="number"
                    step="0.1"
                    value={scanTimeout}
                    onChange={(e) => setScanTimeout(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]"
                  />
                  <span className="text-[10px] text-[#457B9D] block font-sans">
                    TCP connect timeout per destination socket.
                  </span>
                </div>

                <div className="space-y-1.5">
                  <label className="block font-bold text-[#1D3557]">
                    Maximum Concurrent Threads
                  </label>
                  <input
                    type="number"
                    value={maxConcurrency}
                    onChange={(e) => setMaxConcurrency(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]"
                  />
                  <span className="text-[10px] text-[#457B9D] block font-sans">
                    Worker thread pool allocation.
                  </span>
                </div>

                <div className="p-2.5 rounded-lg border border-[#1D3557] bg-[#F1FAEE] text-[11px] font-sans">
                  <strong>Permitted Scopes:</strong> 127.0.0.1/32, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                </div>
              </div>
            </BentoCard>

            {/* Engine B: Sniffer Defaults */}
            <BentoCard
              title="ENGINE B: ANALYZER DEFAULTS"
              subtitle="Frame queue sizing and security privacy policy"
              variant="aqua"
            >
              <div className="space-y-4 font-mono text-xs">
                <div className="space-y-1.5">
                  <label className="block font-bold text-[#1D3557]">
                    In-Memory Frame Ring Buffer
                  </label>
                  <input
                    type="number"
                    value={captureBuffer}
                    onChange={(e) => setCaptureBuffer(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]"
                  />
                  <span className="text-[10px] text-[#1D3557] block font-sans">
                    Maximum frames buffered in memory before FIFO rotation.
                  </span>
                </div>

                <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                  <span className="font-heading font-extrabold text-xs text-[#E63946] block">
                    Payload Storage Policy: STRICTLY DISABLED
                  </span>
                  <p className="text-[11px] text-[#457B9D] mt-1 font-sans">
                    Payload bytes are dropped at the wire capture boundary. Only L2-L4 header fields and timing stats are retained.
                  </p>
                </div>
              </div>
            </BentoCard>
          </div>

          {/* Database & Save Actions */}
          <div className="p-4 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2 text-xs font-mono text-[#457B9D]">
              <Database className="w-4 h-4 text-[#1D3557]" />
              <span>Target DB: <strong className="text-[#1D3557]">SQLite (ani.db)</strong></span>
            </div>

            <button
              type="submit"
              className="btn-primary flex items-center gap-2 px-5 py-2 text-xs font-mono"
            >
              <Save className="w-4 h-4" />
              Save Settings
            </button>
          </div>
        </form>
      </div>
    </DashboardLayout>
  );
}
