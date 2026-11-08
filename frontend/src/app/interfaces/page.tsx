"use client";

import React from "react";
import { Network, Wifi, Activity, CheckCircle2, XCircle, ArrowUpRight, ArrowDownLeft } from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoCard } from "@/components/BentoCard";
import { BentoGrid } from "@/components/BentoGrid";
import { MetricCard } from "@/components/MetricCard";
import { StatusIndicator } from "@/components/StatusIndicator";
import { EmptyState } from "@/components/EmptyState";
import { useNetworkData } from "@/hooks/useNetworkData";
import { formatSpeed } from "@/lib/formatters";

export default function InterfacesPage() {
  const { interfaces, loading } = useNetworkData(0);

  const activeCount = interfaces.filter((i) => i.is_up).length;
  const loopbackCount = interfaces.filter(
    (i) => i.name.toLowerCase().includes("loopback") || i.ipv4_address === "127.0.0.1"
  ).length;

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-6xl mx-auto">
        {/* Page Hero Banner */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <Network className="w-4 h-4 text-[#457B9D]" />
              <span>HARDWARE & ADAPTERS</span>
            </div>
            <h1 className="font-heading font-extrabold text-2xl text-[#1D3557] tracking-tight">
              HOST NETWORK INTERFACES
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Discovered physical, virtual, and loopback network controllers.
            </p>
          </div>

          <StatusIndicator
            status={activeCount > 0 ? "operational" : "warning"}
            label={`${activeCount} ACTIVE / ${interfaces.length} TOTAL`}
          />
        </div>

        {/* Top Metric Cards */}
        <BentoGrid cols={3}>
          <MetricCard
            label="Total Detected Adapters"
            value={interfaces.length}
            unit="NICs"
            subtext="Discovered via psutil kernel hooks"
            icon={Network}
            variant="white"
          />

          <MetricCard
            label="Operational Up State"
            value={activeCount}
            unit="Active"
            subtext="Transmitting carrier link"
            icon={Activity}
            variant="aqua"
          />

          <MetricCard
            label="Loopback Adapters"
            value={loopbackCount}
            unit="Local"
            subtext="Internal socket communication"
            icon={Wifi}
            variant="white"
          />
        </BentoGrid>

        {/* Detailed Interface Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {interfaces.map((iface) => (
            <BentoCard
              key={iface.name}
              title={iface.name}
              subtitle={iface.ipv4_address ? `IPv4: ${iface.ipv4_address}` : "Unassigned IPv4"}
              dotGrid
              action={
                <StatusIndicator
                  status={iface.is_up ? "operational" : "offline"}
                  label={iface.is_up ? "LINK UP" : "DOWN"}
                  pulse={!!iface.is_up}
                />
              }
            >
              <div className="space-y-3 font-mono text-xs">
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2.5 rounded-lg border border-[#1D3557] bg-[#F1FAEE]">
                    <span className="text-[10px] text-[#457B9D] uppercase font-bold block">
                      MAC Address
                    </span>
                    <span className="font-bold text-[#1D3557] truncate block">
                      {iface.mac_address || "None Reported"}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg border border-[#1D3557] bg-[#F1FAEE]">
                    <span className="text-[10px] text-[#457B9D] uppercase font-bold block">
                      Link Speed
                    </span>
                    <span className="font-bold text-[#1D3557] block">
                      {formatSpeed(iface.speed_mbps)}
                    </span>
                  </div>
                </div>

                <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557] text-[11px] space-y-1">
                  <div className="flex justify-between text-[#1D3557]">
                    <span className="font-bold">Carrier Status:</span>
                    <span>{iface.is_up ? "Connected" : "Disconnected / Idle"}</span>
                  </div>
                  <div className="flex justify-between text-[#1D3557]">
                    <span className="font-bold">Packet Capture Eligible:</span>
                    <span className="text-[#10b981] font-bold">YES (Engine B Ready)</span>
                  </div>
                </div>
              </div>
            </BentoCard>
          ))}
        </div>
      </div>
    </DashboardLayout>
  );
}

