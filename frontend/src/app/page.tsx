"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  Network,
  Radar,
  Server,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Radio,
  Clock,
  Layers,
  Cpu,
} from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoGrid } from "@/components/BentoGrid";
import { BentoCard } from "@/components/BentoCard";
import { MetricCard } from "@/components/MetricCard";
import { StatusIndicator } from "@/components/StatusIndicator";
import { NetworkTrafficChart } from "@/components/NetworkTrafficChart";
import { ProtocolDistributionChart } from "@/components/ProtocolDistributionChart";
import { LoadingState } from "@/components/LoadingState";
import { ErrorState } from "@/components/ErrorState";
import { EmptyState } from "@/components/EmptyState";
import { useNetworkData } from "@/hooks/useNetworkData";
import { apiClient } from "@/lib/api";
import { ScanExecutionResponse } from "@/lib/types";
import { formatBytes, formatPackets, formatSpeed } from "@/lib/formatters";

export default function OverviewPage() {
  const {
    health,
    interfaces,
    summary,
    scanner,
    traffic,
    loading,
    error,
    refresh,
    isRefreshing,
  } = useNetworkData(8000);

  const [latestScan, setLatestScan] = useState<ScanExecutionResponse | null>(null);

  const fetchLatestScan = useCallback(async () => {
    try {
      const scan = await apiClient.getLatestScan();
      setLatestScan(scan);
    } catch {
      // Ignore background latest scan errors
    }
  }, []);

  useEffect(() => {
    fetchLatestScan();
  }, [fetchLatestScan]);

  if (loading && !health && !summary) {
    return (
      <DashboardLayout>
        <LoadingState
          message="Connecting to Ashlynx Security Station..."
          subtext="Discovering host interfaces and hardware counters"
        />
      </DashboardLayout>
    );
  }

  const isBackendLive = !!health && health.backend_status === "operational";
  const activeInterfacesCount = interfaces.filter((i) => i.is_up).length;

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Header Hero Banner with Bento Neo Styling */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <span className="w-2 h-2 rounded-full bg-[#10b981] border border-[#1D3557]" />
              <span>STATION ONLINE</span>
              <span>•</span>
              <span>NODE 127.0.0.1</span>
            </div>
            <h1 className="font-heading font-extrabold text-2xl sm:text-3xl text-[#1D3557] tracking-tight">
              NETWORK OVERVIEW
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Network visibility and security intelligence.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557] text-xs font-mono">
              <span className="text-[#457B9D] font-bold mr-1.5">OS:</span>
              <span className="font-bold text-[#1D3557]">
                {health?.operating_system || "Host Environment"}
              </span>
            </div>
            <div className="px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-[#A8DADC] shadow-[2px_2px_0px_#1D3557] text-xs font-mono">
              <span className="text-[#1D3557] font-bold mr-1.5">PY RUNTIME:</span>
              <span className="font-extrabold text-[#1D3557]">
                {health?.python_version || "3.x"}
              </span>
            </div>
          </div>
        </div>

        {/* Global Connection Error State if Backend is unreachable */}
        {error && (
          <ErrorState
            title="API Gateway Communication Interrupted"
            message={error}
            onRetry={refresh}
            isRetrying={isRefreshing}
          />
        )}

        {/* TOP BENTO ROW: 4 Core Metric Cards */}
        <BentoGrid cols={4}>
          {/* Bento Card A: Network Status */}
          <MetricCard
            label="Backend Connectivity"
            value={isBackendLive ? "ONLINE" : "OFFLINE"}
            subtext="Localhost 127.0.0.1:8000"
            icon={Server}
            variant={isBackendLive ? "aqua" : "coral"}
            trend={{
              value: isBackendLive ? "UP" : "DOWN",
              isPositive: isBackendLive,
            }}
          />

          {/* Bento Card B: Packets Captured */}
          <MetricCard
            label="Total Packets Processed"
            value={
              summary
                ? formatPackets(summary.packets_sent + summary.packets_recv)
                : "0"
            }
            unit="pkts"
            subtext={`TX: ${formatPackets(summary?.packets_sent || 0)} / RX: ${formatPackets(summary?.packets_recv || 0)}`}
            icon={Activity}
            variant="white"
          />

          {/* Bento Card C: Bandwidth Transferred */}
          <MetricCard
            label="Total Data Throughput"
            value={
              summary
                ? formatBytes(summary.bytes_sent + summary.bytes_recv).split(" ")[0]
                : "0"
            }
            unit={
              summary
                ? formatBytes(summary.bytes_sent + summary.bytes_recv).split(" ")[1]
                : "B"
            }
            subtext={`RX: ${formatBytes(summary?.bytes_recv || 0)} | TX: ${formatBytes(summary?.bytes_sent || 0)}`}
            icon={ArrowDownLeft}
            variant="white"
          />

          {/* Bento Card D: Active Network Interfaces */}
          <MetricCard
            label="Active Interfaces"
            value={`${activeInterfacesCount} / ${interfaces.length}`}
            unit="NICs"
            subtext="Physical and virtual adapters"
            icon={Network}
            variant="white"
          />
        </BentoGrid>

        {/* MAIN BENTO ROW: Analytics & Engine Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Bento Card E: Network Traffic Analytics (8 cols) */}
          <BentoCard
            title="NETWORK TRAFFIC ANALYTICS"
            subtitle="Time-series ingress and egress bandwidth utilization"
            colSpan="col-span-12"
            className="lg:col-span-8"
            dotGrid
            action={
              <div className="flex items-center gap-2">
                <StatusIndicator
                  status={summary ? "operational" : "standby"}
                  label="TELEMETRY FEED"
                />
              </div>
            }
          >
            {summary ? (
              <NetworkTrafficChart
                bytesSent={summary.bytes_sent}
                bytesRecv={summary.bytes_recv}
                packetsSent={summary.packets_sent}
                packetsRecv={summary.packets_recv}
              />
            ) : (
              <EmptyState
                title="Telemetry Counters Unavailable"
                description="Unable to query host network counters from psutil drivers."
              />
            )}
          </BentoCard>

          {/* Bento Card F: Protocol Distribution (4 cols) */}
          <BentoCard
            title="PROTOCOL DISTRIBUTION"
            subtitle="Engine B packet breakdown"
            colSpan="col-span-12"
            className="lg:col-span-4"
            action={
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-[#1D3557] bg-[#A8DADC] text-[#1D3557]">
                PHASE 1
              </span>
            }
          >
            <ProtocolDistributionChart isLive={false} />
          </BentoCard>
        </div>

        {/* SECOND BENTO ROW: Port Scan Summary + Security Events + Interfaces */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Bento Card D: Port Scan Summary (4 cols) */}
          <BentoCard
            title="PORT SCAN SUMMARY"
            subtitle="Engine A TCP Connect discovery statistics"
            colSpan="col-span-12"
            className="lg:col-span-4"
            variant="white"
            action={
              <Link
                href="/scanner"
                className="text-[11px] font-mono font-bold text-[#457B9D] hover:underline flex items-center gap-1"
              >
                <span>Launch Scanner</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            }
          >
            <div className="space-y-3 my-auto">
              {/* Operational Status */}
              <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] flex items-center justify-between font-mono">
                <span className="text-xs font-bold text-[#1D3557]">
                  Scanner Engine Status
                </span>
                <span className="text-[10px] font-extrabold px-2 py-0.5 rounded border border-[#1D3557] bg-[#dcfce7] text-[#166534]">
                  {scanner?.status ? scanner.status.toUpperCase() : "OPERATIONAL"}
                </span>
              </div>

              {latestScan ? (
                <>
                  <div className="grid grid-cols-2 gap-2 text-center font-mono">
                    <div className="p-2.5 rounded-lg border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                      <span className="block text-[10px] text-[#457B9D] uppercase font-bold">
                        Open Ports
                      </span>
                      <span className="font-heading font-extrabold text-xl text-[#10b981]">
                        {latestScan.open_ports}
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                      <span className="block text-[10px] text-[#457B9D] uppercase font-bold">
                        Closed Ports
                      </span>
                      <span className="font-heading font-extrabold text-xl text-[#1D3557]">
                        {latestScan.closed_ports}
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                      <span className="block text-[10px] text-[#457B9D] uppercase font-bold">
                        Filtered
                      </span>
                      <span className="font-heading font-extrabold text-xl text-[#f59e0b]">
                        {latestScan.filtered_or_unknown_ports}
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                      <span className="block text-[10px] text-[#457B9D] uppercase font-bold">
                        Scanned Ports
                      </span>
                      <span className="font-heading font-extrabold text-xl text-[#457B9D]">
                        {latestScan.total_ports}
                      </span>
                    </div>
                  </div>

                  <div className="text-[10px] font-mono text-[#457B9D] flex justify-between pt-1 border-t border-[#1D3557]/10">
                    <span>Target: <strong>{latestScan.target}</strong></span>
                    <span>Duration: <strong>{latestScan.duration_seconds}s</strong></span>
                  </div>
                </>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-2 text-center font-mono">
                    <div className="p-2.5 rounded-lg border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                      <span className="block text-[10px] text-[#457B9D] uppercase font-bold">
                        Open Ports
                      </span>
                      <span className="font-heading font-extrabold text-xl text-[#10b981]">
                        0
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                      <span className="block text-[10px] text-[#457B9D] uppercase font-bold">
                        Closed Ports
                      </span>
                      <span className="font-heading font-extrabold text-xl text-[#1D3557]">
                        0
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                      <span className="block text-[10px] text-[#457B9D] uppercase font-bold">
                        Filtered
                      </span>
                      <span className="font-heading font-extrabold text-xl text-[#f59e0b]">
                        0
                      </span>
                    </div>
                    <div className="p-2.5 rounded-lg border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                      <span className="block text-[10px] text-[#457B9D] uppercase font-bold">
                        Scanned Ports
                      </span>
                      <span className="font-heading font-extrabold text-xl text-[#457B9D]">
                        0
                      </span>
                    </div>
                  </div>

                  <p className="text-[11px] text-[#457B9D] font-medium leading-relaxed">
                    Engine A is ready. No scan session executed yet in this session.
                  </p>
                </>
              )}
            </div>
          </BentoCard>

          {/* Bento Card H: Network Interfaces (5 cols) */}
          <BentoCard
            title="NETWORK INTERFACES"
            subtitle="Discovered hardware and logical adapters"
            colSpan="col-span-12"
            className="lg:col-span-5"
            action={
              <Link
                href="/interfaces"
                className="text-[11px] font-mono font-bold text-[#457B9D] hover:underline flex items-center gap-1"
              >
                <span>View All ({interfaces.length})</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            }
          >
            {interfaces.length === 0 ? (
              <EmptyState
                title="No Network Adapters"
                description="Operating system reports zero accessible interfaces."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-[#1D3557]/30 text-[#457B9D] uppercase text-[10px] font-bold">
                      <th className="pb-2">Name</th>
                      <th className="pb-2">IPv4</th>
                      <th className="pb-2">State</th>
                      <th className="pb-2 text-right">Speed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1D3557]/10 text-[#1D3557]">
                    {interfaces.slice(0, 4).map((iface) => (
                      <tr key={iface.name} className="hover:bg-[#F1FAEE]/60">
                        <td className="py-2 font-bold truncate max-w-[110px]" title={iface.name}>
                          {iface.name}
                        </td>
                        <td className="py-2 text-[#457B9D]">
                          {iface.ipv4_address || "None"}
                        </td>
                        <td className="py-2">
                          {iface.is_up ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-[#10b981]">
                              <span className="w-1.5 h-1.5 rounded-full bg-[#10b981]" />
                              UP
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold text-slate-400">
                              <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                              DOWN
                            </span>
                          )}
                        </td>
                        <td className="py-2 text-right text-slate-600">
                          {formatSpeed(iface.speed_mbps)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </BentoCard>

          {/* Bento Card G: Security Events (3 cols) */}
          <BentoCard
            title="SECURITY OBSERVATIONS"
            subtitle="Platform operational log"
            colSpan="col-span-12"
            className="lg:col-span-3"
            action={
              <Link
                href="/events"
                className="text-[11px] font-mono font-bold text-[#457B9D] hover:underline flex items-center gap-1"
              >
                <span>Timeline</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            }
          >
            <div className="space-y-2.5 font-mono text-xs">
              <div className="p-2 rounded border border-[#1D3557] bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]">
                <div className="flex items-center justify-between text-[10px] font-bold text-[#10b981]">
                  <span>[ENGINE_A] TCP OPERATIONAL</span>
                  <span>ONLINE</span>
                </div>
                <p className="text-[11px] text-[#1D3557] mt-0.5 font-sans font-medium">
                  TCP Connect scanner engine active with safe-mode target boundaries.
                </p>
              </div>

              <div className="p-2 rounded border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                <div className="flex items-center justify-between text-[10px] font-bold text-[#457B9D]">
                  <span>[GUARDRAIL] SAFE SCOPE</span>
                  <span>ENFORCED</span>
                </div>
                <p className="text-[11px] text-[#1D3557] mt-0.5 font-sans font-medium">
                  Public IP probing blocked. RFC-1918 and loopback targets only.
                </p>
              </div>

              <div className="p-2 rounded border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                <div className="flex items-center justify-between text-[10px] font-bold text-[#f59e0b]">
                  <span>[ENGINE_B] SNIFFER</span>
                  <span>STANDBY</span>
                </div>
                <p className="text-[11px] text-[#1D3557] mt-0.5 font-sans font-medium">
                  Wire sniffer scheduled for activation in Phase 3.
                </p>
              </div>
            </div>
          </BentoCard>
        </div>
      </div>
    </DashboardLayout>
  );
}
