"use client";

import React from "react";
import Link from "next/link";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { Activity, AlertCircle, RefreshCw, Radio } from "lucide-react";
import { cn } from "@/lib/utils";
import { ProtocolAnalyticsResponse } from "@/lib/types";
import { formatBytes } from "@/lib/formatters";

export interface ProtocolDistributionChartProps {
  protocols?: ProtocolAnalyticsResponse | null;
  status?: "LOADING" | "LIVE" | "ARCHIVE" | "INACTIVE" | "ERROR";
  errorMessage?: string | null;
  onRetry?: () => void;
  isLive?: boolean;
  className?: string;
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "#457B9D",   // Steel Blue
  UDP: "#10B981",   // Emerald Green
  ICMP: "#E63946",  // Coral Red
  ARP: "#F59E0B",   // Amber
  OTHER: "#1D3557", // Deep Navy
};

const STANDARD_PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "OTHER"];

export function ProtocolDistributionChart({
  protocols = null,
  status,
  errorMessage = null,
  onRetry,
  isLive = false,
  className,
}: ProtocolDistributionChartProps) {
  // Infer status if not explicitly passed
  const effectiveStatus =
    status ||
    (protocols && protocols.total_packets > 0
      ? isLive
        ? "LIVE"
        : "ARCHIVE"
      : isLive
      ? "LIVE"
      : "INACTIVE");

  // 1. Loading State
  if (effectiveStatus === "LOADING") {
    return (
      <div className={cn("flex flex-col items-center justify-center p-4 min-h-[260px]", className)}>
        <div className="relative w-36 h-36 flex items-center justify-center my-2">
          <div className="w-32 h-32 rounded-full border-4 border-dashed border-[#457B9D]/40 animate-spin" />
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <Radio className="w-6 h-6 text-[#457B9D] animate-pulse" />
          </div>
        </div>
        <p className="font-heading font-black text-xs text-[#1D3557] uppercase tracking-wider mt-2">
          Loading Protocol Telemetry...
        </p>
        <p className="text-[10px] font-mono text-[#457B9D] mt-0.5">
          Retrieving live wire classification from Engine B
        </p>
      </div>
    );
  }

  // 2. Error State
  if (effectiveStatus === "ERROR") {
    return (
      <div className={cn("flex flex-col items-center justify-center p-4 text-center min-h-[260px]", className)}>
        <div className="w-12 h-12 rounded-full border-2 border-[#E63946] bg-[#fee2e2] flex items-center justify-center mb-2 shadow-[2px_2px_0px_#1D3557]">
          <AlertCircle className="w-6 h-6 text-[#E63946]" />
        </div>
        <p className="font-heading font-black text-xs text-[#1D3557] uppercase tracking-wider">
          Telemetry Error
        </p>
        <p className="text-[11px] font-mono text-[#E63946] mt-1 max-w-xs break-words">
          {errorMessage || "Unable to reach traffic analytics engine"}
        </p>
        {onRetry && (
          <button
            onClick={onRetry}
            className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] font-mono text-xs font-bold shadow-[2px_2px_0px_#1D3557] hover:bg-[#F1FAEE] transition-all"
          >
            <RefreshCw className="w-3 h-3" />
            Retry Connection
          </button>
        )}
      </div>
    );
  }

  // 3. Capture Inactive State (Genuine 404 or No Active Capture Session)
  if (effectiveStatus === "INACTIVE" || !protocols || protocols.total_packets === 0) {
    return (
      <div className={cn("flex flex-col items-center justify-center p-4 text-center min-h-[260px]", className)}>
        <div className="relative w-36 h-36 flex items-center justify-center my-2">
          <div className="w-32 h-32 rounded-full border-4 border-dashed border-[#1D3557]/30 flex items-center justify-center bg-[#F1FAEE]">
            <div className="w-20 h-20 rounded-full border-2 border-[#1D3557] bg-white flex flex-col items-center justify-center shadow-[3px_3px_0px_#1D3557]">
              <Radio className="w-5 h-5 text-[#457B9D] mb-0.5" />
              <span className="font-heading font-black text-[9px] text-[#1D3557] uppercase">
                INACTIVE
              </span>
            </div>
          </div>
        </div>

        <p className="font-heading font-black text-xs text-[#1D3557] uppercase tracking-wide mt-1">
          Capture Engine Inactive
        </p>
        <p className="text-[11px] font-mono text-[#457B9D] mt-1 max-w-xs">
          Wire packet capture is stopped. Start Engine B in Traffic Analyzer to classify real-time transport protocols.
        </p>

        <Link
          href="/traffic"
          className="mt-3 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border-2 border-[#1D3557] bg-[#1D3557] text-white font-mono text-xs font-bold shadow-[2px_2px_0px_#457B9D] hover:bg-[#457B9D] transition-colors"
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Launch Traffic Analyzer →</span>
        </Link>
      </div>
    );
  }

  // 4. Active Data State (Live Capture or Archived Session)
  const transportItems = protocols.transport_distribution || [];

  // Format items for Donut chart (only non-zero slices for Recharts stability)
  const chartSlices = transportItems
    .filter((t) => t.packet_count > 0)
    .map((t) => ({
      name: t.protocol,
      value: t.packet_count,
      percentage: t.percentage,
      bytes: t.byte_count,
      color: PROTOCOL_COLORS[t.protocol] || "#457B9D",
    }));

  // Ensure all standard protocols are represented in the legend without fabrication
  const legendItems = STANDARD_PROTOCOLS.map((protoName) => {
    const existing = transportItems.find((t) => t.protocol.toUpperCase() === protoName);
    return {
      protocol: protoName,
      packet_count: existing ? existing.packet_count : 0,
      byte_count: existing ? existing.byte_count : 0,
      percentage: existing ? existing.percentage : 0.0,
      color: PROTOCOL_COLORS[protoName] || "#457B9D",
    };
  });

  return (
    <div className={cn("flex flex-col items-center w-full", className)}>
      {/* Donut Chart with Centered Metric */}
      <div className="relative w-44 h-44 flex items-center justify-center my-1">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0].payload;
                  return (
                    <div className="bg-white border-2 border-[#1D3557] p-2 rounded-lg shadow-[2px_2px_0px_#1D3557] font-mono text-xs">
                      <p className="font-black text-[#1D3557] border-b border-[#1D3557]/20 pb-0.5 uppercase">
                        {data.name} Protocol
                      </p>
                      <div className="pt-1 space-y-0.5">
                        <p className="text-[#1D3557] font-bold">
                          {data.value.toLocaleString()} pkts ({data.percentage}%)
                        </p>
                        <p className="text-[#457B9D] font-bold">
                          {formatBytes(data.bytes || 0)}
                        </p>
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Pie
              data={chartSlices}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={75}
              paddingAngle={chartSlices.length > 1 ? 2 : 0}
              dataKey="value"
              stroke="#1D3557"
              strokeWidth={2}
            >
              {chartSlices.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>

        {/* Center Donut Label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="font-heading font-black text-lg text-[#1D3557] leading-tight">
            {protocols.total_packets.toLocaleString()}
          </span>
          <span className="text-[9px] font-mono font-black uppercase tracking-wider text-[#457B9D]">
            TOTAL PKTS
          </span>
        </div>
      </div>

      {/* Protocol Legend Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5 w-full mt-2 font-mono text-xs">
        {legendItems.map((p) => (
          <div
            key={p.protocol}
            className="flex items-center justify-between p-1.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]"
          >
            <div className="flex items-center gap-1.5 min-w-0">
              <span
                className="w-2.5 h-2.5 rounded-sm border border-[#1D3557] shrink-0"
                style={{ backgroundColor: p.color }}
              />
              <span className="font-black text-[#1D3557] text-[11px] truncate">
                {p.protocol}
              </span>
            </div>
            <div className="text-right pl-1 shrink-0">
              <span className="font-bold text-[#457B9D] text-[11px]">
                {p.percentage}%
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* L7 Inferred Applications Summary (if present) */}
      {protocols.application_breakdown && protocols.application_breakdown.length > 0 && (
        <div className="w-full mt-3 pt-2 border-t border-[#1D3557]/15 flex items-center justify-between text-[10px] font-mono">
          <span className="text-[#457B9D] font-bold">
            L7 Detected:
          </span>
          <span className="text-[#1D3557] font-black truncate max-w-[200px]" title={protocols.application_breakdown.map((a) => a.name).join(", ")}>
            {protocols.application_breakdown.map((a) => a.name).join(" • ")}
          </span>
        </div>
      )}
    </div>
  );
}
