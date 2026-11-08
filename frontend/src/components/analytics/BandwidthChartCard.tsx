"use client";

import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Activity, ArrowDownLeft, ArrowUpRight, Gauge, Layers } from "lucide-react";
import { BentoCard } from "@/components/BentoCard";
import { BandwidthAnalyticsResponse } from "@/lib/types";
import { formatBps, formatBytes } from "@/lib/formatters";

interface BandwidthChartCardProps {
  bandwidth: BandwidthAnalyticsResponse | null;
  selectedWindow: number;
  onWindowChange: (w: number) => void;
  isCapturing: boolean;
}

export function BandwidthChartCard({
  bandwidth,
  selectedWindow,
  onWindowChange,
  isCapturing,
}: BandwidthChartCardProps) {
  const chartData = (bandwidth?.data_points || []).map((pt, idx) => ({
    time: `T-${(bandwidth?.data_points.length || 0) - idx}s`,
    inbound: pt.bytes_inbound * 8, // bits
    outbound: pt.bytes_outbound * 8, // bits
    local: pt.bytes_local * 8,
    unknown: pt.bytes_unknown * 8,
    totalBps: pt.bits_per_second,
    pps: pt.packets_per_second,
  }));

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-white border-2 border-[#1D3557] p-3 rounded-lg shadow-[3px_3px_0px_#1D3557] font-mono text-xs">
          <p className="font-black text-[#1D3557] pb-1 border-b-2 border-[#1D3557]/20 uppercase">
            {label} Window ({selectedWindow}s)
          </p>
          <div className="pt-2 space-y-1">
            <p className="flex items-center justify-between gap-4 text-[#3B82F6] font-bold">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-[#3B82F6] border border-[#1D3557]" />
                Inbound (RX):
              </span>
              <span>{formatBps(payload[0]?.value || 0)}</span>
            </p>
            <p className="flex items-center justify-between gap-4 text-[#E63946] font-bold">
              <span className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-[#E63946] border border-[#1D3557]" />
                Outbound (TX):
              </span>
              <span>{formatBps(payload[1]?.value || 0)}</span>
            </p>
            <p className="flex items-center justify-between gap-4 text-[#1D3557] font-bold pt-1 border-t border-[#1D3557]/10">
              <span>Total Throughput:</span>
              <span>{formatBps((payload[0]?.value || 0) + (payload[1]?.value || 0))}</span>
            </p>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <BentoCard
      title="REAL-TIME BANDWIDTH MONITOR"
      subtitle="Rolling window throughput, directional wire volume, and packet transfer rate"
      action={
        <div className="flex items-center gap-1 font-mono text-xs">
          <span className="text-[10px] font-bold text-[#457B9D] mr-1 hidden sm:inline">WINDOW:</span>
          {[1, 5, 30, 60].map((w) => (
            <button
              key={w}
              onClick={() => onWindowChange(w)}
              className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-black transition-all ${
                selectedWindow === w
                  ? "bg-[#1D3557] text-white shadow-[1px_1px_0px_#1D3557]"
                  : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
              }`}
            >
              {w}s
            </button>
          ))}
        </div>
      }
    >
      {/* Metric Tiles Sub-header */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4 font-mono text-xs">
        <div className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]">
          <span className="block text-[10px] font-black uppercase text-[#457B9D]">Current Throughput</span>
          <span className="text-base font-black text-[#1D3557]">
            {formatBps(bandwidth?.current_bps || 0)}
          </span>
        </div>
        <div className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
          <span className="block text-[10px] font-black uppercase text-[#457B9D]">Packet Rate</span>
          <span className="text-base font-black text-[#1D3557]">
            {(bandwidth?.current_pps || 0).toFixed(0)} <span className="text-xs font-bold text-[#457B9D]">pps</span>
          </span>
        </div>
        <div className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
          <span className="block text-[10px] font-black uppercase text-[#457B9D]">Peak Throughput</span>
          <span className="text-base font-black text-[#E63946]">
            {formatBps(bandwidth?.peak_bps || 0)}
          </span>
        </div>
        <div className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
          <span className="block text-[10px] font-black uppercase text-[#457B9D]">Avg Packet Size</span>
          <span className="text-base font-black text-[#1D3557]">
            {(bandwidth?.average_packet_size_bytes || 0).toFixed(0)}{" "}
            <span className="text-xs font-bold text-[#457B9D]">B</span>
          </span>
        </div>
      </div>

      {/* Chart Legend */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b-2 border-[#1D3557]/15 font-mono text-xs mb-3">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm bg-[#3B82F6] border-2 border-[#1D3557]" />
            <span className="font-bold text-[#1D3557] uppercase text-[11px]">Inbound (RX)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-sm bg-[#E63946] border-2 border-[#1D3557]" />
            <span className="font-bold text-[#1D3557] uppercase text-[11px]">Outbound (TX)</span>
          </div>
        </div>
        <span className="text-[11px] font-bold text-[#457B9D]">
          Total Volume: {formatBytes(bandwidth?.total_bytes || 0)}
        </span>
      </div>

      {/* Recharts Area Container */}
      <div className="h-60 w-full">
        {chartData.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center font-mono text-xs text-[#457B9D] border-2 border-dashed border-[#1D3557]/20 rounded-lg">
            <Activity className="w-6 h-6 mb-1 text-[#457B9D] animate-pulse" />
            <p className="font-bold">Awaiting Live Wire Traffic...</p>
            <p className="text-[10px]">Start capture to monitor real-time bandwidth throughput</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              <defs>
                <linearGradient id="colorInbound" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.15} />
                </linearGradient>
                <linearGradient id="colorOutbound" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#E63946" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#E63946" stopOpacity={0.15} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1D3557" strokeOpacity={0.15} />
              <XAxis dataKey="time" stroke="#1D3557" tick={{ fontSize: 10, fill: "#1D3557", fontWeight: 700 }} />
              <YAxis
                stroke="#1D3557"
                tick={{ fontSize: 10, fill: "#1D3557", fontWeight: 700 }}
                tickFormatter={(v) => formatBps(v)}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="monotone"
                dataKey="inbound"
                name="Inbound (RX)"
                stroke="#1D3557"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorInbound)"
              />
              <Area
                type="monotone"
                dataKey="outbound"
                name="Outbound (TX)"
                stroke="#1D3557"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorOutbound)"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </BentoCard>
  );
}

