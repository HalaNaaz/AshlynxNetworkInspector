"use client";

import React, { useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Clock, TrendingUp } from "lucide-react";
import { BentoCard } from "@/components/BentoCard";
import { TrafficTimelineResponse } from "@/lib/types";
import { formatBps, formatBytes } from "@/lib/formatters";

interface TrafficTimelineCardProps {
  timeline: TrafficTimelineResponse | null;
}

export function TrafficTimelineCard({ timeline }: TrafficTimelineCardProps) {
  const [metricMode, setMetricMode] = useState<"bps" | "pps">("bps");

  const points = (timeline?.points || []).map((pt) => ({
    sec: `${pt.second_offset}s`,
    bps: pt.bps,
    pps: pt.pps,
    tcp: pt.tcp_bytes * 8,
    udp: pt.udp_bytes * 8,
    icmp: pt.icmp_bytes * 8,
    arp: pt.arp_bytes * 8,
    other: pt.other_bytes * 8,
  }));

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const p = payload[0].payload;
      return (
        <div className="bg-white border-2 border-[#1D3557] p-2.5 rounded-lg shadow-[3px_3px_0px_#1D3557] font-mono text-xs">
          <p className="font-black text-[#1D3557] pb-1 border-b border-[#1D3557]/20 uppercase">
            Offset: {label}
          </p>
          <div className="pt-1.5 space-y-0.5">
            <p className="font-bold text-[#1D3557]">Throughput: {formatBps(p.bps)}</p>
            <p className="font-bold text-[#457B9D]">Rate: {p.pps.toFixed(0)} pps</p>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <BentoCard
      title="SECOND-BY-SECOND TRAFFIC TIMELINE"
      subtitle={`Chronological event sequence across ${timeline?.total_seconds || 0} active capture seconds`}
      action={
        <div className="flex items-center gap-1 font-mono text-xs">
          <button
            onClick={() => setMetricMode("bps")}
            className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-black transition-all ${
              metricMode === "bps"
                ? "bg-[#1D3557] text-white shadow-[1px_1px_0px_#1D3557]"
                : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
            }`}
          >
            BITS / SEC
          </button>
          <button
            onClick={() => setMetricMode("pps")}
            className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-black transition-all ${
              metricMode === "pps"
                ? "bg-[#1D3557] text-white shadow-[1px_1px_0px_#1D3557]"
                : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
            }`}
          >
            PACKETS / SEC
          </button>
        </div>
      }
    >
      <div className="h-56 w-full font-mono text-xs">
        {points.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-[#457B9D] border-2 border-dashed border-[#1D3557]/20 rounded-lg">
            <Clock className="w-6 h-6 mb-1 opacity-50" />
            <p className="font-bold">No Timeline Activity Recorded</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={points} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1D3557" strokeOpacity={0.15} />
              <XAxis dataKey="sec" stroke="#1D3557" tick={{ fontSize: 10, fill: "#1D3557", fontWeight: 700 }} />
              <YAxis
                stroke="#1D3557"
                tick={{ fontSize: 10, fill: "#1D3557", fontWeight: 700 }}
                tickFormatter={(v) => (metricMode === "bps" ? formatBps(v) : `${v} pps`)}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar
                dataKey={metricMode === "bps" ? "bps" : "pps"}
                fill={metricMode === "bps" ? "#3B82F6" : "#E63946"}
                stroke="#1D3557"
                strokeWidth={2}
                radius={[4, 4, 0, 0]}
              />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </BentoCard>
  );
}

