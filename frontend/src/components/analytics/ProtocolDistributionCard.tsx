"use client";

import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { BentoCard } from "@/components/BentoCard";
import { ProtocolAnalyticsResponse } from "@/lib/types";
import { formatBytes } from "@/lib/formatters";

interface ProtocolDistributionCardProps {
  protocols: ProtocolAnalyticsResponse | null;
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: "#3B82F6",    // Vibrant Blue
  UDP: "#10B981",    // Vibrant Emerald Green
  ICMP: "#E63946",   // Coral Red
  ARP: "#F59E0B",    // Amber / Yellow
  OTHER: "#A8DADC",  // Soft Aqua
};

export function ProtocolDistributionCard({ protocols }: ProtocolDistributionCardProps) {
  const transportData = (protocols?.transport_distribution || []).map((item) => ({
    name: item.protocol,
    value: item.packet_count,
    percentage: item.percentage,
    bytes: item.byte_count,
    color: PROTOCOL_COLORS[item.protocol] || "#457B9D",
  }));

  const hasData = transportData.some((d) => d.value > 0);

  const chartData = hasData
    ? transportData.filter((d) => d.value > 0)
    : [{ name: "NO TRAFFIC", value: 1, percentage: 0, bytes: 0, color: "#E2E8F0" }];

  const totalPkts = protocols?.total_packets || 0;

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div className="bg-white border-2 border-[#1D3557] p-2.5 rounded-lg shadow-[3px_3px_0px_#1D3557] font-mono text-xs">
          <p className="font-black text-[#1D3557] pb-1 border-b border-[#1D3557]/20 uppercase">
            {data.name} Protocol
          </p>
          <div className="pt-1.5 space-y-0.5">
            <p className="text-[#1D3557] font-bold">Packets: {data.value.toLocaleString()} ({data.percentage}%)</p>
            <p className="text-[#457B9D] font-bold">Volume: {formatBytes(data.bytes || 0)}</p>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <BentoCard
      title="PROTOCOL DISTRIBUTION"
      subtitle="Exclusive transport layer partition (Zero double-counting guaranteed)"
      action={
        <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-[#1D3557] bg-[#F1FAEE] text-[#1D3557]">
          SUM: {totalPkts} PKTS
        </span>
      }
    >
      <div className="flex flex-col items-center">
        {/* Donut Chart with Centered Metric */}
        <div className="relative w-56 h-56 flex items-center justify-center my-2">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Tooltip content={<CustomTooltip />} />
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={88}
                paddingAngle={hasData ? 3 : 0}
                dataKey="value"
                stroke="#1D3557"
                strokeWidth={2.5}
              >
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
            </PieChart>
          </ResponsiveContainer>

          {/* Centered Donut Label */}
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="font-heading font-black text-2xl text-[#1D3557] leading-none">
              {hasData ? "100%" : "0%"}
            </span>
            <span className="text-[10px] font-mono font-black uppercase tracking-wider text-[#457B9D] mt-0.5">
              TOTAL
            </span>
          </div>
        </div>

        {/* Legend Grid Matching Reference Image */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 w-full pt-3 border-t-2 border-[#1D3557]/15 font-mono text-xs">
          {(protocols?.transport_distribution || []).map((p) => {
            const color = PROTOCOL_COLORS[p.protocol] || "#1D3557";
            return (
              <div
                key={p.protocol}
                className="flex items-center justify-between p-2 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]"
              >
                <div className="flex items-center gap-1.5">
                  <span
                    className="w-3 h-3 rounded-sm border-2 border-[#1D3557] shrink-0"
                    style={{ backgroundColor: color }}
                  />
                  <span className="font-black text-[#1D3557] text-[11px]">{p.protocol}</span>
                </div>
                <span className="font-bold text-[#457B9D] text-[11px]">{p.percentage}%</span>
              </div>
            );
          })}
        </div>

        {/* Application Layer Breakdown Sub-panel */}
        {protocols && protocols.application_breakdown.length > 0 && (
          <div className="w-full mt-4 pt-3 border-t-2 border-[#1D3557]/15">
            <div className="flex items-center justify-between mb-2 font-mono text-xs">
              <span className="font-black text-[#1D3557] uppercase text-[11px]">
                Application Layer Intelligence
              </span>
              <span className="text-[10px] text-[#457B9D] font-bold">Non-additive metrics</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {protocols.application_breakdown.map((app) => (
                <div
                  key={`${app.name}-${app.transport_layer}`}
                  className="px-2.5 py-1 rounded-md border-2 border-[#1D3557] bg-[#F1FAEE] text-[11px] font-mono flex items-center gap-2 shadow-[1px_1px_0px_#1D3557]"
                >
                  <span className="font-black text-[#1D3557]">{app.name}</span>
                  <span className="text-[#457B9D] font-bold">
                    {app.packet_count} pkts ({formatBytes(app.byte_count)})
                  </span>
                  <span className="text-[9px] px-1 rounded bg-white border border-[#1D3557] font-bold text-[#1D3557]">
                    {app.transport_layer}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </BentoCard>
  );
}

