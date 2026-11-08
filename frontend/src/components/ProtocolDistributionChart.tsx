"use client";

import React from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { cn } from "@/lib/utils";

interface ProtocolData {
  name: string;
  value: number;
  color: string;
}

interface ProtocolDistributionChartProps {
  isLive?: boolean;
  className?: string;
}

export function ProtocolDistributionChart({
  isLive = false,
  className,
}: ProtocolDistributionChartProps) {
  // Brand color matching for protocols
  const sampleProtocols: ProtocolData[] = [
    { name: "TCP", value: 58, color: "#457B9D" },
    { name: "UDP", value: 24, color: "#A8DADC" },
    { name: "ICMP", value: 6, color: "#E63946" },
    { name: "DNS", value: 8, color: "#f59e0b" },
    { name: "OTHER", value: 4, color: "#1D3557" },
  ];

  if (!isLive) {
    return (
      <div className={cn("flex flex-col items-center justify-center p-4", className)}>
        <div className="relative w-44 h-44 flex items-center justify-center my-2">
          {/* Simulated outer border ring */}
          <div className="w-40 h-40 rounded-full border-4 border-dashed border-[#1D3557]/40 flex items-center justify-center bg-[#F1FAEE]">
            <div className="w-24 h-24 rounded-full border-2 border-[#1D3557] bg-white flex flex-col items-center justify-center shadow-[3px_3px_0px_#1D3557]">
              <span className="font-heading font-extrabold text-sm text-[#1D3557]">
                PHASE 1
              </span>
              <span className="text-[10px] font-mono text-[#457B9D] font-bold">
                STANDBY
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 w-full mt-3 font-mono text-xs">
          {sampleProtocols.map((p) => (
            <div
              key={p.name}
              className="flex items-center justify-between p-1.5 rounded border border-[#1D3557]/20 bg-white"
            >
              <div className="flex items-center gap-1.5">
                <span
                  className="w-2.5 h-2.5 rounded-sm border border-[#1D3557]"
                  style={{ backgroundColor: p.color }}
                />
                <span className="font-bold text-[#1D3557]">{p.name}</span>
              </div>
              <span className="text-slate-400 font-bold">-- %</span>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-[#457B9D] text-center mt-2 font-medium">
          Protocol classification will activate when Engine B wire capture is started.
        </p>
      </div>
    );
  }

  return (
    <div className={cn("flex flex-col items-center", className)}>
      <div className="relative w-48 h-48">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const data = payload[0];
                  return (
                    <div className="bg-white border-2 border-[#1D3557] p-2 rounded shadow-[2px_2px_0px_#1D3557] font-mono text-xs">
                      <span className="font-bold text-[#1D3557]">{data.name}: </span>
                      <span className="text-[#457B9D]">{data.value}%</span>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Pie
              data={sampleProtocols}
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={75}
              paddingAngle={3}
              dataKey="value"
              stroke="#1D3557"
              strokeWidth={2}
            >
              {sampleProtocols.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="font-heading font-extrabold text-sm text-[#1D3557]">
            100%
          </span>
          <span className="text-[9px] font-mono text-[#457B9D] font-bold">
            TOTAL
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 w-full mt-2 font-mono text-xs">
        {sampleProtocols.map((p) => (
          <div
            key={p.name}
            className="flex items-center justify-between p-1.5 rounded border border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]"
          >
            <div className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-sm border border-[#1D3557]"
                style={{ backgroundColor: p.color }}
              />
              <span className="font-bold text-[#1D3557]">{p.name}</span>
            </div>
            <span className="font-bold text-[#457B9D]">{p.value}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

