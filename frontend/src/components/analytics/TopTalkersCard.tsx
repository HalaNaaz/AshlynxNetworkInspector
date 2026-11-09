"use client";

import React, { useState } from "react";
import { ArrowDownLeft, ArrowUpRight, Users } from "lucide-react";
import { BentoCard } from "@/components/BentoCard";
import { TopTalkersResponse, TopTalkerItem } from "@/lib/types";
import { formatBytes } from "@/lib/formatters";

interface TopTalkersCardProps {
  topTalkers: TopTalkersResponse | null;
}

export function TopTalkersCard({ topTalkers }: TopTalkersCardProps) {
  const [activeTab, setActiveTab] = useState<"combined" | "sources" | "destinations">("combined");

  const items: TopTalkerItem[] =
    activeTab === "combined"
      ? topTalkers?.top_combined || []
      : activeTab === "sources"
      ? topTalkers?.top_sources || []
      : topTalkers?.top_destinations || [];

  return (
    <BentoCard
      title="TOP NETWORK TALKERS"
      subtitle="Highest bandwidth consuming IP endpoints, private/public classification, and volume share"
      action={
        <div className="flex flex-wrap items-center gap-1 font-mono text-xs">
          <button
            onClick={() => setActiveTab("combined")}
            className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-black transition-all ${
              activeTab === "combined"
                ? "bg-[#1D3557] text-white shadow-[1px_1px_0px_#1D3557]"
                : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
            }`}
          >
            COMBINED ({topTalkers?.top_combined.length || 0})
          </button>
          <button
            onClick={() => setActiveTab("sources")}
            className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-black transition-all ${
              activeTab === "sources"
                ? "bg-[#1D3557] text-white shadow-[1px_1px_0px_#1D3557]"
                : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
            }`}
          >
            SOURCES ({topTalkers?.top_sources.length || 0})
          </button>
          <button
            onClick={() => setActiveTab("destinations")}
            className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-black transition-all ${
              activeTab === "destinations"
                ? "bg-[#1D3557] text-white shadow-[1px_1px_0px_#1D3557]"
                : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
            }`}
          >
            DESTINATIONS ({topTalkers?.top_destinations.length || 0})
          </button>
        </div>
      }
    >
      <div className="space-y-3 font-mono text-xs w-full min-w-0">
        {items.length === 0 ? (
          <div className="p-8 text-center text-[#457B9D] border-2 border-dashed border-[#1D3557]/20 rounded-lg">
            <Users className="w-6 h-6 mx-auto mb-1 opacity-50" />
            <p className="font-bold">No Network Endpoints Observed</p>
            <p className="text-[10px]">Endpoint ranking will populate as traffic is captured</p>
          </div>
        ) : (
          items.map((item, idx) => (
            <div
              key={`${item.ip_address}-${idx}`}
              className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557] flex flex-col gap-2 min-w-0 w-full"
            >
              {/* Row 1: Rank, IP Address, Classification Badges, and Total Bandwidth */}
              <div className="flex items-start justify-between gap-2 min-w-0 w-full">
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  <span className="w-5 h-5 rounded-full border-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-black text-[10px] flex items-center justify-center shrink-0">
                    {idx + 1}
                  </span>

                  <div className="flex flex-wrap items-center gap-1.5 min-w-0">
                    <span
                      className="font-black text-[#1D3557] text-xs truncate max-w-[130px] sm:max-w-none"
                      title={item.ip_address}
                    >
                      {item.ip_address}
                    </span>
                    {item.is_local_host && (
                      <span className="px-1.5 py-0.2 rounded border border-[#1D3557] bg-[#A8DADC] text-[#1D3557] text-[9px] font-black shrink-0">
                        LOCAL HOST
                      </span>
                    )}
                    <span className="px-1.5 py-0.2 rounded border border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] text-[9px] font-bold shrink-0">
                      {item.ip_category || (item.is_private ? "PRIVATE" : "PUBLIC")}
                    </span>
                  </div>
                </div>

                <div className="text-right shrink-0">
                  <span className="font-black text-[#1D3557] text-xs block leading-none">
                    {formatBytes(item.byte_count)}
                  </span>
                  <span className="text-[10px] text-[#457B9D] font-bold">
                    {item.percentage}%
                  </span>
                </div>
              </div>

              {/* Row 2: Full-Width Contained Progress Bar */}
              <div className="w-full min-w-0 bg-[#F1FAEE] h-2 rounded-full border border-[#1D3557] overflow-hidden">
                <div
                  className="bg-[#457B9D] h-full transition-all duration-300"
                  style={{ width: `${Math.min(100, Math.max(3, item.percentage))}%` }}
                />
              </div>

              {/* Row 3: Metrics (Packets, TX, RX, Participation) */}
              <div className="flex flex-wrap items-center justify-between gap-x-2.5 gap-y-1 text-[10px] text-[#457B9D] font-bold min-w-0 pt-0.5">
                <span className="shrink-0">
                  <strong className="text-[#1D3557]">{item.packet_count.toLocaleString()}</strong> pkts
                </span>
                <span className="flex items-center gap-1 shrink-0">
                  <ArrowUpRight className="w-3 h-3 text-[#E63946]" />
                  <span>TX:</span>
                  <strong className="text-[#1D3557]">{formatBytes(item.bytes_sent || 0)}</strong>
                </span>
                <span className="flex items-center gap-1 shrink-0">
                  <ArrowDownLeft className="w-3 h-3 text-[#10B981]" />
                  <span>RX:</span>
                  <strong className="text-[#1D3557]">{formatBytes(item.bytes_received || 0)}</strong>
                </span>
                <span className="shrink-0 text-[#1D3557]">
                  {item.percentage}% share
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </BentoCard>
  );
}
