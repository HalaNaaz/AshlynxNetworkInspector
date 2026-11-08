"use client";

import React, { useState } from "react";
import { ArrowDownLeft, ArrowUpRight, Globe, Lock, Shield, Users } from "lucide-react";
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
        <div className="flex items-center gap-1 font-mono text-xs">
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
      <div className="space-y-2.5 font-mono text-xs">
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
              className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557] flex flex-col sm:flex-row sm:items-center justify-between gap-2"
            >
              <div className="flex items-center gap-2">
                <span className="w-5 h-5 rounded-full border-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-black text-[10px] flex items-center justify-center shrink-0">
                  {idx + 1}
                </span>

                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-black text-[#1D3557] text-xs">{item.ip_address}</span>
                    {item.is_local_host && (
                      <span className="px-1.5 py-0.2 rounded border border-[#1D3557] bg-[#A8DADC] text-[#1D3557] text-[9px] font-black">
                        LOCAL HOST
                      </span>
                    )}
                    <span className="px-1.5 py-0.2 rounded border border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] text-[9px] font-bold">
                      {item.ip_category || (item.is_private ? "PRIVATE" : "PUBLIC")}
                    </span>
                  </div>
                  <div className="text-[10px] text-[#457B9D] font-bold space-x-2">
                    <span>{item.packet_count} packets</span>
                    <span>•</span>
                    <span>TX: {formatBytes(item.bytes_sent || 0)}</span>
                    <span>•</span>
                    <span>RX: {formatBytes(item.bytes_received || 0)}</span>
                    <span>•</span>
                    <span>{item.percentage}% participation</span>
                  </div>
                </div>
              </div>

              <div className="flex sm:flex-col items-end justify-between sm:justify-center shrink-0">
                <span className="font-black text-[#1D3557] text-xs">{formatBytes(item.byte_count)}</span>
                <div className="w-24 sm:w-28 bg-[#F1FAEE] h-2 rounded-full border border-[#1D3557] overflow-hidden mt-1">
                  <div
                    className="bg-[#457B9D] h-full"
                    style={{ width: `${Math.min(100, Math.max(5, item.percentage))}%` }}
                  />
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </BentoCard>
  );
}

