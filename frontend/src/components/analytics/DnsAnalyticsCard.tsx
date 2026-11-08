"use client";

import React from "react";
import { AlertCircle, CheckCircle2, Globe, HelpCircle, Search, Server } from "lucide-react";
import { BentoCard } from "@/components/BentoCard";
import { DnsAnalyticsResponse } from "@/lib/types";

interface DnsAnalyticsCardProps {
  dns: DnsAnalyticsResponse | null;
}

export function DnsAnalyticsCard({ dns }: DnsAnalyticsCardProps) {
  const topDomains = dns?.top_domains || [];
  const queryTypes = dns?.query_types || [];
  const responseCodes = dns?.response_codes || [];

  return (
    <BentoCard
      title="DNS INTELLIGENCE & RESOLUTION"
      subtitle="Safely parsed DNS queries, resolution status codes, and queried domain names (Zero payload inspection)"
      action={
        <div className="flex items-center gap-2 font-mono text-xs">
          <span className="text-[10px] font-bold text-[#457B9D]">
            TOTAL: {dns?.total_dns_packets || 0} FRAMES
          </span>
        </div>
      }
    >
      <div className="space-y-4 font-mono text-xs">
        {/* KPI Mini-Tiles */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          <div className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]">
            <span className="block text-[10px] font-black uppercase text-[#457B9D]">Total Queries</span>
            <span className="text-base font-black text-[#1D3557]">{dns?.total_queries || 0}</span>
          </div>
          <div className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
            <span className="block text-[10px] font-black uppercase text-[#457B9D]">Total Responses</span>
            <span className="text-base font-black text-[#1D3557]">{dns?.total_responses || 0}</span>
          </div>
          <div className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
            <span className="block text-[10px] font-black uppercase text-[#457B9D]">Unmatched Queries</span>
            <span className="text-base font-black text-[#F59E0B]">{dns?.unmatched_queries || 0}</span>
          </div>
          <div className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
            <span className="block text-[10px] font-black uppercase text-[#457B9D]">Unique Domains</span>
            <span className="text-base font-black text-[#1D3557]">{topDomains.length}</span>
          </div>
        </div>

        {/* Top Queried Domains */}
        <div className="space-y-2 pt-2 border-t-2 border-[#1D3557]/15">
          <div className="flex items-center justify-between">
            <span className="font-black text-[#1D3557] uppercase text-[11px] flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-[#457B9D]" /> Top Queried Domains
            </span>
            <span className="text-[10px] text-[#457B9D] font-bold">Query Frequency</span>
          </div>

          {topDomains.length === 0 ? (
            <div className="p-4 text-center text-[#457B9D] border border-dashed border-[#1D3557]/20 rounded-lg">
              <p className="font-bold text-[11px]">No DNS Queries Recorded</p>
            </div>
          ) : (
            <div className="space-y-1.5">
              {topDomains.slice(0, 5).map((dom) => (
                <div
                  key={dom.query_name}
                  className="p-2 rounded-lg border-2 border-[#1D3557] bg-white shadow-[1px_1px_0px_#1D3557] flex items-center justify-between"
                >
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[#3B82F6] border border-[#1D3557]" />
                    <span className="font-bold text-[#1D3557]">{dom.query_name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-[#457B9D] font-bold">{dom.percentage}%</span>
                    <span className="px-1.5 py-0.2 rounded border border-[#1D3557] bg-[#F1FAEE] font-black text-[#1D3557] text-[10px]">
                      {dom.count} reqs
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Query Types & Response Codes Dual Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t-2 border-[#1D3557]/15">
          {/* Query Types */}
          <div>
            <span className="font-black text-[#1D3557] uppercase text-[11px] block mb-1.5">
              Query Types (RR Type)
            </span>
            {queryTypes.length === 0 ? (
              <span className="text-[#457B9D] text-[11px]">None observed</span>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {queryTypes.map((qt) => (
                  <span
                    key={qt.qtype}
                    className="px-2 py-0.5 rounded border border-[#1D3557] bg-[#F1FAEE] text-[10px] font-bold text-[#1D3557]"
                  >
                    {qt.qtype}: <strong>{qt.count}</strong>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Response Codes */}
          <div>
            <span className="font-black text-[#1D3557] uppercase text-[11px] block mb-1.5">
              Response Status (RCODE)
            </span>
            {responseCodes.length === 0 ? (
              <span className="text-[#457B9D] text-[11px]">None observed</span>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {responseCodes.map((rc) => (
                  <span
                    key={rc.rcode}
                    className={`px-2 py-0.5 rounded border text-[10px] font-black ${
                      rc.rcode === 0
                        ? "bg-[#dcfce7] text-[#15803d] border-[#16a34a]"
                        : "bg-[#fee2e2] text-[#b91c1c] border-[#dc2626]"
                    }`}
                  >
                    {rc.rcode_name} (Code {rc.rcode}): <strong>{rc.count}</strong>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </BentoCard>
  );
}

