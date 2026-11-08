"use client";

import React, { useState } from "react";
import { ArrowLeftRight, CheckCircle2, Clock, Filter, Network, RefreshCw, XCircle } from "lucide-react";
import { BentoCard } from "@/components/BentoCard";
import { ConnectionsAnalyticsResponse } from "@/lib/types";
import { formatBytes } from "@/lib/formatters";

interface ConnectionFlowsCardProps {
  connections: ConnectionsAnalyticsResponse | null;
}

export function ConnectionFlowsCard({ connections }: ConnectionFlowsCardProps) {
  const [filterState, setFilterState] = useState<string>("ALL");

  const flows = connections?.flows || [];
  const filteredFlows =
    filterState === "ALL"
      ? flows
      : flows.filter((f) => f.state.toUpperCase() === filterState.toUpperCase());

  const getStateBadge = (state: string) => {
    switch (state.toUpperCase()) {
      case "ESTABLISHED":
        return "bg-[#dcfce7] text-[#15803d] border-[#16a34a]";
      case "ACTIVE":
        return "bg-[#dbeafe] text-[#1d4ed8] border-[#2563eb]";
      case "CLOSED":
        return "bg-[#f1f5f9] text-[#475569] border-[#64748b]";
      case "RESET":
        return "bg-[#fee2e2] text-[#b91c1c] border-[#dc2626]";
      default:
        return "bg-[#f1faee] text-[#1d3557] border-[#1d3557]";
    }
  };

  return (
    <BentoCard
      title="ACTIVE CONNECTION FLOWS"
      subtitle={`Canonical 5-tuple tracking (${connections?.total_active_flows || 0} active, ${connections?.total_flows_tracked || 0} cumulative)`}
      action={
        <div className="flex items-center gap-1 font-mono text-xs">
          {["ALL", "ESTABLISHED", "ACTIVE", "CLOSED", "RESET"].map((st) => (
            <button
              key={st}
              onClick={() => setFilterState(st)}
              className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-black transition-all ${
                filterState === st
                  ? "bg-[#1D3557] text-white shadow-[1px_1px_0px_#1D3557]"
                  : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      }
    >
      <div className="overflow-x-auto">
        {filteredFlows.length === 0 ? (
          <div className="p-8 text-center text-[#457B9D] font-mono text-xs border-2 border-dashed border-[#1D3557]/20 rounded-lg">
            <Network className="w-6 h-6 mx-auto mb-1 opacity-50" />
            <p className="font-bold">No Active Connection Flows</p>
            <p className="text-[10px]">Flow state tracking will appear as packets are captured</p>
          </div>
        ) : (
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[10px] font-black text-[#1D3557] uppercase tracking-wider">
                <th className="py-2 px-3">Protocol</th>
                <th className="py-2 px-3">Flow Endpoints (5-Tuple)</th>
                <th className="py-2 px-3">Service</th>
                <th className="py-2 px-3">Volume</th>
                <th className="py-2 px-3">TCP Flags</th>
                <th className="py-2 px-3">Duration</th>
                <th className="py-2 px-3 text-right">Flow State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1D3557]/15">
              {filteredFlows.slice(0, 15).map((flow) => (
                <tr key={flow.flow_id} className="hover:bg-[#F1FAEE]/60 transition-colors">
                  <td className="py-2 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded border border-[#1D3557] text-[10px] font-black ${
                        flow.protocol === "TCP" ? "bg-[#3B82F6] text-white" : "bg-[#10B981] text-white"
                      }`}
                    >
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    <div className="flex items-center gap-1.5 font-bold text-[#1D3557]">
                      <span>{flow.src_ip}:{flow.src_port}</span>
                      <ArrowLeftRight className={`w-3.5 h-3.5 ${flow.is_bidirectional ? "text-[#10B981]" : "text-[#94A3B8]"}`} />
                      <span>{flow.dst_ip}:{flow.dst_port}</span>
                    </div>
                  </td>
                  <td className="py-2 px-3">
                    {flow.service ? (
                      <span className="px-1.5 py-0.2 rounded border border-[#1D3557] bg-white font-black text-[10px] text-[#1D3557]">
                        {flow.service}
                      </span>
                    ) : (
                      <span className="text-[#94A3B8] text-[10px]">--</span>
                    )}
                  </td>
                  <td className="py-2 px-3">
                    <span className="font-bold text-[#1D3557]">
                      {flow.packet_count} pkts
                    </span>
                    <span className="text-[#457B9D] text-[10px] block">
                      {formatBytes(flow.byte_count)}
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    {flow.tcp_flags_observed.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {flow.tcp_flags_observed.map((fl) => (
                          <span
                            key={fl}
                            className="px-1 rounded border border-[#1D3557]/30 bg-white text-[9px] font-bold text-[#1D3557]"
                          >
                            {fl}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[#94A3B8] text-[10px]">--</span>
                    )}
                  </td>
                  <td className="py-2 px-3 text-[#457B9D] font-bold">
                    {flow.duration_seconds}s
                  </td>
                  <td className="py-2 px-3 text-right">
                    <span
                      className={`px-2 py-0.5 rounded-full border text-[10px] font-black uppercase ${getStateBadge(
                        flow.state
                      )}`}
                    >
                      {flow.state}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </BentoCard>
  );
}

