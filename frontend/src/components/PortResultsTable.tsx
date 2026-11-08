import React from "react";
import { cn } from "@/lib/utils";

export interface PortScanResult {
  port: number;
  protocol: "TCP" | "UDP";
  state: "OPEN" | "CLOSED" | "FILTERED" | "UNKNOWN";
  service: string;
  responseTimeMs: number;
}

interface PortResultsTableProps {
  results: PortScanResult[];
  className?: string;
}

export function PortResultsTable({ results, className }: PortResultsTableProps) {
  if (results.length === 0) {
    return (
      <div className="p-8 text-center text-xs font-mono text-[#457B9D]">
        No scan results in session. Execute a port scan to view discovered sockets.
      </div>
    );
  }

  const stateBadges = {
    OPEN: "bg-[#dcfce7] text-[#166534] border-[#166534]",
    CLOSED: "bg-[#f1f5f9] text-[#475569] border-[#475569]",
    FILTERED: "bg-[#ffedd5] text-[#9a3412] border-[#9a3412]",
    UNKNOWN: "bg-[#f3e8ff] text-[#6b21a8] border-[#6b21a8]",
  };

  return (
    <div className={cn("overflow-x-auto", className)}>
      <table className="w-full text-left font-mono text-xs border-collapse">
        <thead>
          <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-bold text-[11px] uppercase tracking-wider">
            <th className="py-2.5 px-3">Port</th>
            <th className="py-2.5 px-3">Protocol</th>
            <th className="py-2.5 px-3">State</th>
            <th className="py-2.5 px-3">Service</th>
            <th className="py-2.5 px-3 text-right">Latency</th>
          </tr>
        </thead>
        <tbody className="divide-y border-b border-[#1D3557]/20 text-[#1D3557]">
          {results.map((res, idx) => (
            <tr
              key={`${res.port}-${res.protocol}-${idx}`}
              className="hover:bg-[#F1FAEE]/60 transition-colors"
            >
              <td className="py-2 px-3 font-bold text-[#1D3557]">
                {res.port}
              </td>
              <td className="py-2 px-3 text-[#457B9D] font-semibold">
                {res.protocol}
              </td>
              <td className="py-2 px-3">
                <span
                  className={cn(
                    "px-2 py-0.5 rounded text-[10px] font-bold border shadow-[1px_1px_0px_#1D3557]",
                    stateBadges[res.state] || stateBadges.UNKNOWN
                  )}
                >
                  {res.state}
                </span>
              </td>
              <td className="py-2 px-3 font-medium text-[#1D3557]">
                {res.service}
              </td>
              <td className="py-2 px-3 text-right text-[#457B9D]">
                {res.responseTimeMs} ms
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

