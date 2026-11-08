import React from "react";
import { cn } from "@/lib/utils";
import { PacketMetadataItem } from "@/lib/types";

interface PacketTableProps {
  packets: PacketMetadataItem[];
  selectedPacketId?: number | null;
  onSelectPacket?: (pkt: PacketMetadataItem) => void;
  className?: string;
}

export function PacketTable({
  packets,
  selectedPacketId,
  onSelectPacket,
  className,
}: PacketTableProps) {
  if (packets.length === 0) {
    return (
      <div className="p-8 text-center text-xs font-mono text-[#457B9D]">
        No packet frames currently captured in display buffer.
      </div>
    );
  }

  const getProtocolColor = (proto: string) => {
    switch (proto.toUpperCase()) {
      case "TCP":
        return "bg-[#A8DADC] text-[#1D3557]";
      case "UDP":
        return "bg-[#F1FAEE] text-[#457B9D]";
      case "ICMP":
      case "ICMPV6":
        return "bg-[#ffe4e6] text-[#E63946]";
      case "DNS":
        return "bg-[#fef3c7] text-[#92400e]";
      case "ARP":
        return "bg-[#f3e8ff] text-[#7e22ce]";
      default:
        return "bg-slate-100 text-slate-700";
    }
  };

  return (
    <div className={cn("overflow-x-auto", className)}>
      <table className="w-full text-left font-mono text-xs border-collapse">
        <thead>
          <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-bold text-[11px] uppercase tracking-wider">
            <th className="py-2.5 px-3">#</th>
            <th className="py-2.5 px-3">Time</th>
            <th className="py-2.5 px-3">Source</th>
            <th className="py-2.5 px-3">Destination</th>
            <th className="py-2.5 px-3">Protocol</th>
            <th className="py-2.5 px-3 text-right">Length</th>
            <th className="py-2.5 px-3">Details / Flags</th>
          </tr>
        </thead>
        <tbody className="divide-y border-b border-[#1D3557]/20 text-[#1D3557]">
          {packets.map((pkt) => {
            const isSelected = selectedPacketId === pkt.packet_id;
            const timeStr = new Date(pkt.timestamp).toLocaleTimeString([], {
              hour12: false,
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
            });
            const srcStr = pkt.src_port ? `${pkt.src_ip}:${pkt.src_port}` : pkt.src_ip;
            const dstStr = pkt.dst_port ? `${pkt.dst_ip}:${pkt.dst_port}` : pkt.dst_ip;
            const summary = pkt.tcp_flags ? `Flags: [${pkt.tcp_flags}]` : pkt.dns_summary || "—";

            return (
              <tr
                key={pkt.packet_id}
                onClick={() => onSelectPacket?.(pkt)}
                className={cn(
                  "cursor-pointer transition-colors",
                  isSelected
                    ? "bg-[#A8DADC]/40 font-bold"
                    : "hover:bg-[#F1FAEE]/70"
                )}
              >
                <td className="py-2 px-3 text-slate-400 font-bold text-[10px]">
                  {pkt.packet_id}
                </td>
                <td className="py-2 px-3 text-slate-500 text-[11px]">
                  {timeStr}
                </td>
                <td className="py-2 px-3 font-semibold text-[#1D3557]">
                  {srcStr}
                </td>
                <td className="py-2 px-3 font-semibold text-[#457B9D]">
                  {dstStr}
                </td>
                <td className="py-2 px-3">
                  <span
                    className={cn(
                      "px-1.5 py-0.5 rounded text-[10px] font-bold border border-[#1D3557] shadow-[1px_1px_0px_#1D3557]",
                      getProtocolColor(pkt.protocol)
                    )}
                  >
                    {pkt.protocol}
                  </span>
                </td>
                <td className="py-2 px-3 text-right text-slate-600 font-bold">
                  {pkt.length} B
                </td>
                <td className="py-2 px-3 text-[11px] text-slate-600 truncate max-w-xs" title={summary}>
                  {summary}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
