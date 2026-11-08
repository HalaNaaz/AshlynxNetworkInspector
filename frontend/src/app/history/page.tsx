"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { History, Search, RefreshCw, Radar, Compass, ArrowRight } from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoCard } from "@/components/BentoCard";
import { EmptyState } from "@/components/EmptyState";
import { StatusIndicator } from "@/components/StatusIndicator";
import { apiClient } from "@/lib/api";
import { DiscoveryHistoryItem, ScanHistoryItem } from "@/lib/types";

export default function HistoryPage() {
  const [activeTab, setActiveTab] = useState<"SCANS" | "DISCOVERY">("SCANS");
  const [searchTerm, setSearchTerm] = useState("");
  const [scanRecords, setScanRecords] = useState<ScanHistoryItem[]>([]);
  const [discoveryRecords, setDiscoveryRecords] = useState<DiscoveryHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const [scans, discoveries] = await Promise.allSettled([
        apiClient.getScanHistory(),
        apiClient.getDiscoveryHistory(),
      ]);
      if (scans.status === "fulfilled") setScanRecords(scans.value);
      if (discoveries.status === "fulfilled") setDiscoveryRecords(discoveries.value);
    } catch {
      // Ignore background fetch error
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const filteredScans = scanRecords.filter(
    (rec) =>
      rec.target.includes(searchTerm) ||
      rec.scan_id.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredDiscoveries = discoveryRecords.filter(
    (rec) =>
      rec.cidr.includes(searchTerm) ||
      rec.discovery_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rec.method.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-6xl mx-auto">
        {/* Page Hero Banner */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <History className="w-4 h-4 text-[#457B9D]" />
              <span>PERSISTENCE & RECONNAISSANCE AUDIT</span>
            </div>
            <h1 className="font-heading font-extrabold text-2xl text-[#1D3557] tracking-tight">
              RECONNAISSANCE AUDIT ARCHIVE
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Session-archived records for Port Scans (Engine A) and Subnet Discoveries (Engine C).
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchHistory}
              disabled={loading}
              className="btn-secondary flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-bold"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-[#457B9D]" : ""}`} />
              <span>Refresh</span>
            </button>
            <StatusIndicator
              status="operational"
              label={`${scanRecords.length + discoveryRecords.length} SESSIONS`}
            />
          </div>
        </div>

        {/* Tab & Search Bar */}
        <div className="p-4 rounded-xl border-2 border-[#1D3557] bg-white shadow-[3px_3px_0px_#1D3557] flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 bg-[#F1FAEE] p-1 rounded-lg border-2 border-[#1D3557]">
            <button
              onClick={() => setActiveTab("SCANS")}
              className={`px-3 py-1.5 rounded-md font-mono text-xs font-bold transition-all ${
                activeTab === "SCANS"
                  ? "bg-[#457B9D] text-white border-2 border-[#1D3557] shadow-[1px_1px_0px_#1D3557]"
                  : "text-[#1D3557] border-2 border-transparent"
              }`}
            >
              PORT SCANS ({scanRecords.length})
            </button>
            <button
              onClick={() => setActiveTab("DISCOVERY")}
              className={`px-3 py-1.5 rounded-md font-mono text-xs font-bold transition-all ${
                activeTab === "DISCOVERY"
                  ? "bg-[#457B9D] text-white border-2 border-[#1D3557] shadow-[1px_1px_0px_#1D3557]"
                  : "text-[#1D3557] border-2 border-transparent"
              }`}
            >
              HOST DISCOVERIES ({discoveryRecords.length})
            </button>
          </div>

          <div className="relative w-full sm:w-72">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-[#457B9D]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search target, CIDR, or ID..."
              className="w-full pl-9 pr-3 py-1.5 rounded-lg border-2 border-[#1D3557] font-mono text-xs text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
            />
          </div>
        </div>

        {/* ================= PORT SCANS TABLE ================= */}
        {activeTab === "SCANS" && (
          <BentoCard
            title="PORT SCAN ARCHIVE"
            subtitle="Chronological record of TCP and UDP port reconnaissance"
            action={
              <Link
                href="/scanner"
                className="btn-primary flex items-center gap-1.5 px-3 py-1 text-xs font-mono font-bold"
              >
                <Radar className="w-3.5 h-3.5" />
                <span>New Port Scan</span>
              </Link>
            }
          >
            {filteredScans.length === 0 ? (
              <EmptyState
                title="No Scan Records Found"
                description="Execute a port scan from the Port Scanner workspace to populate this archive."
                icon={History}
                badge="ENGINE A"
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs border-collapse">
                  <thead>
                    <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-bold text-[11px] uppercase tracking-wider">
                      <th className="py-2.5 px-3">Session ID</th>
                      <th className="py-2.5 px-3">Target</th>
                      <th className="py-2.5 px-3">Type</th>
                      <th className="py-2.5 px-3">Ports</th>
                      <th className="py-2.5 px-3">Open</th>
                      <th className="py-2.5 px-3">Duration</th>
                      <th className="py-2.5 px-3 text-right">Timestamp (Local)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y border-b border-[#1D3557]/20 text-[#1D3557]">
                    {filteredScans.map((item) => (
                      <tr key={item.scan_id} className="hover:bg-[#F1FAEE]/60 transition-colors">
                        <td className="py-2 px-3 font-bold text-[#1D3557]">
                          {item.scan_id.slice(0, 18)}...
                        </td>
                        <td className="py-2 px-3 text-[#457B9D] font-bold">
                          {item.target}
                        </td>
                        <td className="py-2 px-3">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold border border-[#1D3557] bg-[#A8DADC] text-[#1D3557]">
                            {item.scan_type}
                          </span>
                        </td>
                        <td className="py-2 px-3 font-semibold">
                          {item.total_ports}
                        </td>
                        <td className="py-2 px-3">
                          <span className="font-extrabold text-[#10b981]">
                            {item.open_ports} open
                          </span>
                        </td>
                        <td className="py-2 px-3 text-[#457B9D]">
                          {item.duration_seconds}s
                        </td>
                        <td
                          className="py-2 px-3 text-right text-slate-600 font-medium cursor-help"
                          title={`UTC: ${new Date(item.started_at).toISOString()}`}
                        >
                          {new Date(item.started_at).toLocaleString([], {
                            dateStyle: "short",
                            timeStyle: "medium",
                          })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </BentoCard>
        )}

        {/* ================= HOST DISCOVERY TABLE ================= */}
        {activeTab === "DISCOVERY" && (
          <BentoCard
            title="HOST DISCOVERY ARCHIVE"
            subtitle="Chronological record of subnet sweeps and active host inventories"
            action={
              <Link
                href="/discovery"
                className="btn-primary flex items-center gap-1.5 px-3 py-1 text-xs font-mono font-bold"
              >
                <Compass className="w-3.5 h-3.5" />
                <span>New Subnet Sweep</span>
              </Link>
            }
          >
            {filteredDiscoveries.length === 0 ? (
              <EmptyState
                title="No Subnet Discovery Records"
                description="Run a host discovery sweep from the Host Discovery workspace to populate this archive."
                icon={Compass}
                badge="ENGINE C"
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs border-collapse">
                  <thead>
                    <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-bold text-[11px] uppercase tracking-wider">
                      <th className="py-2.5 px-3">Discovery ID</th>
                      <th className="py-2.5 px-3">Subnet (CIDR)</th>
                      <th className="py-2.5 px-3">Method</th>
                      <th className="py-2.5 px-3">Probed</th>
                      <th className="py-2.5 px-3">Online Nodes</th>
                      <th className="py-2.5 px-3">Duration</th>
                      <th className="py-2.5 px-3 text-right">Timestamp (Local)</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y border-b border-[#1D3557]/20 text-[#1D3557]">
                    {filteredDiscoveries.map((item) => (
                      <tr key={item.discovery_id} className="hover:bg-[#F1FAEE]/60 transition-colors">
                        <td className="py-2 px-3 font-bold text-[#1D3557]">
                          {item.discovery_id.slice(0, 18)}...
                        </td>
                        <td className="py-2 px-3 text-[#457B9D] font-bold">
                          {item.cidr}
                        </td>
                        <td className="py-2 px-3">
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold border border-[#1D3557] bg-[#A8DADC] text-[#1D3557]">
                            {item.method}
                          </span>
                        </td>
                        <td className="py-2 px-3 font-semibold">
                          {item.total_probed}
                        </td>
                        <td className="py-2 px-3">
                          <span className="font-extrabold text-[#10b981]">
                            {item.online_count} online
                          </span>
                        </td>
                        <td className="py-2 px-3 text-[#457B9D]">
                          {item.duration_seconds}s
                        </td>
                        <td
                          className="py-2 px-3 text-right text-slate-600 font-medium cursor-help"
                          title={`UTC: ${new Date(item.started_at).toISOString()}`}
                        >
                          {new Date(item.started_at).toLocaleString([], {
                            dateStyle: "short",
                            timeStyle: "medium",
                          })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </BentoCard>
        )}
      </div>
    </DashboardLayout>
  );
}
