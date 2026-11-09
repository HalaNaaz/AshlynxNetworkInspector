"use client";

import React, { useState } from "react";
import {
  Compass,
  Play,
  CheckCircle2,
  AlertTriangle,
  Search,
  Clock,
  Layers,
  Shield,
  Download,
  Copy,
  Check,
  Loader2,
  Globe,
  Cpu,
  Wifi,
} from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoCard } from "@/components/BentoCard";
import { BentoGrid } from "@/components/BentoGrid";
import { MetricCard } from "@/components/MetricCard";
import { StatusIndicator } from "@/components/StatusIndicator";
import { EmptyState } from "@/components/EmptyState";
import { apiClient } from "@/lib/api";
import {
  DiscoveredHostItem,
  DiscoveryValidationResponse,
  HostDiscoveryRequest,
  HostDiscoveryResponse,
} from "@/lib/types";

export default function DiscoveryPage() {
  // Input parameters
  const [cidr, setCidr] = useState("127.0.0.1/32");
  const [method, setMethod] = useState<"AUTO" | "ICMP_ECHO" | "TCP_CONNECT" | "ARP">("AUTO");
  const [timeoutSec, setTimeoutSec] = useState("1.0");
  const [maxHosts, setMaxHosts] = useState("256");
  const [concurrency, setConcurrency] = useState("30");

  // Validation
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState<DiscoveryValidationResponse | null>(null);

  // Execution
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [discoveryResponse, setDiscoveryResponse] = useState<HostDiscoveryResponse | null>(null);
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);

  // Filter & Sort
  const [statusFilter, setStatusFilter] = useState<"ALL" | "ONLINE" | "NO_RESPONSE" | "UNREACHABLE">("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<"ip" | "status" | "latency">("ip");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("asc");
  const [copiedId, setCopiedId] = useState(false);

  // Validate CIDR
  const handleValidate = async () => {
    setIsValidating(true);
    setDiscoveryError(null);
    try {
      const res = await apiClient.validateDiscoveryConfig({ cidr });
      setValidationResult(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Validation call failed";
      setValidationResult({
        valid: false,
        normalized_cidr: null,
        network_address: null,
        broadcast_address: null,
        total_usable_hosts: 0,
        is_authorized: false,
        error: msg,
      });
    } finally {
      setIsValidating(false);
    }
  };

  // Execute Host Discovery
  const handleStartDiscovery = async () => {
    setIsDiscovering(true);
    setDiscoveryError(null);
    try {
      const payload: HostDiscoveryRequest = {
        cidr,
        method,
        timeout: parseFloat(timeoutSec) || 1.0,
        max_hosts: parseInt(maxHosts, 10) || 256,
        concurrency: parseInt(concurrency, 10) || 30,
      };

      const res = await apiClient.executeHostDiscovery(payload);
      setDiscoveryResponse(res);
      setStatusFilter("ALL");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Subnet discovery failed";
      setDiscoveryError(msg);
    } finally {
      setIsDiscovering(false);
    }
  };

  // Filter & sort logic
  const filteredHosts = (discoveryResponse?.hosts || []).filter((h) => {
    const matchesStatus = statusFilter === "ALL" ? true : h.status === statusFilter;
    const matchesSearch =
      h.ip_address.includes(searchQuery) ||
      (h.hostname && h.hostname.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (h.mac_address && h.mac_address.toLowerCase().includes(searchQuery.toLowerCase())) ||
      h.discovery_method.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesStatus && matchesSearch;
  });

  const sortedHosts = [...filteredHosts].sort((a, b) => {
    if (sortBy === "ip") {
      // Sort IP addresses numerically
      const aParts = a.ip_address.split(".").map(Number);
      const bParts = b.ip_address.split(".").map(Number);
      for (let i = 0; i < 4; i++) {
        if (aParts[i] !== bParts[i]) {
          return sortOrder === "asc" ? aParts[i] - bParts[i] : bParts[i] - aParts[i];
        }
      }
      return 0;
    }
    if (sortBy === "status") {
      return sortOrder === "asc" ? a.status.localeCompare(b.status) : b.status.localeCompare(a.status);
    }
    if (sortBy === "latency") {
      const aLat = a.response_time_ms ?? 999999;
      const bLat = b.response_time_ms ?? 999999;
      return sortOrder === "asc" ? aLat - bLat : bLat - aLat;
    }
    return 0;
  });

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-6xl mx-auto">
        {/* Page Hero Banner */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <Compass className="w-4 h-4 text-[#457B9D]" />
              <span>ENGINE C • SUBNET RECONNAISSANCE & INVENTORY</span>
            </div>
            <h1 className="font-heading font-extrabold text-2xl text-[#1D3557] tracking-tight">
              HOST DISCOVERY ENGINE
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Concurrent network sweeps via ARP, ICMP echo ping, and TCP connect with PTR hostname resolution.
            </p>
          </div>

          <StatusIndicator
            status="operational"
            label="ENGINE C: OPERATIONAL (v0.3.0)"
          />
        </div>

        {/* Global Error Banner */}
        {discoveryError && (
          <div className="p-4 rounded-xl border-2 border-[#E63946] bg-[#ffe4e6] shadow-[4px_4px_0px_#E63946] flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-[#E63946] shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <h4 className="font-heading font-extrabold text-[#E63946]">Discovery Execution Halted</h4>
              <p className="text-[#1D3557] font-medium leading-relaxed">{discoveryError}</p>
            </div>
          </div>
        )}

        {/* Configuration Bento Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Controls Form (8 cols) */}
          <BentoCard
            title="SUBNET PARAMETERS & DISPATCH"
            subtitle="Configure target CIDR network, probing technique, and concurrency"
            colSpan="col-span-12"
            className="lg:col-span-8"
            dotGrid
          >
            <div className="space-y-4 font-mono text-xs">
              {/* CIDR Input */}
              <div className="space-y-1.5">
                <label className="block font-bold text-[#1D3557]">
                  Subnet CIDR Range or IP Address
                </label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={cidr}
                    onChange={(e) => {
                      setCidr(e.target.value);
                      setValidationResult(null);
                    }}
                    placeholder="e.g. 192.168.1.0/24 or 127.0.0.1/32"
                    className="flex-1 px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]"
                  />
                  <button
                    type="button"
                    onClick={handleValidate}
                    disabled={isValidating}
                    className="btn-secondary px-4 py-2 font-bold text-xs"
                  >
                    {isValidating ? "Validating..." : "Validate"}
                  </button>
                </div>

                {/* Pre-fill Quick Chips */}
                <div className="flex items-center gap-2 pt-1">
                  <span className="text-[10px] text-[#457B9D] font-bold">Quick Presets:</span>
                  {[
                    { label: "Localhost (/32)", val: "127.0.0.1/32" },
                    { label: "Loopback (/24)", val: "127.0.0.0/24" },
                    { label: "Class C (/24)", val: "192.168.1.0/24" },
                  ].map((p) => (
                    <button
                      key={p.val}
                      type="button"
                      onClick={() => {
                        setCidr(p.val);
                        setValidationResult(null);
                      }}
                      className="px-2 py-0.5 rounded border border-[#1D3557]/40 text-[10px] bg-white hover:bg-[#F1FAEE] text-[#1D3557]"
                    >
                      {p.label}
                    </button>
                  ))}
                </div>

                {validationResult && (
                  <div
                    className={`p-2.5 rounded-lg border-2 mt-2 text-[11px] ${
                      validationResult.valid
                        ? "bg-[#dcfce7] border-[#166534] text-[#166534]"
                        : "bg-[#fee2e2] border-[#b91c1c] text-[#b91c1c]"
                    }`}
                  >
                    {validationResult.valid ? (
                      <div className="space-y-1">
                        <div className="flex items-center gap-1.5 font-bold">
                          <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                          <span>Subnet {validationResult.normalized_cidr} is valid and authorized.</span>
                        </div>
                        <div className="text-[10px] opacity-90 pl-5">
                          Usable addresses: <strong>{validationResult.total_usable_hosts}</strong> • Network: {validationResult.network_address} • Broadcast: {validationResult.broadcast_address}
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                        <span>{validationResult.error || "Invalid subnet notation."}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Discovery Method Selection */}
              <div className="space-y-2">
                <label className="block font-bold text-[#1D3557]">Discovery Technique</label>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {[
                    { id: "AUTO", label: "AUTO (Tri-Phase)" },
                    { id: "ICMP_ECHO", label: "ICMP Echo" },
                    { id: "TCP_CONNECT", label: "TCP Connect" },
                    { id: "ARP", label: "ARP (L2 Local)" },
                  ].map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      onClick={() => setMethod(m.id as "AUTO" | "ICMP_ECHO" | "TCP_CONNECT" | "ARP")}
                      className={`py-2 px-2 rounded-lg border-2 text-[11px] font-bold text-center transition-all ${
                        method === m.id
                          ? "bg-[#457B9D] text-white border-[#1D3557] shadow-[2px_2px_0px_#1D3557]"
                          : "bg-white text-[#1D3557] border-[#1D3557] hover:bg-[#F1FAEE]"
                      }`}
                    >
                      {m.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Sliders: Timeout, Max Hosts, Concurrency */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-1">
                <div className="space-y-1">
                  <label className="flex justify-between text-[#1D3557] font-bold">
                    <span>Probe Timeout:</span>
                    <span className="text-[#457B9D]">{timeoutSec}s</span>
                  </label>
                  <input
                    type="range"
                    min="0.2"
                    max="3.0"
                    step="0.1"
                    value={timeoutSec}
                    onChange={(e) => setTimeoutSec(e.target.value)}
                    className="w-full accent-[#457B9D]"
                  />
                  <span className="text-[10px] text-[#457B9D] block font-sans">
                    0.2s - 3.0s (default 1.0s)
                  </span>
                </div>

                <div className="space-y-1">
                  <label className="flex justify-between text-[#1D3557] font-bold">
                    <span>Max Hosts Limit:</span>
                    <span className="text-[#457B9D]">{maxHosts}</span>
                  </label>
                  <input
                    type="range"
                    min="1"
                    max="512"
                    step="1"
                    value={maxHosts}
                    onChange={(e) => setMaxHosts(e.target.value)}
                    className="w-full accent-[#457B9D]"
                  />
                  <span className="text-[10px] text-[#457B9D] block font-sans">
                    Max sweep limit (up to 512)
                  </span>
                </div>

                <div className="space-y-1">
                  <label className="flex justify-between text-[#1D3557] font-bold">
                    <span>Workers:</span>
                    <span className="text-[#457B9D]">{concurrency}</span>
                  </label>
                  <input
                    type="range"
                    min="5"
                    max="50"
                    step="5"
                    value={concurrency}
                    onChange={(e) => setConcurrency(e.target.value)}
                    className="w-full accent-[#457B9D]"
                  />
                  <span className="text-[10px] text-[#457B9D] block font-sans">
                    Concurrent threads (max 50)
                  </span>
                </div>
              </div>

              {/* Start Discovery Button */}
              <div className="pt-3 border-t-2 border-[#1D3557]/20 flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-[11px] text-[#457B9D] font-sans">
                  <Shield className="w-3.5 h-3.5 text-[#10b981]" />
                  <span>Subnet bounded to RFC-1918 / Loopback</span>
                </div>

                <button
                  type="button"
                  onClick={handleStartDiscovery}
                  disabled={isDiscovering}
                  className="btn-primary flex items-center gap-2 px-6 py-2.5 text-xs font-mono font-bold"
                >
                  {isDiscovering ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Sweeping Subnet...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      <span>Start Subnet Sweep</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </BentoCard>

          {/* Engine C Methodology Card (4 cols) */}
          <BentoCard
            title="DISCOVERY METHODOLOGY"
            subtitle="Engine C multi-vector reconnaissance"
            colSpan="col-span-12"
            className="lg:col-span-4"
            variant="aqua"
          >
            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                  <span>TRI-PHASE AUTO STRATEGY</span>
                  <span className="text-[#457B9D]">ADAPTIVE</span>
                </div>
                <p className="text-[10px] text-[#457B9D] font-sans mt-1">
                  1. Instant ARP probe (L2 local subnet).<br />
                  2. OS ICMP Echo ping (unprivileged).<br />
                  3. Multi-port TCP handshake (80, 443, 22, 135, 445).
                </p>
              </div>

              <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                  <span>REVERSE DNS RESOLUTION</span>
                  <span className="text-[#10b981]">ACTIVE</span>
                </div>
                <p className="text-[10px] text-[#457B9D] font-sans mt-1">
                  Identified online hosts are queried for PTR domain records via standard DNS lookup.
                </p>
              </div>

              <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                  <span>ZERO ELEVATION</span>
                  <span className="text-[#f59e0b]">SAFE</span>
                </div>
                <p className="text-[10px] text-[#457B9D] font-sans mt-1">
                  Windows SendARP API + OS ping utility ensure zero root/administrator elevation requirement.
                </p>
              </div>
            </div>
          </BentoCard>
        </div>

        {/* Discovery Results Section */}
        {discoveryResponse && (
          <div className="space-y-5 animate-in fade-in duration-200">
            <BentoGrid cols={4}>
              <MetricCard
                label="Target Subnet"
                value={discoveryResponse.cidr}
                subtext={`ID: ${discoveryResponse.discovery_id.slice(0, 18)}...`}
                icon={Compass}
                variant="white"
              />
              <MetricCard
                label="Online Hosts"
                value={discoveryResponse.online_hosts_count}
                unit="Nodes"
                subtext="Confirmed responsive"
                icon={CheckCircle2}
                variant={discoveryResponse.online_hosts_count > 0 ? "aqua" : "white"}
                trend={{
                  value: `${discoveryResponse.online_hosts_count} Active`,
                  isPositive: discoveryResponse.online_hosts_count > 0,
                }}
              />
              <MetricCard
                label="Total Addresses Probed"
                value={discoveryResponse.total_probed}
                unit="IPs"
                subtext={`Method: ${discoveryResponse.method}`}
                icon={Layers}
                variant="white"
              />
              <MetricCard
                label="Execution Duration"
                value={discoveryResponse.duration_seconds}
                unit="sec"
                subtext={`Subnet sweep finished`}
                icon={Clock}
                variant="white"
              />
            </BentoGrid>

            {/* Discovered Hosts Table Bento Card */}
            <BentoCard
              title="DISCOVERED HOSTS & INVENTORY"
              subtitle={`Displaying ${sortedHosts.length} of ${discoveryResponse.hosts.length} scanned addresses`}
              action={
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(discoveryResponse.discovery_id);
                      setCopiedId(true);
                      setTimeout(() => setCopiedId(false), 2000);
                    }}
                    className="btn-secondary flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono font-bold"
                  >
                    {copiedId ? <Check className="w-3.5 h-3.5 text-[#10b981]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedId ? "Copied" : "Copy ID"}</span>
                  </button>
                  <button
                    onClick={() => {
                      const blob = new Blob([JSON.stringify(discoveryResponse, null, 2)], { type: "application/json" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = `discovery-${discoveryResponse.discovery_id}.json`;
                      a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="btn-primary flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono font-bold"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>JSON</span>
                  </button>
                </div>
              }
            >
              {/* Filter and Search Sub-bar */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pb-3 border-b-2 border-[#1D3557]/10">
                <div className="relative w-full sm:w-64">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#457B9D]" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search IP, hostname, MAC..."
                    className="w-full pl-8 pr-3 py-1.5 rounded-lg border-2 border-[#1D3557] font-mono text-xs text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
                  />
                </div>

                <div className="flex flex-wrap items-center gap-1 font-mono text-xs self-start sm:self-auto">
                  {(["ALL", "ONLINE", "NO_RESPONSE", "UNREACHABLE"] as const).map((st) => (
                    <button
                      key={st}
                      onClick={() => setStatusFilter(st)}
                      className={`px-2.5 py-1 rounded-md border-2 border-[#1D3557] text-[10px] font-bold transition-all ${
                        statusFilter === st
                          ? "bg-[#457B9D] text-white shadow-[1px_1px_0px_#1D3557]"
                          : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              {/* Table */}
              {sortedHosts.length === 0 ? (
                <EmptyState
                  title="No Hosts Match Criteria"
                  description="Try adjusting your status filter or search query."
                />
              ) : (
                <div className="overflow-x-auto mt-2">
                  <table className="w-full text-left font-mono text-xs border-collapse">
                    <thead>
                      <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-bold text-[11px] uppercase tracking-wider">
                        <th
                          onClick={() => {
                            setSortBy("ip");
                            setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                          }}
                          className="py-2.5 px-3 cursor-pointer select-none hover:bg-[#A8DADC]/40"
                        >
                          IP Address {sortBy === "ip" && (sortOrder === "asc" ? "▲" : "▼")}
                        </th>
                        <th className="py-2.5 px-3">Resolved Hostname</th>
                        <th className="py-2.5 px-3">Method</th>
                        <th
                          onClick={() => {
                            setSortBy("status");
                            setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                          }}
                          className="py-2.5 px-3 cursor-pointer select-none hover:bg-[#A8DADC]/40"
                        >
                          Status {sortBy === "status" && (sortOrder === "asc" ? "▲" : "▼")}
                        </th>
                        <th className="py-2.5 px-3">MAC Address</th>
                        <th
                          onClick={() => {
                            setSortBy("latency");
                            setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                          }}
                          className="py-2.5 px-3 text-right cursor-pointer select-none hover:bg-[#A8DADC]/40"
                        >
                          Latency {sortBy === "latency" && (sortOrder === "asc" ? "▲" : "▼")}
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y border-b border-[#1D3557]/20 text-[#1D3557]">
                      {sortedHosts.map((h) => (
                        <tr
                          key={h.ip_address}
                          className={`hover:bg-[#F1FAEE]/70 transition-colors ${
                            h.status === "ONLINE" ? "bg-[#dcfce7]/30" : ""
                          }`}
                        >
                          <td className="py-2 px-3 font-extrabold text-[#1D3557]">{h.ip_address}</td>
                          <td className="py-2 px-3 font-bold">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <span className={h.hostname === "Unresolved" ? "text-slate-400 italic font-normal" : "text-[#1D3557]"}>
                                {h.hostname || "Unresolved"}
                              </span>
                              {h.hostname_source && h.hostname_source !== "UNRESOLVED" && (
                                <span className="text-[9px] px-1 py-0.5 rounded border border-[#1D3557]/30 bg-[#F1FAEE] text-[#457B9D] font-mono font-bold">
                                  {h.hostname_source}
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2 px-3">
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border border-[#1D3557]/30 bg-white text-[#1D3557]">
                              {h.discovery_method}
                            </span>
                          </td>
                          <td className="py-2 px-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold border shadow-[1px_1px_0px_#1D3557] ${
                                h.status === "ONLINE"
                                  ? "bg-[#dcfce7] text-[#166534] border-[#166534]"
                                  : h.status === "UNREACHABLE"
                                  ? "bg-[#fee2e2] text-[#991b1b] border-[#991b1b]"
                                  : "bg-[#f1f5f9] text-[#64748b] border-[#64748b]"
                              }`}
                            >
                              {h.status}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-[#1D3557]">
                            {h.mac_address && h.mac_address !== "00:00:00:00:00:00" ? (
                              <span>{h.mac_address}</span>
                            ) : (
                              <span className="text-slate-400 italic text-[11px]">Not applicable</span>
                            )}
                          </td>
                          <td className="py-2 px-3 text-right text-[#457B9D] font-bold">
                            {h.response_time_ms !== null ? `${h.response_time_ms} ms` : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </BentoCard>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}

