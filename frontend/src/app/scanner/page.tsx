"use client";

import React, { useState } from "react";
import {
  Radar,
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
  Radio,
  HelpCircle,
  Activity,
} from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoCard } from "@/components/BentoCard";
import { BentoGrid } from "@/components/BentoGrid";
import { MetricCard } from "@/components/MetricCard";
import { StatusIndicator } from "@/components/StatusIndicator";
import { EmptyState } from "@/components/EmptyState";
import { apiClient } from "@/lib/api";
import {
  PortScanRequest,
  PortScanResultItem,
  ScanExecutionResponse,
  ScanValidationResponse,
  UdpScanExecutionResponse,
  UdpScanRequest,
  UdpScanResultItem,
} from "@/lib/types";

export default function ScannerPage() {
  // Active engine tab: "TCP" | "UDP"
  const [activeEngine, setActiveEngine] = useState<"TCP" | "UDP">("TCP");

  // ==================== TCP CONFIG & EXECUTION STATES ====================
  const [tcpTarget, setTcpTarget] = useState("127.0.0.1");
  const [tcpMode, setTcpMode] = useState<"common" | "range" | "list">("common");
  const [tcpRange, setTcpRange] = useState("1-1024");
  const [tcpList, setTcpList] = useState("21, 22, 80, 443, 135, 445, 3306, 8080");
  const [tcpTimeout, setTcpTimeout] = useState("1.0");
  const [tcpConcurrency, setTcpConcurrency] = useState("50");

  const [isTcpValidating, setIsTcpValidating] = useState(false);
  const [tcpValidation, setTcpValidation] = useState<ScanValidationResponse | null>(null);
  const [isTcpScanning, setIsTcpScanning] = useState(false);
  const [tcpResponse, setTcpResponse] = useState<ScanExecutionResponse | null>(null);
  const [tcpError, setTcpError] = useState<string | null>(null);

  const [tcpFilterState, setTcpFilterState] = useState<string>("ALL");
  const [tcpSearch, setTcpSearch] = useState("");
  const [tcpSortBy, setTcpSortBy] = useState<"port" | "state" | "latency">("port");
  const [tcpSortOrder, setTcpSortOrder] = useState<"asc" | "desc">("asc");
  const [tcpCopiedId, setTcpCopiedId] = useState(false);

  // ==================== UDP CONFIG & EXECUTION STATES ====================
  const [udpTarget, setUdpTarget] = useState("127.0.0.1");
  const [udpMode, setUdpMode] = useState<"common" | "range" | "list">("common");
  const [udpRange, setUdpRange] = useState("50-150");
  const [udpList, setUdpList] = useState("53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900");
  const [udpTimeout, setUdpTimeout] = useState("1.0");
  const [udpConcurrency, setUdpConcurrency] = useState("20");

  const [isUdpValidating, setIsUdpValidating] = useState(false);
  const [udpValidation, setUdpValidation] = useState<ScanValidationResponse | null>(null);
  const [isUdpScanning, setIsUdpScanning] = useState(false);
  const [udpResponse, setUdpResponse] = useState<UdpScanExecutionResponse | null>(null);
  const [udpError, setUdpError] = useState<string | null>(null);

  const [udpFilterState, setUdpFilterState] = useState<string>("ALL");
  const [udpSearch, setUdpSearch] = useState("");
  const [udpSortBy, setUdpSortBy] = useState<"port" | "state" | "latency">("port");
  const [udpSortOrder, setUdpSortOrder] = useState<"asc" | "desc">("asc");
  const [udpCopiedId, setUdpCopiedId] = useState(false);

  // ==================== TCP HANDLERS ====================
  const handleValidateTcp = async () => {
    setIsTcpValidating(true);
    setTcpError(null);
    try {
      const payload: { target: string; preset?: string; port_range?: string; ports?: number[] } = {
        target: tcpTarget,
      };
      if (tcpMode === "common") payload.preset = "common";
      else if (tcpMode === "range") payload.port_range = tcpRange;
      else payload.ports = tcpList.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));

      const res = await apiClient.validateScanConfig(payload);
      setTcpValidation(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "TCP validation failed";
      setTcpValidation({
        valid: false,
        target_ip: null,
        resolved_ports_count: 0,
        resolved_ports_preview: [],
        target_authorized: false,
        error: msg,
      });
    } finally {
      setIsTcpValidating(false);
    }
  };

  const handleStartTcpScan = async () => {
    setIsTcpScanning(true);
    setTcpError(null);
    try {
      const payload: PortScanRequest = {
        target: tcpTarget,
        timeout: parseFloat(tcpTimeout) || 1.0,
        concurrency: parseInt(tcpConcurrency, 10) || 50,
      };
      if (tcpMode === "common") payload.preset = "common";
      else if (tcpMode === "range") payload.port_range = tcpRange;
      else payload.ports = tcpList.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));

      const res = await apiClient.executePortScan(payload);
      setTcpResponse(res);
      setTcpFilterState("ALL");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "TCP scan failed to execute";
      setTcpError(msg);
    } finally {
      setIsTcpScanning(false);
    }
  };

  // ==================== UDP HANDLERS ====================
  const handleValidateUdp = async () => {
    setIsUdpValidating(true);
    setUdpError(null);
    try {
      const payload: { target: string; preset?: string; port_range?: string; ports?: number[] } = {
        target: udpTarget,
      };
      if (udpMode === "common") payload.preset = "common";
      else if (udpMode === "range") payload.port_range = udpRange;
      else payload.ports = udpList.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));

      const res = await apiClient.validateUdpScanConfig(payload);
      setUdpValidation(res);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "UDP validation failed";
      setUdpValidation({
        valid: false,
        target_ip: null,
        resolved_ports_count: 0,
        resolved_ports_preview: [],
        target_authorized: false,
        error: msg,
      });
    } finally {
      setIsUdpValidating(false);
    }
  };

  const handleStartUdpScan = async () => {
    setIsUdpScanning(true);
    setUdpError(null);
    try {
      const payload: UdpScanRequest = {
        target: udpTarget,
        timeout: parseFloat(udpTimeout) || 1.0,
        concurrency: parseInt(udpConcurrency, 10) || 20,
      };
      if (udpMode === "common") payload.preset = "common";
      else if (udpMode === "range") payload.port_range = udpRange;
      else payload.ports = udpList.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));

      const res = await apiClient.executeUdpPortScan(payload);
      setUdpResponse(res);
      setUdpFilterState("ALL");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "UDP scan failed to execute";
      setUdpError(msg);
    } finally {
      setIsUdpScanning(false);
    }
  };

  // Filter & sort logic for TCP
  const filteredTcpResults = (tcpResponse?.results || []).filter((r) => {
    const matchesState = tcpFilterState === "ALL" ? true : r.state === tcpFilterState;
    const matchesSearch =
      r.port.toString().includes(tcpSearch) ||
      r.service.toLowerCase().includes(tcpSearch.toLowerCase()) ||
      r.state.toLowerCase().includes(tcpSearch.toLowerCase());
    return matchesState && matchesSearch;
  });

  const sortedTcpResults = [...filteredTcpResults].sort((a, b) => {
    if (tcpSortBy === "port") return tcpSortOrder === "asc" ? a.port - b.port : b.port - a.port;
    if (tcpSortBy === "state") return tcpSortOrder === "asc" ? a.state.localeCompare(b.state) : b.state.localeCompare(a.state);
    if (tcpSortBy === "latency") return tcpSortOrder === "asc" ? a.response_time_ms - b.response_time_ms : b.response_time_ms - a.response_time_ms;
    return 0;
  });

  // Filter & sort logic for UDP
  const filteredUdpResults = (udpResponse?.results || []).filter((r) => {
    const matchesState = udpFilterState === "ALL" ? true : r.state === udpFilterState;
    const matchesSearch =
      r.port.toString().includes(udpSearch) ||
      r.service.toLowerCase().includes(udpSearch.toLowerCase()) ||
      r.state.toLowerCase().includes(udpSearch.toLowerCase());
    return matchesState && matchesSearch;
  });

  const sortedUdpResults = [...filteredUdpResults].sort((a, b) => {
    if (udpSortBy === "port") return udpSortOrder === "asc" ? a.port - b.port : b.port - a.port;
    if (udpSortBy === "state") return udpSortOrder === "asc" ? a.state.localeCompare(b.state) : b.state.localeCompare(a.state);
    if (udpSortBy === "latency") return udpSortOrder === "asc" ? a.response_time_ms - b.response_time_ms : b.response_time_ms - a.response_time_ms;
    return 0;
  });

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-6xl mx-auto">
        {/* Page Hero Banner */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <Radar className="w-4 h-4 text-[#457B9D]" />
              <span>ENGINE A • ACTIVE PORT RECONNAISSANCE</span>
            </div>
            <h1 className="font-heading font-extrabold text-2xl text-[#1D3557] tracking-tight">
              PORT SCANNER WORKSTATION
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Independent TCP Connect and UDP Datagram reconnaissance engines with verified state classification.
            </p>
          </div>

          {/* Engine Selector Tabs */}
          <div className="flex items-center gap-2 bg-[#F1FAEE] p-1.5 rounded-xl border-2 border-[#1D3557] shadow-[2px_2px_0px_#1D3557]">
            <button
              onClick={() => setActiveEngine("TCP")}
              className={`px-4 py-2 rounded-lg font-mono text-xs font-bold transition-all ${
                activeEngine === "TCP"
                  ? "bg-[#457B9D] text-white border-2 border-[#1D3557] shadow-[2px_2px_0px_#1D3557]"
                  : "text-[#1D3557] hover:bg-white border-2 border-transparent"
              }`}
            >
              TCP CONNECT
            </button>
            <button
              onClick={() => setActiveEngine("UDP")}
              className={`px-4 py-2 rounded-lg font-mono text-xs font-bold transition-all ${
                activeEngine === "UDP"
                  ? "bg-[#457B9D] text-white border-2 border-[#1D3557] shadow-[2px_2px_0px_#1D3557]"
                  : "text-[#1D3557] hover:bg-white border-2 border-transparent"
              }`}
            >
              UDP DATAGRAM
            </button>
          </div>
        </div>

        {/* ============================================================== */}
        {/* ======================= TCP ENGINE UI ======================= */}
        {/* ============================================================== */}
        {activeEngine === "TCP" && (
          <div className="space-y-6">
            {tcpError && (
              <div className="p-4 rounded-xl border-2 border-[#E63946] bg-[#ffe4e6] shadow-[4px_4px_0px_#E63946] flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-[#E63946] shrink-0 mt-0.5" />
                <div className="text-xs space-y-1">
                  <h4 className="font-heading font-extrabold text-[#E63946]">TCP Scan Failed</h4>
                  <p className="text-[#1D3557] font-medium leading-relaxed">{tcpError}</p>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Controls Form (8 cols) */}
              <BentoCard
                title="TCP SCAN PARAMETERS & DISPATCH"
                subtitle="Configure target IP, port scopes, timeout, and concurrency"
                colSpan="col-span-12"
                className="lg:col-span-8"
                dotGrid
              >
                <div className="space-y-4 font-mono text-xs">
                  {/* Target Input */}
                  <div className="space-y-1.5">
                    <label className="block font-bold text-[#1D3557]">Target IP Address / Hostname</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={tcpTarget}
                        onChange={(e) => {
                          setTcpTarget(e.target.value);
                          setTcpValidation(null);
                        }}
                        placeholder="e.g. 127.0.0.1 or localhost"
                        className="flex-1 px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]"
                      />
                      <button
                        type="button"
                        onClick={handleValidateTcp}
                        disabled={isTcpValidating}
                        className="btn-secondary px-4 py-2 font-bold text-xs"
                      >
                        {isTcpValidating ? "Checking..." : "Validate"}
                      </button>
                    </div>

                    {tcpValidation && (
                      <div
                        className={`p-2.5 rounded-lg border-2 mt-2 text-[11px] ${
                          tcpValidation.valid
                            ? "bg-[#dcfce7] border-[#166534] text-[#166534]"
                            : "bg-[#fee2e2] border-[#b91c1c] text-[#b91c1c]"
                        }`}
                      >
                        {tcpValidation.valid ? (
                          <div className="flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            <span>
                              Target <strong>{tcpValidation.target_ip}</strong> authorized. {tcpValidation.resolved_ports_count} ports staged for scan.
                            </span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                            <span>{tcpValidation.error || "Invalid scan configuration."}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Port Selection Modes */}
                  <div className="space-y-2">
                    <label className="block font-bold text-[#1D3557]">Port Scope Selection</label>
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { id: "common", label: "Common Ports (21)" },
                        { id: "range", label: "Port Range" },
                        { id: "list", label: "Custom List" },
                      ].map((mode) => (
                        <button
                          key={mode.id}
                          type="button"
                          onClick={() => {
                            setTcpMode(mode.id as "common" | "range" | "list");
                            setTcpValidation(null);
                          }}
                          className={`py-2 px-2.5 rounded-lg border-2 text-[11px] font-bold text-center transition-all ${
                            tcpMode === mode.id
                              ? "bg-[#457B9D] text-white border-[#1D3557] shadow-[2px_2px_0px_#1D3557]"
                              : "bg-white text-[#1D3557] border-[#1D3557] hover:bg-[#F1FAEE]"
                          }`}
                        >
                          {mode.label}
                        </button>
                      ))}
                    </div>

                    {tcpMode === "range" && (
                      <div className="pt-1">
                        <input
                          type="text"
                          value={tcpRange}
                          onChange={(e) => setTcpRange(e.target.value)}
                          placeholder="e.g. 1-1024 or 80-90"
                          className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
                        />
                      </div>
                    )}

                    {tcpMode === "list" && (
                      <div className="pt-1">
                        <input
                          type="text"
                          value={tcpList}
                          onChange={(e) => setTcpList(e.target.value)}
                          placeholder="e.g. 21, 22, 80, 443, 3306"
                          className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
                        />
                      </div>
                    )}
                  </div>

                  {/* Sliders: Timeout & Concurrency */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
                    <div className="space-y-1">
                      <label className="flex justify-between text-[#1D3557] font-bold">
                        <span>Connection Timeout:</span>
                        <span className="text-[#457B9D]">{tcpTimeout}s</span>
                      </label>
                      <input
                        type="range"
                        min="0.2"
                        max="3.0"
                        step="0.1"
                        value={tcpTimeout}
                        onChange={(e) => setTcpTimeout(e.target.value)}
                        className="w-full accent-[#457B9D]"
                      />
                      <span className="text-[10px] text-[#457B9D] block font-sans">
                        Range: 0.2s - 3.0s (default 1.0s)
                      </span>
                    </div>

                    <div className="space-y-1">
                      <label className="flex justify-between text-[#1D3557] font-bold">
                        <span>Concurrency:</span>
                        <span className="text-[#457B9D]">{tcpConcurrency} workers</span>
                      </label>
                      <input
                        type="range"
                        min="5"
                        max="100"
                        step="5"
                        value={tcpConcurrency}
                        onChange={(e) => setTcpConcurrency(e.target.value)}
                        className="w-full accent-[#457B9D]"
                      />
                      <span className="text-[10px] text-[#457B9D] block font-sans">
                        Worker pool size (max 100 threads)
                      </span>
                    </div>
                  </div>

                  {/* Start Button */}
                  <div className="pt-3 border-t-2 border-[#1D3557]/20 flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-[11px] text-[#457B9D] font-sans">
                      <Shield className="w-3.5 h-3.5 text-[#10b981]" />
                      <span>RFC-1918 safe-mode boundaries enforced.</span>
                    </div>

                    <button
                      type="button"
                      onClick={handleStartTcpScan}
                      disabled={isTcpScanning}
                      className="btn-primary flex items-center gap-2 px-6 py-2.5 text-xs font-mono font-bold"
                    >
                      {isTcpScanning ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" />
                          <span>Scanning TCP Ports...</span>
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4" />
                          <span>Start TCP Scan</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </BentoCard>

              {/* Methodology Card (4 cols) */}
              <BentoCard
                title="METHODOLOGY & CLASSIFICATION"
                subtitle="Engine A TCP connect specifications"
                colSpan="col-span-12"
                className="lg:col-span-4"
                variant="aqua"
              >
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                    <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                      <span>SCAN MECHANISM</span>
                      <span className="text-[#457B9D]">TCP CONNECT</span>
                    </div>
                    <p className="text-[10px] text-[#457B9D] font-sans mt-1">
                      Full standard three-way handshake (SYN, SYN-ACK, ACK) via unprivileged socket connect_ex().
                    </p>
                  </div>

                  <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                    <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                      <span>STATE LOGIC</span>
                      <span className="text-[#10b981]">QUAD-STATE</span>
                    </div>
                    <div className="text-[10px] text-[#457B9D] font-sans mt-1 space-y-0.5">
                      <p>• <strong>OPEN:</strong> Handshake confirmed (code 0).</p>
                      <p>• <strong>CLOSED:</strong> Explicit RST (ECONNREFUSED / 10061).</p>
                      <p>• <strong>FILTERED:</strong> Explicit permission/firewall drop.</p>
                      <p>• <strong>NO_RESPONSE:</strong> Socket timeout without evidence.</p>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                    <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                      <span>SERVICE CONFIDENCE</span>
                      <span className="text-[#f59e0b]">INFERRED</span>
                    </div>
                    <p className="text-[10px] text-[#457B9D] font-sans mt-1">
                      Derived from well-known port database; verified banner grabbing reserved for later phases.
                    </p>
                  </div>
                </div>
              </BentoCard>
            </div>

            {/* TCP Results Table */}
            {tcpResponse && (
              <div className="space-y-5 animate-in fade-in duration-200">
                <BentoGrid cols={4}>
                  <MetricCard
                    label="Target & Scan ID"
                    value={tcpResponse.target}
                    subtext={`ID: ${tcpResponse.scan_id.slice(0, 18)}...`}
                    icon={Radar}
                    variant="white"
                  />
                  <MetricCard
                    label="Open Ports"
                    value={tcpResponse.open_ports}
                    unit="Sockets"
                    subtext="Confirmed listening"
                    icon={CheckCircle2}
                    variant={tcpResponse.open_ports > 0 ? "aqua" : "white"}
                  />
                  <MetricCard
                    label="Closed Ports"
                    value={tcpResponse.closed_ports}
                    unit="Sockets"
                    subtext="Explicit RST refusal"
                    icon={Layers}
                    variant="white"
                  />
                  <MetricCard
                    label="Execution Duration"
                    value={tcpResponse.duration_seconds}
                    unit="sec"
                    subtext={`Total ${tcpResponse.total_ports} ports scanned`}
                    icon={Clock}
                    variant="white"
                  />
                </BentoGrid>

                <BentoCard
                  title="TCP PORT FINDINGS"
                  subtitle={`Displaying ${sortedTcpResults.length} of ${tcpResponse.results.length} evaluated ports`}
                  action={
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(tcpResponse.scan_id);
                          setTcpCopiedId(true);
                          setTimeout(() => setTcpCopiedId(false), 2000);
                        }}
                        className="btn-secondary flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono font-bold"
                      >
                        {tcpCopiedId ? <Check className="w-3.5 h-3.5 text-[#10b981]" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{tcpCopiedId ? "Copied" : "Copy ID"}</span>
                      </button>
                      <button
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(tcpResponse, null, 2)], { type: "application/json" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `tcp-${tcpResponse.scan_id}.json`;
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
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pb-3 border-b-2 border-[#1D3557]/10">
                    <div className="relative w-full sm:w-64">
                      <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#457B9D]" />
                      <input
                        type="text"
                        value={tcpSearch}
                        onChange={(e) => setTcpSearch(e.target.value)}
                        placeholder="Filter port or service..."
                        className="w-full pl-8 pr-3 py-1.5 rounded-lg border-2 border-[#1D3557] font-mono text-xs text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
                      />
                    </div>

                    <div className="flex flex-wrap items-center gap-1 font-mono text-xs self-start sm:self-auto">
                      {["ALL", "OPEN", "CLOSED", "FILTERED", "NO_RESPONSE"].map((st) => (
                        <button
                          key={st}
                          onClick={() => setTcpFilterState(st)}
                          className={`px-2.5 py-1 rounded-md border-2 border-[#1D3557] text-[10px] font-bold transition-all ${
                            tcpFilterState === st
                              ? "bg-[#457B9D] text-white shadow-[1px_1px_0px_#1D3557]"
                              : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
                          }`}
                        >
                          {st}
                        </button>
                      ))}
                    </div>
                  </div>

                  {sortedTcpResults.length === 0 ? (
                    <EmptyState
                      title="No Ports Match Filter"
                      description="Adjust search term or select another state category."
                    />
                  ) : (
                    <div className="overflow-x-auto mt-2">
                      <table className="w-full text-left font-mono text-xs border-collapse">
                        <thead>
                          <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-bold text-[11px] uppercase tracking-wider">
                            <th
                              onClick={() => {
                                setTcpSortBy("port");
                                setTcpSortOrder(tcpSortOrder === "asc" ? "desc" : "asc");
                              }}
                              className="py-2.5 px-3 cursor-pointer select-none hover:bg-[#A8DADC]/40"
                            >
                              Port {tcpSortBy === "port" && (tcpSortOrder === "asc" ? "▲" : "▼")}
                            </th>
                            <th className="py-2.5 px-3">Proto</th>
                            <th
                              onClick={() => {
                                setTcpSortBy("state");
                                setTcpSortOrder(tcpSortOrder === "asc" ? "desc" : "asc");
                              }}
                              className="py-2.5 px-3 cursor-pointer select-none hover:bg-[#A8DADC]/40"
                            >
                              State {tcpSortBy === "state" && (tcpSortOrder === "asc" ? "▲" : "▼")}
                            </th>
                            <th className="py-2.5 px-3">Inferred Service</th>
                            <th className="py-2.5 px-3">Confidence</th>
                            <th
                              onClick={() => {
                                setTcpSortBy("latency");
                                setTcpSortOrder(tcpSortOrder === "asc" ? "desc" : "asc");
                              }}
                              className="py-2.5 px-3 text-right cursor-pointer select-none hover:bg-[#A8DADC]/40"
                            >
                              Latency {tcpSortBy === "latency" && (tcpSortOrder === "asc" ? "▲" : "▼")}
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y border-b border-[#1D3557]/20 text-[#1D3557]">
                          {sortedTcpResults.map((item) => (
                            <tr
                              key={`${item.port}-${item.protocol}`}
                              className={`hover:bg-[#F1FAEE]/70 transition-colors ${
                                item.state === "OPEN" ? "bg-[#dcfce7]/30" : ""
                              }`}
                            >
                              <td className="py-2 px-3 font-extrabold text-[#1D3557]">{item.port}</td>
                              <td className="py-2 px-3 text-[#457B9D] font-bold">{item.protocol}</td>
                              <td className="py-2 px-3">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold border shadow-[1px_1px_0px_#1D3557] ${
                                    item.state === "OPEN"
                                      ? "bg-[#dcfce7] text-[#166534] border-[#166534]"
                                      : item.state === "CLOSED"
                                      ? "bg-[#f1f5f9] text-[#475569] border-[#475569]"
                                      : item.state === "NO_RESPONSE"
                                      ? "bg-[#fef3c7] text-[#92400e] border-[#92400e]"
                                      : "bg-[#e0f2fe] text-[#0369a1] border-[#0369a1]"
                                  }`}
                                >
                                  {item.state}
                                </span>
                              </td>
                              <td className="py-2 px-3 font-bold text-[#1D3557]">{item.service}</td>
                              <td className="py-2 px-3 text-[10px] text-[#457B9D] font-medium">{item.service_confidence}</td>
                              <td className="py-2 px-3 text-right text-[#457B9D] font-bold">{item.response_time_ms} ms</td>
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
        )}

        {/* ============================================================== */}
        {/* ======================= UDP ENGINE UI ======================= */}
        {/* ============================================================== */}
        {activeEngine === "UDP" && (
          <div className="space-y-6">
            {udpError && (
              <div className="p-4 rounded-xl border-2 border-[#E63946] bg-[#ffe4e6] shadow-[4px_4px_0px_#E63946] flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-[#E63946] shrink-0 mt-0.5" />
                <div className="text-xs space-y-1">
                  <h4 className="font-heading font-extrabold text-[#E63946]">UDP Scan Failed</h4>
                  <p className="text-[#1D3557] font-medium leading-relaxed">{udpError}</p>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Controls Form (8 cols) */}
              <BentoCard
                title="UDP SCAN PARAMETERS & DISPATCH"
                subtitle="Configure UDP target, datagram presets, timeout, and concurrency"
                colSpan="col-span-12"
                className="lg:col-span-8"
                dotGrid
              >
                <div className="space-y-4 font-mono text-xs">
                  {/* Target Input */}
                  <div className="space-y-1.5">
                    <label className="block font-bold text-[#1D3557]">Target IP Address / Hostname</label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={udpTarget}
                        onChange={(e) => {
                          setUdpTarget(e.target.value);
                          setUdpValidation(null);
                        }}
                        placeholder="e.g. 127.0.0.1 or localhost"
                        className="flex-1 px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]"
                      />
                      <button
                        type="button"
                        onClick={handleValidateUdp}
                        disabled={isUdpValidating}
                        className="btn-secondary px-4 py-2 font-bold text-xs"
                      >
                        {isUdpValidating ? "Checking..." : "Validate"}
                      </button>
                    </div>

                    {udpValidation && (
                      <div
                        className={`p-2.5 rounded-lg border-2 mt-2 text-[11px] ${
                          udpValidation.valid
                            ? "bg-[#dcfce7] border-[#166534] text-[#166534]"
                            : "bg-[#fee2e2] border-[#b91c1c] text-[#b91c1c]"
                        }`}
                      >
                        {udpValidation.valid ? (
                          <div className="flex items-center gap-1.5">
                            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            <span>
                              Target <strong>{udpValidation.target_ip}</strong> authorized. {udpValidation.resolved_ports_count} UDP ports staged for probe.
                            </span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5">
                            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                            <span>{udpValidation.error || "Invalid scan configuration."}</span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* UDP Port Scope Selection */}
                  <div className="space-y-2">
                    <label className="block font-bold text-[#1D3557]">UDP Port Scope Selection</label>
                    <div className="grid grid-cols-3 gap-2">
                      {[
                        { id: "common", label: "Common UDP (13)" },
                        { id: "range", label: "Port Range" },
                        { id: "list", label: "Custom List" },
                      ].map((mode) => (
                        <button
                          key={mode.id}
                          type="button"
                          onClick={() => {
                            setUdpMode(mode.id as "common" | "range" | "list");
                            setUdpValidation(null);
                          }}
                          className={`py-2 px-2.5 rounded-lg border-2 text-[11px] font-bold text-center transition-all ${
                            udpMode === mode.id
                              ? "bg-[#457B9D] text-white border-[#1D3557] shadow-[2px_2px_0px_#1D3557]"
                              : "bg-white text-[#1D3557] border-[#1D3557] hover:bg-[#F1FAEE]"
                          }`}
                        >
                          {mode.label}
                        </button>
                      ))}
                    </div>

                    {udpMode === "common" && (
                      <p className="text-[10px] text-[#457B9D] font-sans">
                        Preset: 53 (DNS), 67/68 (DHCP), 69 (TFTP), 123 (NTP), 137/138 (NetBIOS), 161/162 (SNMP), 500 (IKE), 514 (Syslog), 520 (RIP), 1900 (SSDP).
                      </p>
                    )}

                    {udpMode === "range" && (
                      <div className="pt-1">
                        <input
                          type="text"
                          value={udpRange}
                          onChange={(e) => setUdpRange(e.target.value)}
                          placeholder="e.g. 50-150"
                          className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
                        />
                      </div>
                    )}

                    {udpMode === "list" && (
                      <div className="pt-1">
                        <input
                          type="text"
                          value={udpList}
                          onChange={(e) => setUdpList(e.target.value)}
                          placeholder="e.g. 53, 123, 161, 1900"
                          className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
                        />
                      </div>
                    )}
                  </div>

                  {/* Sliders: UDP Timeout & Concurrency */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
                    <div className="space-y-1">
                      <label className="flex justify-between text-[#1D3557] font-bold">
                        <span>UDP Probe Timeout:</span>
                        <span className="text-[#457B9D]">{udpTimeout}s</span>
                      </label>
                      <input
                        type="range"
                        min="0.5"
                        max="3.0"
                        step="0.1"
                        value={udpTimeout}
                        onChange={(e) => setUdpTimeout(e.target.value)}
                        className="w-full accent-[#457B9D]"
                      />
                      <span className="text-[10px] text-[#457B9D] block font-sans">
                        Range: 0.5s - 3.0s (default 1.0s)
                      </span>
                    </div>

                    <div className="space-y-1">
                      <label className="flex justify-between text-[#1D3557] font-bold">
                        <span>Concurrency:</span>
                        <span className="text-[#457B9D]">{udpConcurrency} workers</span>
                      </label>
                      <input
                        type="range"
                        min="5"
                        max="50"
                        step="5"
                        value={udpConcurrency}
                        onChange={(e) => setUdpConcurrency(e.target.value)}
                        className="w-full accent-[#457B9D]"
                      />
                      <span className="text-[10px] text-[#457B9D] block font-sans">
                        Capped at 50 to prevent ICMP rate-limiting
                      </span>
                    </div>
                  </div>

                  {/* Start Button */}
                  <div className="pt-3 border-t-2 border-[#1D3557]/20 flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-[11px] text-[#457B9D] font-sans">
                      <Shield className="w-3.5 h-3.5 text-[#10b981]" />
                      <span>Zero raw socket privileges required.</span>
                    </div>

                    <button
                      type="button"
                      onClick={handleStartUdpScan}
                      disabled={isUdpScanning}
                      className="btn-primary flex items-center gap-2 px-6 py-2.5 text-xs font-mono font-bold"
                    >
                      {isUdpScanning ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" />
                          <span>Scanning UDP Ports...</span>
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4" />
                          <span>Start UDP Scan</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </BentoCard>

              {/* Methodology Card (4 cols) */}
              <BentoCard
                title="UDP SCANNING ARCHITECTURE"
                subtitle="Engine A UDP probe methodology"
                colSpan="col-span-12"
                className="lg:col-span-4"
                variant="aqua"
              >
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                    <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                      <span>PROTOCOL PROBE</span>
                      <span className="text-[#457B9D]">SOCKET DATAGRAM</span>
                    </div>
                    <p className="text-[10px] text-[#457B9D] font-sans mt-1">
                      Employs connected UDP sockets and safe minimal payloads (DNS headers, NTP requests, SNMP get, SSDP M-SEARCH).
                    </p>
                  </div>

                  <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                    <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                      <span>STATE CLASSIFICATION</span>
                      <span className="text-[#10b981]">RFC 792 / 1122</span>
                    </div>
                    <div className="text-[10px] text-[#457B9D] font-sans mt-1 space-y-0.5">
                      <p>• <strong>OPEN:</strong> Direct application UDP response received.</p>
                      <p>• <strong>CLOSED:</strong> ICMP Port Unreachable (WSAECONNRESET 10054).</p>
                      <p>• <strong>OPEN|FILTERED:</strong> No response received within timeout.</p>
                      <p>• <strong>UNKNOWN:</strong> Network unreachable or error.</p>
                    </div>
                  </div>

                  <div className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
                    <div className="flex justify-between items-center text-[11px] font-bold text-[#1D3557]">
                      <span>RATE-LIMITING AWARE</span>
                      <span className="text-[#f59e0b]">GUARDRAIL</span>
                    </div>
                    <p className="text-[10px] text-[#457B9D] font-sans mt-1">
                      OS ICMP destination unreachable responses are strictly rate-limited; conservative concurrency avoids packet loss.
                    </p>
                  </div>
                </div>
              </BentoCard>
            </div>

            {/* UDP Results Table */}
            {udpResponse && (
              <div className="space-y-5 animate-in fade-in duration-200">
                <BentoGrid cols={4}>
                  <MetricCard
                    label="Target & Scan ID"
                    value={udpResponse.target}
                    subtext={`ID: ${udpResponse.scan_id.slice(0, 18)}...`}
                    icon={Radar}
                    variant="white"
                  />
                  <MetricCard
                    label="Open UDP Ports"
                    value={udpResponse.open_ports}
                    unit="Sockets"
                    subtext="Application response verified"
                    icon={CheckCircle2}
                    variant={udpResponse.open_ports > 0 ? "aqua" : "white"}
                  />
                  <MetricCard
                    label="Closed Ports"
                    value={udpResponse.closed_ports}
                    unit="Sockets"
                    subtext="ICMP Port Unreachable"
                    icon={Layers}
                    variant="white"
                  />
                  <MetricCard
                    label="Open | Filtered"
                    value={udpResponse.open_or_filtered_ports}
                    unit="Ports"
                    subtext="No ICMP response (silent)"
                    icon={Clock}
                    variant="white"
                  />
                </BentoGrid>

                <BentoCard
                  title="UDP PORT FINDINGS"
                  subtitle={`Displaying ${sortedUdpResults.length} of ${udpResponse.results.length} probed UDP ports`}
                  action={
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(udpResponse.scan_id);
                          setUdpCopiedId(true);
                          setTimeout(() => setUdpCopiedId(false), 2000);
                        }}
                        className="btn-secondary flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono font-bold"
                      >
                        {udpCopiedId ? <Check className="w-3.5 h-3.5 text-[#10b981]" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{udpCopiedId ? "Copied" : "Copy ID"}</span>
                      </button>
                      <button
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(udpResponse, null, 2)], { type: "application/json" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `udp-${udpResponse.scan_id}.json`;
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
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pb-3 border-b-2 border-[#1D3557]/10">
                    <div className="relative w-full sm:w-64">
                      <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#457B9D]" />
                      <input
                        type="text"
                        value={udpSearch}
                        onChange={(e) => setUdpSearch(e.target.value)}
                        placeholder="Filter port or service..."
                        className="w-full pl-8 pr-3 py-1.5 rounded-lg border-2 border-[#1D3557] font-mono text-xs text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
                      />
                    </div>

                    <div className="flex flex-wrap items-center gap-1 font-mono text-xs self-start sm:self-auto">
                      {["ALL", "OPEN", "CLOSED", "OPEN|FILTERED", "UNKNOWN"].map((st) => (
                        <button
                          key={st}
                          onClick={() => setUdpFilterState(st)}
                          className={`px-2.5 py-1 rounded-md border-2 border-[#1D3557] text-[10px] font-bold transition-all ${
                            udpFilterState === st
                              ? "bg-[#457B9D] text-white shadow-[1px_1px_0px_#1D3557]"
                              : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
                          }`}
                        >
                          {st}
                        </button>
                      ))}
                    </div>
                  </div>

                  {sortedUdpResults.length === 0 ? (
                    <EmptyState
                      title="No Ports Match Filter"
                      description="Adjust search term or select another state category."
                    />
                  ) : (
                    <div className="overflow-x-auto mt-2">
                      <table className="w-full text-left font-mono text-xs border-collapse">
                        <thead>
                          <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[#1D3557] font-bold text-[11px] uppercase tracking-wider">
                            <th
                              onClick={() => {
                                setUdpSortBy("port");
                                setUdpSortOrder(udpSortOrder === "asc" ? "desc" : "asc");
                              }}
                              className="py-2.5 px-3 cursor-pointer select-none hover:bg-[#A8DADC]/40"
                            >
                              Port {udpSortBy === "port" && (udpSortOrder === "asc" ? "▲" : "▼")}
                            </th>
                            <th className="py-2.5 px-3">Proto</th>
                            <th
                              onClick={() => {
                                setUdpSortBy("state");
                                setUdpSortOrder(udpSortOrder === "asc" ? "desc" : "asc");
                              }}
                              className="py-2.5 px-3 cursor-pointer select-none hover:bg-[#A8DADC]/40"
                            >
                              State {udpSortBy === "state" && (udpSortOrder === "asc" ? "▲" : "▼")}
                            </th>
                            <th className="py-2.5 px-3">Inferred Service</th>
                            <th className="py-2.5 px-3">Confidence</th>
                            <th
                              onClick={() => {
                                setUdpSortBy("latency");
                                setUdpSortOrder(udpSortOrder === "asc" ? "desc" : "asc");
                              }}
                              className="py-2.5 px-3 text-right cursor-pointer select-none hover:bg-[#A8DADC]/40"
                            >
                              Latency {udpSortBy === "latency" && (udpSortOrder === "asc" ? "▲" : "▼")}
                            </th>
                          </tr>
                        </thead>
                        <tbody className="divide-y border-b border-[#1D3557]/20 text-[#1D3557]">
                          {sortedUdpResults.map((item) => (
                            <tr
                              key={`${item.port}-${item.protocol}`}
                              className={`hover:bg-[#F1FAEE]/70 transition-colors ${
                                item.state === "OPEN" ? "bg-[#dcfce7]/30" : ""
                              }`}
                            >
                              <td className="py-2 px-3 font-extrabold text-[#1D3557]">{item.port}</td>
                              <td className="py-2 px-3 text-[#457B9D] font-bold">{item.protocol}</td>
                              <td className="py-2 px-3">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold border shadow-[1px_1px_0px_#1D3557] ${
                                    item.state === "OPEN"
                                      ? "bg-[#dcfce7] text-[#166534] border-[#166534]"
                                      : item.state === "CLOSED"
                                      ? "bg-[#f1f5f9] text-[#475569] border-[#475569]"
                                      : item.state === "OPEN|FILTERED"
                                      ? "bg-[#e0f2fe] text-[#0369a1] border-[#0369a1]"
                                      : "bg-[#fef3c7] text-[#92400e] border-[#92400e]"
                                  }`}
                                >
                                  {item.state}
                                </span>
                              </td>
                              <td className="py-2 px-3 font-bold text-[#1D3557]">{item.service}</td>
                              <td className="py-2 px-3 text-[10px] text-[#457B9D] font-medium">{item.service_confidence}</td>
                              <td className="py-2 px-3 text-right text-[#457B9D] font-bold">{item.response_time_ms} ms</td>
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
        )}
      </div>
    </DashboardLayout>
  );
}
