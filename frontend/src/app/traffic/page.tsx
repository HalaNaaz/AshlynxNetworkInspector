"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Activity,
  Play,
  Square,
  Shield,
  Layers,
  Clock,
  Search,
  Download,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Wifi,
  Cpu,
  HelpCircle,
  X,
  BarChart3,
  ListFilter,
  ArrowUpDown,
  Gauge,
  Network,
} from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoCard } from "@/components/BentoCard";
import { BentoGrid } from "@/components/BentoGrid";
import { MetricCard } from "@/components/MetricCard";
import { StatusIndicator } from "@/components/StatusIndicator";
import { PacketTable } from "@/components/PacketTable";
import { EmptyState } from "@/components/EmptyState";
import { apiClient, analyticsApi } from "@/lib/api";
import {
  CaptureEnvironmentData,
  CaptureInterfaceItem,
  CaptureSessionResponse,
  CaptureStatistics,
  PacketMetadataItem,
  AnalyticsOverviewResponse,
  ProtocolAnalyticsResponse,
  BandwidthAnalyticsResponse,
  TopTalkersResponse,
  ConnectionsAnalyticsResponse,
  DnsAnalyticsResponse,
  TrafficTimelineResponse,
} from "@/lib/types";
import { formatBps, formatBytes } from "@/lib/formatters";
import { BandwidthChartCard } from "@/components/analytics/BandwidthChartCard";
import { ProtocolDistributionCard } from "@/components/analytics/ProtocolDistributionCard";
import { TopTalkersCard } from "@/components/analytics/TopTalkersCard";
import { ConnectionFlowsCard } from "@/components/analytics/ConnectionFlowsCard";
import { DnsAnalyticsCard } from "@/components/analytics/DnsAnalyticsCard";
import { TrafficTimelineCard } from "@/components/analytics/TrafficTimelineCard";

export default function TrafficPage() {
  // Capability & interfaces
  const [environment, setEnvironment] = useState<CaptureEnvironmentData | null>(null);
  const [interfaces, setInterfaces] = useState<CaptureInterfaceItem[]>([]);
  const [selectedInterfaceId, setSelectedInterfaceId] = useState<string>("");

  // Filter & configuration
  const [filterPreset, setFilterPreset] = useState<string>("all");
  const [customBpf, setCustomBpf] = useState<string>("");
  const [bufferLimit, setBufferLimit] = useState<number>(1000);

  // Active session & statistics
  const [activeSession, setActiveSession] = useState<CaptureSessionResponse | null>(null);
  const [statistics, setStatistics] = useState<CaptureStatistics | null>(null);
  const [packets, setPackets] = useState<PacketMetadataItem[]>([]);
  const [totalMatchingPackets, setTotalMatchingPackets] = useState<number>(0);
  const [selectedPacket, setSelectedPacket] = useState<PacketMetadataItem | null>(null);

  // Phase 5: Real-time Analytics States
  const [overview, setOverview] = useState<AnalyticsOverviewResponse | null>(null);
  const [protocols, setProtocols] = useState<ProtocolAnalyticsResponse | null>(null);
  const [bandwidth, setBandwidth] = useState<BandwidthAnalyticsResponse | null>(null);
  const [topTalkers, setTopTalkers] = useState<TopTalkersResponse | null>(null);
  const [connections, setConnections] = useState<ConnectionsAnalyticsResponse | null>(null);
  const [dns, setDns] = useState<DnsAnalyticsResponse | null>(null);
  const [timeline, setTimeline] = useState<TrafficTimelineResponse | null>(null);
  const [bandwidthWindow, setBandwidthWindow] = useState<number>(1);

  // Active View Tab
  const [activeTab, setActiveTab] = useState<"analytics" | "packets">("analytics");

  // UI state
  const [isStarting, setIsStarting] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [tableSearch, setTableSearch] = useState("");
  const [tableProtocol, setTableProtocol] = useState("ALL");

  // Polling ref
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);

  // Initial load
  const loadInitialData = useCallback(async () => {
    try {
      const [env, ifaces, sessions] = await Promise.all([
        apiClient.getCaptureEnvironmentStatus(),
        apiClient.getCaptureInterfaces(),
        apiClient.getCaptureSessions(),
      ]);
      setEnvironment(env);
      setInterfaces(ifaces);

      if (ifaces.length > 0 && !selectedInterfaceId) {
        // Default to first physical or up interface
        const firstPhysical = ifaces.find((i) => i.interface_type === "physical" && i.is_up);
        setSelectedInterfaceId(firstPhysical ? firstPhysical.id : ifaces[0].id);
      }

      // Check if there is an active session
      const capturing = sessions.find((s) => s.status === "CAPTURING");
      const targetSession = capturing || (sessions.length > 0 ? sessions[sessions.length - 1] : null);

      if (targetSession) {
        setActiveSession(targetSession);
        setStatistics(targetSession.statistics);
        // Load existing analytics for target session
        try {
          const [ov, pr, bw, tt, cn, dn, tl] = await Promise.all([
            analyticsApi.getOverview(targetSession.session_id),
            analyticsApi.getProtocols(targetSession.session_id),
            analyticsApi.getBandwidth(targetSession.session_id, bandwidthWindow),
            analyticsApi.getTopTalkers(targetSession.session_id),
            analyticsApi.getConnections(targetSession.session_id, 100),
            analyticsApi.getDns(targetSession.session_id),
            analyticsApi.getTimeline(targetSession.session_id),
          ]);
          if (ov && dn) {
            ov.dns_queries_count = dn.total_queries;
          }
          setOverview(ov);
          setProtocols(pr);
          setBandwidth(bw);
          setTopTalkers(tt);
          setConnections(cn);
          setDns(dn);
          setTimeline(tl);
        } catch {
          // Ignore
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load capture environment.";
      setErrorMessage(msg);
    }
  }, [selectedInterfaceId, bandwidthWindow]);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  // Polling live packets and analytics when capturing
  const pollSessionData = useCallback(async () => {
    if (!activeSession || activeSession.status !== "CAPTURING") return;

    try {
      const [sessData, stats, pktData, ov, pr, bw, tt, cn, dn, tl] = await Promise.all([
        apiClient.getCaptureSession(activeSession.session_id).catch(() => null),
        apiClient.getCaptureSessionStatistics(activeSession.session_id).catch(() => null),
        apiClient.getCaptureSessionPackets(activeSession.session_id, {
          limit: 100,
          protocol: tableProtocol !== "ALL" ? tableProtocol : undefined,
          search: tableSearch || undefined,
        }).catch(() => null),
        analyticsApi.getOverview(activeSession.session_id).catch(() => null),
        analyticsApi.getProtocols(activeSession.session_id).catch(() => null),
        analyticsApi.getBandwidth(activeSession.session_id, bandwidthWindow).catch(() => null),
        analyticsApi.getTopTalkers(activeSession.session_id).catch(() => null),
        analyticsApi.getConnections(activeSession.session_id, 100).catch(() => null),
        analyticsApi.getDns(activeSession.session_id).catch(() => null),
        analyticsApi.getTimeline(activeSession.session_id).catch(() => null),
      ]);

      // Synchronize session lifecycle state if stopped/errored in background
      if (sessData && sessData.status !== "CAPTURING") {
        setActiveSession(sessData);
        if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      }

      if (stats) setStatistics(stats);
      if (pktData) {
        setPackets(pktData.packets);
        setTotalMatchingPackets(pktData.total_matching);
      }

      if (ov) {
        if (dn) {
          ov.dns_queries_count = dn.total_queries;
        }
        setOverview(ov);
      }
      if (pr) setProtocols(pr);
      if (bw) setBandwidth(bw);
      if (tt) setTopTalkers(tt);
      if (cn) setConnections(cn);
      if (dn) setDns(dn);
      if (tl) setTimeline(tl);
    } catch {
      // Ignore background transient polling errors
    }
  }, [activeSession, tableProtocol, tableSearch, bandwidthWindow]);

  useEffect(() => {
    if (activeSession && activeSession.status === "CAPTURING") {
      pollSessionData();
      pollTimerRef.current = setInterval(pollSessionData, 1200);
    } else {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    }

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [activeSession, pollSessionData]);

  // Window switcher trigger
  const handleWindowChange = async (w: number) => {
    setBandwidthWindow(w);
    if (activeSession) {
      try {
        const bw = await analyticsApi.getBandwidth(activeSession.session_id, w);
        setBandwidth(bw);
      } catch {
        // Ignore
      }
    }
  };

  // Start Capture
  const handleStartCapture = async () => {
    setIsStarting(true);
    setErrorMessage(null);
    try {
      const session = await apiClient.startCaptureSession({
        interface_id: selectedInterfaceId,
        filter_preset: filterPreset,
        custom_bpf_filter: customBpf.trim() || undefined,
        buffer_limit: bufferLimit,
      });
      setActiveSession(session);
      setStatistics(session.statistics);
      setPackets([]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to start capture.";
      setErrorMessage(msg);
    } finally {
      setIsStarting(false);
    }
  };

  // Stop Capture
  const handleStopCapture = async () => {
    setIsStopping(true);
    setErrorMessage(null);
    try {
      const session = await apiClient.stopCaptureSession();
      setActiveSession(session);
      setStatistics(session.statistics);
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      // Fetch final analytics snapshot
      const [ov, pr, bw, tt, cn, dn, tl] = await Promise.all([
        analyticsApi.getOverview(session.session_id).catch(() => null),
        analyticsApi.getProtocols(session.session_id).catch(() => null),
        analyticsApi.getBandwidth(session.session_id, bandwidthWindow).catch(() => null),
        analyticsApi.getTopTalkers(session.session_id).catch(() => null),
        analyticsApi.getConnections(session.session_id, 100).catch(() => null),
        analyticsApi.getDns(session.session_id).catch(() => null),
        analyticsApi.getTimeline(session.session_id).catch(() => null),
      ]);
      if (ov) {
        if (dn) {
          ov.dns_queries_count = dn.total_queries;
        }
        setOverview(ov);
      }
      if (pr) setProtocols(pr);
      if (bw) setBandwidth(bw);
      if (tt) setTopTalkers(tt);
      if (cn) setConnections(cn);
      if (dn) setDns(dn);
      if (tl) setTimeline(tl);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to stop capture.";
      setErrorMessage(msg);
      // Synchronize session state: if backend reports no active capture, stop polling and mark status STOPPED
      if (msg.includes("No active packet capture session") || msg.includes("not running")) {
        setActiveSession((prev) => (prev ? { ...prev, status: "STOPPED" } : null));
        if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      }
    } finally {
      setIsStopping(false);
    }
  };

  // Clear display buffer
  const handleClearBuffer = async () => {
    if (!activeSession) return;
    try {
      await apiClient.clearCaptureBuffer(activeSession.session_id);
      setPackets([]);
      setTotalMatchingPackets(0);
    } catch {
      // Ignore
    }
  };

  const selectedInterfaceObj = interfaces.find((i) => i.id === selectedInterfaceId);
  const isCapturing = activeSession?.status === "CAPTURING";
  const npcapMissing = environment?.capability_status === "NPCAP_MISSING";

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-6xl mx-auto">
        {/* Page Hero Banner */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <Activity className="w-4 h-4 text-[#457B9D]" />
              <span>ENGINE B • REAL-TIME WIRE ANALYTICS & LIVE SNIFFER</span>
            </div>
            <h1 className="font-heading font-black text-3xl text-[#1D3557] tracking-tight uppercase">
              ANALYTICS & TRAFFIC INSPECTOR
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Real-time bandwidth monitoring, zero double-counting protocol partition, 5-tuple flow tracking & DNS intelligence.
            </p>
          </div>

          <StatusIndicator
            status={
              isCapturing
                ? "operational"
                : environment?.can_capture
                ? "operational"
                : "standby"
            }
            label={
              isCapturing
                ? "CAPTURING LIVE TRAFFIC"
                : environment?.can_capture
                ? "ENGINE B: READY (v0.5.0)"
                : `ENGINE B: ${environment?.capability_status || "STANDBY"}`
            }
          />
        </div>

        {/* Missing Npcap Diagnostic Card */}
        {npcapMissing && (
          <div className="p-5 rounded-xl border-2 border-[#E63946] bg-[#ffe4e6] shadow-[4px_4px_0px_#E63946] space-y-3">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-6 h-6 text-[#E63946] shrink-0 mt-0.5" />
              <div>
                <h3 className="font-heading font-extrabold text-sm text-[#E63946]">
                  Npcap Packet Capture Driver Not Detected
                </h3>
                <p className="text-xs text-[#1D3557] font-medium mt-1 leading-relaxed">
                  Scapy is installed, but live wire capture on Windows requires the official Npcap packet capture driver. Without Npcap, Windows raw socket capture is restricted by the operating system.
                </p>
              </div>
            </div>

            <div className="p-3.5 rounded-lg border-2 border-[#1D3557] bg-white font-mono text-xs space-y-2">
              <span className="font-bold text-[#1D3557] block">
                How to Enable Live Wire Capture:
              </span>
              <ol className="list-decimal pl-5 space-y-1 text-[#457B9D] text-[11px]">
                <li>
                  Download the official Npcap installer from{" "}
                  <a
                    href="https://npcap.com/#download"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="underline text-[#1D3557] font-bold hover:text-[#457B9D] inline-flex items-center gap-0.5"
                  >
                    npcap.com <ExternalLink className="w-3 h-3" />
                  </a>
                </li>
                <li>
                  During installation, check{" "}
                  <strong>&quot;Install Npcap in WinPcap API-compatible Mode&quot;</strong>.
                </li>
                <li>Restart the FastAPI backend server. Live packet sniffing will automatically activate!</li>
              </ol>
            </div>
          </div>
        )}

        {/* Global Error Banner */}
        {errorMessage && (
          <div className="p-4 rounded-xl border-2 border-[#E63946] bg-[#fee2e2] shadow-[3px_3px_0px_#E63946] flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-[#E63946] shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <h4 className="font-heading font-extrabold text-[#E63946]">Capture Operation Halted</h4>
              <p className="text-[#1D3557] font-medium leading-relaxed">{errorMessage}</p>
            </div>
          </div>
        )}

        {/* Capture Controls Bento Card */}
        <BentoCard
          title="CAPTURE CONFIGURATION & SNIFFER CONTROLS"
          subtitle="Configure host network adapter, BPF filter expressions, and ring buffer size"
          dotGrid
          action={
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-[#1D3557] bg-[#F1FAEE] text-[#1D3557]">
                PAYLOAD STORAGE: DISABLED (METADATA-ONLY)
              </span>
            </div>
          }
        >
          <div className="space-y-4 font-mono text-xs">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Interface Select */}
              <div className="space-y-1.5">
                <label className="block font-bold text-[#1D3557]">Network Interface</label>
                <select
                  value={selectedInterfaceId}
                  onChange={(e) => setSelectedInterfaceId(e.target.value)}
                  disabled={isCapturing}
                  className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557] disabled:opacity-60"
                >
                  {interfaces.map((iface) => (
                    <option key={iface.id} value={iface.id}>
                      {iface.name} ({iface.ipv4_addresses[0] || iface.interface_type})
                    </option>
                  ))}
                </select>

                {selectedInterfaceObj && (
                  <div className="text-[10px] text-[#457B9D] font-mono space-y-0.5 pt-1">
                    <p>Driver: {selectedInterfaceObj.description || "Generic"}</p>
                    <p>MAC: {selectedInterfaceObj.mac_address || "None"} • Type: {selectedInterfaceObj.interface_type}</p>
                  </div>
                )}
              </div>

              {/* BPF Filter Preset */}
              <div className="space-y-1.5">
                <label className="block font-bold text-[#1D3557]">BPF Filter Preset</label>
                <select
                  value={filterPreset}
                  onChange={(e) => setFilterPreset(e.target.value)}
                  disabled={isCapturing}
                  className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557] disabled:opacity-60"
                >
                  <option value="all">All Traffic (Unfiltered)</option>
                  <option value="tcp">TCP Only</option>
                  <option value="udp">UDP Only</option>
                  <option value="icmp">ICMP Only</option>
                  <option value="dns">DNS (Port 53)</option>
                  <option value="arp">ARP Frames</option>
                  <option value="ip">IPv4 Only</option>
                  <option value="ip6">IPv6 Only</option>
                </select>
                <span className="text-[10px] text-[#457B9D] block font-sans">
                  Compiled Berkeley Packet Filter
                </span>
              </div>

              {/* Custom BPF & Buffer */}
              <div className="space-y-1.5">
                <label className="block font-bold text-[#1D3557]">Custom BPF Filter (Optional)</label>
                <input
                  type="text"
                  value={customBpf}
                  onChange={(e) => setCustomBpf(e.target.value)}
                  disabled={isCapturing}
                  placeholder="e.g. host 127.0.0.1 or port 80"
                  className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557] disabled:opacity-60"
                />
                <span className="text-[10px] text-[#457B9D] block font-sans">
                  Overrides preset when specified
                </span>
              </div>
            </div>

            {/* Action Bar */}
            <div className="pt-3 border-t-2 border-[#1D3557]/20 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-bold text-[#1D3557]">Ring Buffer Limit:</span>
                <input
                  type="range"
                  min="200"
                  max="5000"
                  step="100"
                  value={bufferLimit}
                  onChange={(e) => setBufferLimit(parseInt(e.target.value, 10))}
                  disabled={isCapturing}
                  className="accent-[#457B9D] w-32"
                />
                <span className="text-[11px] text-[#457B9D] font-bold">{bufferLimit} pkts</span>
              </div>

              <div className="flex items-center gap-2">
                {isCapturing ? (
                  <button
                    onClick={handleStopCapture}
                    disabled={isStopping}
                    className="btn-danger flex items-center gap-1.5 px-5 py-2 text-xs font-mono font-bold shadow-[2px_2px_0px_#1D3557]"
                  >
                    <Square className="w-3.5 h-3.5" />
                    <span>{isStopping ? "Stopping Sniffer..." : "Stop Capture"}</span>
                  </button>
                ) : (
                  <button
                    onClick={handleStartCapture}
                    disabled={isStarting || npcapMissing}
                    className="btn-primary flex items-center gap-1.5 px-6 py-2 text-xs font-mono font-bold shadow-[2px_2px_0px_#1D3557] disabled:opacity-50"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>{isStarting ? "Initializing Driver..." : "Start Capture"}</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </BentoCard>

        {/* View Switcher Tabs (Analytics vs Live Packets) */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 p-1.5 rounded-xl border-2 border-[#1D3557] bg-white shadow-[3px_3px_0px_#1D3557] font-mono text-xs">
          <button
            onClick={() => setActiveTab("analytics")}
            className={`flex-1 py-2 px-4 rounded-lg font-black uppercase flex items-center justify-center gap-2 transition-all ${
              activeTab === "analytics"
                ? "bg-[#1D3557] text-white shadow-[2px_2px_0px_#1D3557]"
                : "text-[#1D3557] hover:bg-[#F1FAEE]"
            }`}
          >
            <BarChart3 className="w-4 h-4" />
            <span>Real-Time Traffic Analytics Dashboard</span>
          </button>
          <button
            onClick={() => setActiveTab("packets")}
            className={`flex-1 py-2 px-4 rounded-lg font-black uppercase flex items-center justify-center gap-2 transition-all ${
              activeTab === "packets"
                ? "bg-[#1D3557] text-white shadow-[2px_2px_0px_#1D3557]"
                : "text-[#1D3557] hover:bg-[#F1FAEE]"
            }`}
          >
            <ListFilter className="w-4 h-4" />
            <span>Live Packet Stream Table ({packets.length})</span>
          </button>
        </div>

        {/* ===================== TAB 1: ANALYTICS DASHBOARD ===================== */}
        {activeTab === "analytics" && (
          <div className="space-y-6">
            {/* Executive KPI Overview Grid */}
            <BentoGrid cols={6}>
              <MetricCard
                label="Total Packets"
                value={overview?.total_packets ?? statistics?.total_captured ?? 0}
                unit="pkts"
                subtext="Frames analyzed"
                icon={Activity}
                variant="white"
              />
              <MetricCard
                label="Total Volume"
                value={formatBytes(overview?.total_bytes ?? statistics?.bytes_captured ?? 0)}
                subtext="Cumulative wire data"
                icon={Layers}
                variant="white"
              />
              <MetricCard
                label="Throughput"
                value={formatBps(overview?.current_bps ?? 0)}
                subtext={`Peak ${formatBps(overview?.peak_bps ?? 0)}`}
                icon={Gauge}
                variant="aqua"
              />
              <MetricCard
                label="Packet Rate"
                value={(overview?.current_pps ?? 0).toFixed(0)}
                unit="pps"
                subtext={`Peak ${(overview?.peak_pps ?? 0).toFixed(0)} pps`}
                icon={Clock}
                variant="white"
              />
              <MetricCard
                label="Active Flows"
                value={overview?.active_flows_count ?? 0}
                unit="flows"
                subtext="5-tuple connections"
                icon={Network}
                variant="white"
              />
              <MetricCard
                label="DNS Queries"
                value={dns?.total_queries ?? overview?.dns_queries_count ?? 0}
                unit="reqs"
                subtext="Parsed requests"
                icon={Shield}
                variant="white"
              />
            </BentoGrid>

            {/* Row 1: Bandwidth Throughput (Area Chart) + Protocol Distribution (Donut Chart) */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
              <div className="xl:col-span-2 min-w-0">
                <BandwidthChartCard
                  bandwidth={bandwidth}
                  selectedWindow={bandwidthWindow}
                  onWindowChange={handleWindowChange}
                  isCapturing={isCapturing}
                />
              </div>
              <div className="xl:col-span-1 min-w-0">
                <ProtocolDistributionCard protocols={protocols} />
              </div>
            </div>

            {/* Row 2: Top Talkers + Active Connection Flows */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
              <div className="xl:col-span-1 min-w-0">
                <TopTalkersCard topTalkers={topTalkers} />
              </div>
              <div className="xl:col-span-2 min-w-0">
                <ConnectionFlowsCard connections={connections} />
              </div>
            </div>

            {/* Row 3: DNS Intelligence + Second-by-Second Traffic Timeline */}
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
              <div className="min-w-0">
                <DnsAnalyticsCard dns={dns} />
              </div>
              <div className="min-w-0">
                <TrafficTimelineCard timeline={timeline} />
              </div>
            </div>
          </div>
        )}

        {/* ===================== TAB 2: LIVE PACKET STREAM ===================== */}
        {activeTab === "packets" && (
          <div className="space-y-6">
            {/* Live Packet Statistics Grid */}
            <BentoGrid cols={6}>
              <MetricCard
                label="Total Frames"
                value={statistics?.total_captured ?? 0}
                unit="pkts"
                subtext="Frames received"
                icon={Activity}
                variant="white"
              />
              <MetricCard
                label="TCP Segments"
                value={statistics?.tcp_count ?? 0}
                unit="pkts"
                subtext="Handshakes & stream"
                icon={Layers}
                variant="aqua"
              />
              <MetricCard
                label="UDP Datagrams"
                value={statistics?.udp_count ?? 0}
                unit="pkts"
                subtext="DNS / media / NTP"
                icon={Layers}
                variant="white"
              />
              <MetricCard
                label="ICMP Messages"
                value={statistics?.icmp_count ?? 0}
                unit="pkts"
                subtext="Pings & unreachables"
                icon={Shield}
                variant="white"
              />
              <MetricCard
                label="ARP Packets"
                value={statistics?.arp_count ?? 0}
                unit="pkts"
                subtext="Hardware resolution"
                icon={Wifi}
                variant="white"
              />
              <MetricCard
                label="Buffer Retained"
                value={statistics?.retained_in_buffer ?? 0}
                unit="pkts"
                subtext={`Capacity ${bufferLimit}`}
                icon={Clock}
                variant="white"
              />
            </BentoGrid>

            {/* Live Frame Log Table Bento Card */}
            <BentoCard
              title="LIVE PACKET STREAM"
              subtitle={`Displaying ${packets.length} frames currently retained in display memory (zero payloads)`}
              action={
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleClearBuffer}
                    disabled={packets.length === 0}
                    className="btn-secondary flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-mono font-bold shadow-[2px_2px_0px_#1D3557]"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Clear Buffer</span>
                  </button>
                </div>
              }
            >
              {/* Table Filters Sub-bar */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pb-3 border-b-2 border-[#1D3557]/10">
                <div className="relative w-full sm:w-64">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#457B9D]" />
                  <input
                    type="text"
                    value={tableSearch}
                    onChange={(e) => setTableSearch(e.target.value)}
                    placeholder="Search IP, port, protocol..."
                    className="w-full pl-8 pr-3 py-1.5 rounded-lg border-2 border-[#1D3557] font-mono text-xs text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
                  />
                </div>

                <div className="flex flex-wrap items-center gap-1 font-mono text-xs self-start sm:self-auto">
                  {["ALL", "TCP", "UDP", "ICMP", "ARP", "DNS"].map((proto) => (
                    <button
                      key={proto}
                      onClick={() => setTableProtocol(proto)}
                      className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-bold transition-all ${
                        tableProtocol === proto
                          ? "bg-[#457B9D] text-white shadow-[1px_1px_0px_#1D3557]"
                          : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
                      }`}
                    >
                      {proto}
                    </button>
                  ))}
                </div>
              </div>

              {/* Packet Table */}
              <PacketTable
                packets={packets}
                selectedPacketId={selectedPacket?.packet_id}
                onSelectPacket={(pkt) => setSelectedPacket(pkt)}
              />
            </BentoCard>

            {/* Selected Packet Metadata Drawer */}
            {selectedPacket && (
              <div className="p-5 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] space-y-3 font-mono text-xs animate-in fade-in duration-150">
                <div className="flex items-center justify-between border-b-2 border-[#1D3557]/15 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="font-heading font-extrabold text-[#1D3557] text-sm">
                      PACKET #{selectedPacket.packet_id} METADATA INSPECTOR
                    </span>
                    <span className="px-1.5 py-0.5 rounded border border-[#1D3557] bg-[#A8DADC] text-[#1D3557] text-[10px] font-bold">
                      {selectedPacket.protocol}
                    </span>
                  </div>
                  <button
                    onClick={() => setSelectedPacket(null)}
                    className="p-1 rounded hover:bg-[#F1FAEE] text-[#1D3557]"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
                  <div className="p-2.5 rounded-lg border border-[#1D3557]/30 bg-[#F1FAEE]">
                    <span className="block text-[10px] text-[#457B9D] font-bold">SOURCE</span>
                    <span className="font-bold text-[#1D3557]">
                      {selectedPacket.src_ip}
                      {selectedPacket.src_port ? `:${selectedPacket.src_port}` : ""}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg border border-[#1D3557]/30 bg-[#F1FAEE]">
                    <span className="block text-[10px] text-[#457B9D] font-bold">DESTINATION</span>
                    <span className="font-bold text-[#1D3557]">
                      {selectedPacket.dst_ip}
                      {selectedPacket.dst_port ? `:${selectedPacket.dst_port}` : ""}
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg border border-[#1D3557]/30 bg-[#F1FAEE]">
                    <span className="block text-[10px] text-[#457B9D] font-bold">FRAME LENGTH</span>
                    <span className="font-bold text-[#1D3557]">{selectedPacket.length} Bytes</span>
                  </div>
                  <div className="p-2.5 rounded-lg border border-[#1D3557]/30 bg-[#F1FAEE]">
                    <span className="block text-[10px] text-[#457B9D] font-bold">TIMESTAMP (UTC)</span>
                    <span className="font-bold text-[#1D3557]">{selectedPacket.timestamp}</span>
                  </div>
                </div>

                {selectedPacket.tcp_flags && (
                  <div className="p-2.5 rounded-lg border border-[#1D3557]/30 bg-white">
                    <span className="block text-[10px] text-[#457B9D] font-bold">TCP FLAGS</span>
                    <span className="font-bold text-[#1D3557]">{selectedPacket.tcp_flags}</span>
                  </div>
                )}

                {selectedPacket.dns_summary && (
                  <div className="p-2.5 rounded-lg border border-[#1D3557]/30 bg-white">
                    <span className="block text-[10px] text-[#457B9D] font-bold">DNS METADATA</span>
                    <span className="font-bold text-[#1D3557]">{selectedPacket.dns_summary}</span>
                  </div>
                )}

                <div className="flex items-center justify-between text-[10px] text-[#457B9D] pt-2 border-t border-[#1D3557]/10">
                  <span>Session: {selectedPacket.session_id} • Interface: {selectedPacket.interface}</span>
                  <span className="font-bold text-[#10b981]">Zero Payload Stored (Safe Mode)</span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
