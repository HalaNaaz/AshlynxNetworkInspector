"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  ShieldAlert,
  Shield,
  AlertTriangle,
  Filter,
  CheckCircle2,
  Search,
  Sliders,
  X,
  MessageSquare,
  Clock,
  ArrowRight,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  Layers,
  Activity,
  Check,
  HelpCircle,
} from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoCard } from "@/components/BentoCard";
import { BentoGrid } from "@/components/BentoGrid";
import { MetricCard } from "@/components/MetricCard";
import { StatusIndicator } from "@/components/StatusIndicator";
import { securityApi } from "@/lib/api";
import {
  RuleConfigItem,
  SecurityEventItem,
  SecurityOverviewResponse,
  SecurityTimelineResponse,
} from "@/lib/types";

export default function EventsPage() {
  const [overview, setOverview] = useState<SecurityOverviewResponse | null>(null);
  const [events, setEvents] = useState<SecurityEventItem[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [rules, setRules] = useState<RuleConfigItem[]>([]);
  const [timeline, setTimeline] = useState<SecurityTimelineResponse | null>(null);

  // Filters
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [filterCategory, setFilterCategory] = useState<string>("ALL");
  const [filterStatus, setFilterStatus] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Selected event for investigation drawer
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventItem | null>(null);
  const [newNoteText, setNewNoteText] = useState<string>("");
  const [isSubmittingNote, setIsSubmittingNote] = useState<boolean>(false);

  // Rules Modal
  const [showRulesModal, setShowRulesModal] = useState<boolean>(false);
  const [editingRule, setEditingRule] = useState<RuleConfigItem | null>(null);
  const [ruleThreshold, setRuleThreshold] = useState<string>("");

  // Loading state
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const pollTimerRef = useRef<NodeJS.Timeout | null>(null);

  const loadData = useCallback(async () => {
    try {
      const [ov, evList, rList, tl] = await Promise.all([
        securityApi.getOverview().catch(() => null),
        securityApi.listEvents({
          severity: filterSeverity !== "ALL" ? filterSeverity : undefined,
          category: filterCategory !== "ALL" ? filterCategory : undefined,
          status: filterStatus !== "ALL" ? filterStatus : undefined,
          limit: 100,
        }).catch(() => null),
        securityApi.listRules().catch(() => []),
        securityApi.getTimeline().catch(() => null),
      ]);

      if (ov) setOverview(ov);
      if (evList) {
        setEvents(evList.events);
        setTotalEvents(evList.total);
      }
      if (rList) setRules(rList);
      if (tl) setTimeline(tl);
    } catch {
      // Ignore background transient errors
    } finally {
      setIsLoading(false);
    }
  }, [filterSeverity, filterCategory, filterStatus]);

  useEffect(() => {
    loadData();
    pollTimerRef.current = setInterval(loadData, 2000);
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [loadData]);

  // Lifecycle status transition
  const handleStatusChange = async (eventId: string, newStatus: string) => {
    try {
      const updated = await securityApi.updateEventStatus(eventId, newStatus, "SOC Analyst");
      setSelectedEvent(updated);
      setEvents((prev) => prev.map((e) => (e.event_id === eventId ? updated : e)));
      loadData();
    } catch {
      // Ignore
    }
  };

  // Add analyst note
  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEvent || !newNoteText.trim()) return;

    setIsSubmittingNote(true);
    try {
      const updated = await securityApi.addEventNote(selectedEvent.event_id, newNoteText.trim(), "SOC Analyst");
      setSelectedEvent(updated);
      setNewNoteText("");
      setEvents((prev) => prev.map((item) => (item.event_id === updated.event_id ? updated : item)));
    } catch {
      // Ignore
    } finally {
      setIsSubmittingNote(false);
    }
  };

  // Update rule threshold
  const handleSaveRule = async () => {
    if (!editingRule) return;
    const val = parseFloat(ruleThreshold);
    if (isNaN(val) || val <= 0) return;

    try {
      await securityApi.updateRule(editingRule.rule_id, {
        threshold: val,
        enabled: editingRule.enabled,
      });
      setShowRulesModal(false);
      setEditingRule(null);
      loadData();
    } catch {
      // Ignore
    }
  };

  const handleToggleRule = async (rule: RuleConfigItem) => {
    try {
      await securityApi.updateRule(rule.rule_id, { enabled: !rule.enabled });
      loadData();
    } catch {
      // Ignore
    }
  };

  // Filtered by search client-side
  const displayedEvents = events.filter((e) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.detection_name.toLowerCase().includes(q) ||
      (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
      (e.destination_ip && e.destination_ip.toLowerCase().includes(q)) ||
      e.rule_id.toLowerCase().includes(q) ||
      e.category.toLowerCase().includes(q)
    );
  });

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return "bg-[#fee2e2] text-[#E63946] border-[#E63946] font-black";
      case "HIGH":
        return "bg-[#ffedd5] text-[#ea580c] border-[#ea580c] font-black";
      case "MEDIUM":
        return "bg-[#fef9c3] text-[#ca8a04] border-[#ca8a04] font-bold";
      case "LOW":
        return "bg-[#e0f2fe] text-[#0284c7] border-[#0284c7] font-bold";
      default:
        return "bg-[#f1faee] text-[#1D3557] border-[#1D3557] font-bold";
    }
  };

  const getStatusBadgeClass = (st: string) => {
    switch (st.toUpperCase()) {
      case "RESOLVED":
        return "bg-[#dcfce7] text-[#16a34a] border-[#16a34a]";
      case "FALSE_POSITIVE":
        return "bg-[#f1f5f9] text-[#64748b] border-[#94a3b8]";
      case "INVESTIGATING":
        return "bg-[#e0e7ff] text-[#4f46e5] border-[#6366f1]";
      case "ACKNOWLEDGED":
        return "bg-[#fef3c7] text-[#d97706] border-[#f59e0b]";
      default:
        return "bg-[#fee2e2] text-[#dc2626] border-[#ef4444]";
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-6xl mx-auto">
        {/* Page Hero Banner */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <ShieldAlert className="w-4 h-4 text-[#E63946]" />
              <span>ENGINE B / C • PASSIVE SECURITY INTELLIGENCE & ANOMALY DETECTION</span>
            </div>
            <h1 className="font-heading font-black text-3xl text-[#1D3557] tracking-tight uppercase">
              SECURITY EVENTS WORKSTATION
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Empirical anomaly detection, multi-vector correlation, port sweep classification & audited investigation logs.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowRulesModal(true)}
              className="btn-secondary flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-bold shadow-[2px_2px_0px_#1D3557]"
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>Configure Rules ({rules.length})</span>
            </button>
            <StatusIndicator
              status="operational"
              label={`BASELINE: ${overview?.status.baseline_status || "READY"}`}
            />
          </div>
        </div>

        {/* Executive KPI Metrics Grid */}
        <BentoGrid cols={6}>
          <MetricCard
            label="Total Events"
            value={overview?.status.total_events_detected ?? 0}
            unit="events"
            subtext="Session detections"
            icon={ShieldAlert}
            variant="white"
          />
          <MetricCard
            label="Critical Alerts"
            value={overview?.status.critical_events ?? 0}
            unit="high risk"
            subtext="Immediate review"
            icon={AlertTriangle}
            variant="coral"
          />
          <MetricCard
            label="High Severity"
            value={overview?.status.high_events ?? 0}
            unit="events"
            subtext="Strong evidence"
            icon={Shield}
            variant="white"
          />
          <MetricCard
            label="Medium Severity"
            value={overview?.status.medium_events ?? 0}
            unit="events"
            subtext="Suspicious vectors"
            icon={Layers}
            variant="aqua"
          />
          <MetricCard
            label="Under Review"
            value={overview?.status.active_investigations ?? 0}
            unit="cases"
            subtext="Investigating"
            icon={Clock}
            variant="white"
          />
          <MetricCard
            label="Resolved / FP"
            value={overview?.status.resolved_events ?? 0}
            unit="closed"
            subtext="Audited findings"
            icon={CheckCircle2}
            variant="white"
          />
        </BentoGrid>

        {/* Top Threat Sources + Category Breakdown Dual Row */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Category Breakdown */}
          <BentoCard
            title="DETECTION CATEGORIES"
            subtitle="Distribution of security events across monitored behavioral vectors"
          >
            <div className="space-y-2 font-mono text-xs">
              {Object.keys(overview?.category_breakdown || {}).length === 0 ? (
                <div className="p-4 text-center text-[#457B9D] border border-dashed border-[#1D3557]/20 rounded-lg">
                  <p className="font-bold text-[11px]">No Category Detections</p>
                </div>
              ) : (
                Object.entries(overview?.category_breakdown || {}).map(([cat, count]) => (
                  <div
                    key={cat}
                    onClick={() => setFilterCategory(filterCategory === cat ? "ALL" : cat)}
                    className={`p-2 rounded-lg border-2 border-[#1D3557] flex items-center justify-between cursor-pointer transition-all ${
                      filterCategory === cat ? "bg-[#1D3557] text-white" : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
                    }`}
                  >
                    <span className="font-black text-[11px]">{cat}</span>
                    <span className="px-2 py-0.5 rounded-full border border-current text-[10px] font-black">
                      {count}
                    </span>
                  </div>
                ))
              )}
            </div>
          </BentoCard>

          {/* Top Threat Sources */}
          <div className="lg:col-span-2">
            <BentoCard
              title="TOP OBSERVED SUSPICIOUS SOURCES"
              subtitle="Attributed IP addresses producing anomalous activity and multi-vector detections"
            >
              <div className="space-y-2 font-mono text-xs">
                {(overview?.top_sources || []).length === 0 ? (
                  <div className="p-6 text-center text-[#457B9D] border border-dashed border-[#1D3557]/20 rounded-lg">
                    <p className="font-bold text-xs">No Threat Sources Observed</p>
                    <p className="text-[10px] mt-0.5">Anomalous endpoints will populate as suspicious patterns are detected</p>
                  </div>
                ) : (
                  (overview?.top_sources || []).map((src) => (
                    <div
                      key={src.source_ip}
                      className="p-2.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557] flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-black text-[#1D3557] text-xs">{src.source_ip}</span>
                        <span className={`px-2 py-0.2 rounded border text-[9px] uppercase ${getSeverityBadgeClass(src.highest_severity)}`}>
                          {src.highest_severity}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] text-[#457B9D] font-bold">
                          {src.event_count} events • Rules: {src.associated_rules.join(", ")}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </BentoCard>
          </div>
        </div>

        {/* Security Events Main Table Bento Card */}
        <BentoCard
          title="SECURITY DETECTION EVENTS"
          subtitle={`Displaying ${displayedEvents.length} events detected from live wire analysis (Deterministic evidence only)`}
          action={
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded border border-[#1D3557] bg-[#F1FAEE] text-[#1D3557]">
                DEFENSIVE PASSIVE MODE
              </span>
            </div>
          }
        >
          {/* Sub-bar Filter Controls */}
          <div className="flex flex-col md:flex-row items-center justify-between gap-3 pb-3 border-b-2 border-[#1D3557]/15 font-mono text-xs">
            {/* Search */}
            <div className="relative w-full md:w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[#457B9D]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search rule, IP, category..."
                className="w-full pl-8 pr-3 py-1.5 rounded-lg border-2 border-[#1D3557] font-mono text-xs text-[#1D3557] focus:outline-none focus:bg-[#F1FAEE]"
              />
            </div>

            {/* Severity Filter Buttons */}
            <div className="flex flex-wrap items-center gap-1">
              {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-2 py-0.5 rounded-md border-2 border-[#1D3557] text-[10px] font-bold transition-all ${
                    filterSeverity === sev
                      ? "bg-[#1D3557] text-white shadow-[1px_1px_0px_#1D3557]"
                      : "bg-white text-[#1D3557] hover:bg-[#F1FAEE]"
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Status Filter Buttons */}
            <div className="flex flex-wrap items-center gap-1">
              {["ALL", "NEW", "INVESTIGATING", "RESOLVED"].map((st) => (
                <button
                  key={st}
                  onClick={() => setFilterStatus(st)}
                  className={`px-2 py-0.5 rounded-md border border-[#1D3557] text-[10px] font-bold transition-all ${
                    filterStatus === st
                      ? "bg-[#457B9D] text-white"
                      : "bg-[#F1FAEE] text-[#1D3557] hover:bg-white"
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          {/* Events Table */}
          <div className="overflow-x-auto pt-2">
            {displayedEvents.length === 0 ? (
              <div className="p-12 text-center text-[#457B9D] font-mono text-xs border-2 border-dashed border-[#1D3557]/20 rounded-lg my-2">
                <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-[#10b981]" />
                <p className="font-heading font-black text-sm text-[#1D3557] uppercase">
                  No Security Events Detected
                </p>
                <p className="text-[11px] text-[#457B9D] mt-1">
                  Passive security engine is monitoring live wire metadata. Suspicious anomalies will appear here with empirical evidence.
                </p>
              </div>
            ) : (
              <table className="w-full text-left font-mono text-xs border-collapse">
                <thead>
                  <tr className="border-b-2 border-[#1D3557] bg-[#F1FAEE] text-[10px] font-black text-[#1D3557] uppercase tracking-wider">
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Detection Name</th>
                    <th className="py-2.5 px-3">Source IP</th>
                    <th className="py-2.5 px-3">Destination IP</th>
                    <th className="py-2.5 px-3">Risk Score</th>
                    <th className="py-2.5 px-3">Lifecycle Status</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1D3557]/15">
                  {displayedEvents.map((evt) => (
                    <tr
                      key={evt.event_id}
                      onClick={() => setSelectedEvent(evt)}
                      className={`cursor-pointer hover:bg-[#F1FAEE]/70 transition-colors ${
                        selectedEvent?.event_id === evt.event_id ? "bg-[#F1FAEE]" : ""
                      }`}
                    >
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded border text-[10px] uppercase ${getSeverityBadgeClass(evt.severity)}`}>
                          {evt.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-black text-[#1D3557] text-xs">
                          {evt.detection_name}
                        </div>
                        <div className="text-[10px] text-[#457B9D] font-bold">
                          {evt.category} • {evt.event_id}
                          {evt.correlation_id && (
                            <span className="ml-1 px-1 rounded bg-[#ffedd5] border border-[#ea580c] text-[#ea580c] text-[9px]">
                              CORRELATED
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-bold text-[#1D3557]">
                        {evt.source_ip || "--"}
                      </td>
                      <td className="py-2.5 px-3 font-bold text-[#1D3557]">
                        {evt.destination_ip ? (
                          <span>
                            {evt.destination_ip}
                            {evt.target_port ? `:${evt.target_port}` : ""}
                          </span>
                        ) : evt.related_ips && evt.related_ips.length > 0 ? (
                          <span
                            title={evt.related_ips.join(", ")}
                            className="inline-flex items-center gap-1 underline decoration-dotted cursor-help text-[#1D3557]"
                          >
                            <span>{evt.related_ips.length} Targets</span>
                            {evt.target_port ? <span className="text-[#457B9D]">(:{evt.target_port})</span> : null}
                          </span>
                        ) : (
                          "--"
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-1.5 font-black text-xs text-[#1D3557]">
                          <span>{evt.risk_score}/100</span>
                          <span className="text-[10px] text-[#457B9D] font-bold">
                            ({(evt.confidence * 100).toFixed(0)}% conf)
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded-full border text-[10px] font-black uppercase ${getStatusBadgeClass(evt.status)}`}>
                          {evt.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(evt);
                          }}
                          className="px-2 py-1 rounded border-2 border-[#1D3557] bg-white hover:bg-[#1D3557] hover:text-white text-[10px] font-black transition-all shadow-[1px_1px_0px_#1D3557]"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </BentoCard>

        {/* Selected Event Investigation Drawer */}
        {selectedEvent && (
          <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[6px_6px_0px_#1D3557] space-y-4 font-mono text-xs animate-in fade-in duration-150">
            {/* Header */}
            <div className="flex items-start justify-between border-b-2 border-[#1D3557] pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded border text-[10px] uppercase ${getSeverityBadgeClass(selectedEvent.severity)}`}>
                    {selectedEvent.severity}
                  </span>
                  <span className="font-heading font-black text-lg text-[#1D3557]">
                    {selectedEvent.detection_name}
                  </span>
                  <span className="text-[10px] text-[#457B9D] font-bold">
                    [{selectedEvent.event_id}]
                  </span>
                </div>
                <p className="text-[11px] text-[#457B9D] mt-1 font-bold">
                  Rule ID: {selectedEvent.rule_id} • First Seen: {selectedEvent.first_seen} • Last Seen: {selectedEvent.last_seen}
                </p>
              </div>

              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1.5 rounded-lg border-2 border-[#1D3557] hover:bg-[#F1FAEE] text-[#1D3557]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Empirical Evidence & Guidance Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Evidence */}
              <div className="p-4 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] space-y-2">
                <span className="font-black text-[#1D3557] uppercase text-[11px] block">
                  Empirical Evidence
                </span>
                <p className="text-xs text-[#1D3557] font-medium leading-relaxed">
                  {selectedEvent.evidence_summary}
                </p>
                <div className="pt-2 border-t border-[#1D3557]/20 flex flex-wrap gap-3 text-[10px] text-[#457B9D]">
                  <span>Threshold: <strong>{selectedEvent.detection_threshold}</strong></span>
                  <span>Observed: <strong>{selectedEvent.observed_value}</strong></span>
                  <span>Count: <strong>{selectedEvent.observation_count}</strong></span>
                </div>
              </div>

              {/* Action */}
              <div className="p-4 rounded-lg border-2 border-[#1D3557] bg-white space-y-2 shadow-[2px_2px_0px_#1D3557]">
                <span className="font-black text-[#1D3557] uppercase text-[11px] block">
                  Recommended Defensive Action
                </span>
                <p className="text-xs text-[#1D3557] font-medium leading-relaxed">
                  {selectedEvent.recommended_action}
                </p>
                <div className="pt-2 border-t border-[#1D3557]/20 text-[10px] text-[#10b981] font-bold">
                  Safe Advisory Only (Passive Analysis Mode)
                </div>
              </div>
            </div>

            {/* Target Destination IPs Panel if multiple */}
            {selectedEvent.related_ips && selectedEvent.related_ips.length > 0 && (
              <div className="p-4 rounded-lg border-2 border-[#1D3557] bg-white space-y-2 shadow-[2px_2px_0px_#1D3557]">
                <div className="flex items-center justify-between text-[11px] font-black text-[#1D3557]">
                  <span>TARGET DESTINATION HOSTS ({selectedEvent.related_ips.length}):</span>
                  {selectedEvent.target_port && (
                    <span className="font-mono text-[10px] text-[#457B9D] font-bold">PORT: {selectedEvent.target_port}</span>
                  )}
                </div>
                <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto pt-1">
                  {selectedEvent.related_ips.map((ip, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded border border-[#1D3557]/40 bg-[#F1FAEE] font-mono text-[10px] font-bold text-[#1D3557]"
                    >
                      {ip}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Lifecycle Status & Controls */}
            <div className="p-4 rounded-lg border-2 border-[#1D3557] bg-white flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="font-black text-[#1D3557] text-[11px]">LIFECYCLE STATUS:</span>
                <span className={`px-2.5 py-0.5 rounded-full border text-[11px] font-black uppercase ${getStatusBadgeClass(selectedEvent.status)}`}>
                  {selectedEvent.status}
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] font-bold text-[#457B9D] mr-1">TRANSITION:</span>
                {["ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"].map((st) => (
                  <button
                    key={st}
                    onClick={() => handleStatusChange(selectedEvent.event_id, st)}
                    disabled={selectedEvent.status === st}
                    className="px-2.5 py-1 rounded border-2 border-[#1D3557] bg-white hover:bg-[#F1FAEE] text-[10px] font-black transition-all shadow-[1px_1px_0px_#1D3557] disabled:opacity-40"
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            {/* Analyst Notes Section */}
            <div className="space-y-3 pt-2 border-t-2 border-[#1D3557]/15">
              <div className="flex items-center gap-2 font-black text-[#1D3557] uppercase text-[11px]">
                <MessageSquare className="w-3.5 h-3.5 text-[#457B9D]" />
                <span>Analyst Investigation Notes ({selectedEvent.analyst_notes.length})</span>
              </div>

              {selectedEvent.analyst_notes.length > 0 && (
                <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                  {selectedEvent.analyst_notes.map((note, idx) => (
                    <div key={idx} className="p-2.5 rounded-lg border border-[#1D3557]/30 bg-[#F1FAEE] text-xs">
                      {note}
                    </div>
                  ))}
                </div>
              )}

              {/* Add Note Form */}
              <form onSubmit={handleAddNote} className="flex gap-2">
                <input
                  type="text"
                  value={newNoteText}
                  onChange={(e) => setNewNoteText(e.target.value)}
                  placeholder="Add audited analyst investigation finding..."
                  className="flex-1 px-3 py-1.5 rounded-lg border-2 border-[#1D3557] font-mono text-xs focus:outline-none focus:bg-[#F1FAEE]"
                />
                <button
                  type="submit"
                  disabled={isSubmittingNote || !newNoteText.trim()}
                  className="btn-primary px-4 py-1.5 text-xs font-mono font-bold shadow-[2px_2px_0px_#1D3557] disabled:opacity-50"
                >
                  {isSubmittingNote ? "Saving..." : "Add Note"}
                </button>
              </form>
            </div>

            {/* Audited Event History Log */}
            <div className="pt-2 border-t border-[#1D3557]/15">
              <span className="font-bold text-[#457B9D] text-[10px] uppercase block mb-1">
                Audited Action Trail
              </span>
              <div className="space-y-0.5 text-[10px] text-[#457B9D]">
                {selectedEvent.audit_trail.map((log, idx) => (
                  <p key={idx}>{log}</p>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Rules Configuration Modal */}
        {showRulesModal && (
          <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4 backdrop-blur-xs animate-in fade-in">
            <div className="bg-white border-2 border-[#1D3557] rounded-xl shadow-[6px_6px_0px_#1D3557] max-w-2xl w-full p-6 space-y-4 font-mono text-xs max-h-[85vh] overflow-y-auto">
              <div className="flex items-center justify-between border-b-2 border-[#1D3557] pb-3">
                <div>
                  <h3 className="font-heading font-black text-lg text-[#1D3557]">
                    DETECTION RULE MANAGEMENT
                  </h3>
                  <p className="text-[11px] text-[#457B9D]">
                    Configure operational parameters and thresholds for passive security rules
                  </p>
                </div>
                <button
                  onClick={() => setShowRulesModal(false)}
                  className="p-1 rounded hover:bg-[#F1FAEE]"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3">
                {rules.map((rule) => (
                  <div
                    key={rule.rule_id}
                    className="p-3 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557] flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-black text-[#1D3557] text-xs">{rule.name}</span>
                        <span className={`px-1.5 py-0.2 rounded border text-[9px] font-black uppercase ${
                          rule.enabled ? "bg-[#dcfce7] text-[#16a34a] border-[#16a34a]" : "bg-[#fee2e2] text-[#dc2626] border-[#dc2626]"
                        }`}>
                          {rule.enabled ? "ENABLED" : "DISABLED"}
                        </span>
                      </div>
                      <p className="text-[10px] text-[#457B9D] mt-0.5">{rule.description}</p>
                      <div className="flex gap-3 text-[10px] text-[#1D3557] font-bold mt-1">
                        <span>Threshold: <strong>{rule.threshold}</strong></span>
                        <span>Window: <strong>{rule.window_seconds}s</strong></span>
                        <span>Cooldown: <strong>{rule.cooldown_seconds}s</strong></span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => {
                          setEditingRule(rule);
                          setRuleThreshold(rule.threshold.toString());
                        }}
                        className="px-2 py-1 rounded border-2 border-[#1D3557] bg-[#F1FAEE] text-[10px] font-black hover:bg-white"
                      >
                        Edit Threshold
                      </button>
                      <button
                        onClick={() => handleToggleRule(rule)}
                        className={`px-2 py-1 rounded border-2 border-[#1D3557] text-[10px] font-black ${
                          rule.enabled ? "bg-[#fee2e2] text-[#dc2626]" : "bg-[#dcfce7] text-[#16a34a]"
                        }`}
                      >
                        {rule.enabled ? "Disable" : "Enable"}
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {/* Edit Rule Sub-drawer */}
              {editingRule && (
                <div className="p-4 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] space-y-2 mt-3">
                  <span className="font-black text-[#1D3557] text-xs block">
                    Update Threshold for {editingRule.name}
                  </span>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      step="1"
                      value={ruleThreshold}
                      onChange={(e) => setRuleThreshold(e.target.value)}
                      className="w-32 px-2.5 py-1.5 rounded border-2 border-[#1D3557] bg-white font-mono text-xs font-bold"
                    />
                    <button
                      onClick={handleSaveRule}
                      className="btn-primary px-4 py-1.5 text-xs font-mono font-bold"
                    >
                      Save
                    </button>
                    <button
                      onClick={() => setEditingRule(null)}
                      className="btn-secondary px-3 py-1.5 text-xs font-mono font-bold"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
