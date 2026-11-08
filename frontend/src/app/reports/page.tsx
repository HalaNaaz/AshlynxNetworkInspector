"use client";

import React, { useEffect, useState } from "react";
import {
  FileText,
  Download,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Network,
  Activity,
  Trash2,
  RefreshCw,
  Eye,
  FileSpreadsheet,
  FileCode,
  Layers,
  Sparkles,
  Server,
  Copy,
  Check,
} from "lucide-react";
import { DashboardLayout } from "@/components/DashboardLayout";
import { BentoCard } from "@/components/BentoCard";
import { StatusIndicator } from "@/components/StatusIndicator";
import { reportsApi } from "@/lib/api";
import {
  ReportFormat,
  ReportMetadataItem,
  ReportPreviewResponse,
  ReportSourceOption,
  ReportType,
} from "@/lib/types";

export default function ReportsPage() {
  const [sources, setSources] = useState<ReportSourceOption[]>([]);
  const [history, setHistory] = useState<ReportMetadataItem[]>([]);
  const [selectedType, setSelectedType] = useState<ReportType>("system_baseline");
  const [selectedFormat, setSelectedFormat] = useState<ReportFormat>("pdf");
  const [selectedSourceId, setSelectedSourceId] = useState<string>("");
  const [customTitle, setCustomTitle] = useState<string>("");
  const [customNotes, setCustomNotes] = useState<string>("");
  const [generating, setGenerating] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Active preview state
  const [preview, setPreview] = useState<ReportPreviewResponse | null>(null);
  const [loadingPreview, setLoadingPreview] = useState<boolean>(false);
  const [copiedJson, setCopiedJson] = useState<boolean>(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  // Load initial sources and history
  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [sourcesResp, historyResp] = await Promise.all([
        reportsApi.listSources().catch(() => ({ sources: [] })),
        reportsApi.listHistory(20).catch(() => []),
      ]);
      setSources(sourcesResp.sources || []);
      setHistory(historyResp || []);

      // If we have history, auto-load preview of the latest report
      if (historyResp && historyResp.length > 0 && !preview) {
        handleLoadPreview(historyResp[0].report_id);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to load reporting workstation state.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Filter sources matching the currently chosen report type
  const matchingSources = sources.filter((s) => s.source_type === selectedType);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setGenerating(true);
      setError(null);
      setSuccessMsg(null);

      // Validate format explicitly
      if (!["pdf", "csv", "json"].includes(selectedFormat)) {
        throw new Error(`Unsupported export format '${selectedFormat}'. Supported formats are: pdf, csv, json.`);
      }

      const generated = await reportsApi.generateReport({
        report_type: selectedType,
        report_format: selectedFormat,
        source_id: selectedSourceId ? selectedSourceId : undefined,
        title: customTitle.trim() || undefined,
        notes: customNotes.trim() || undefined,
      });

      setSuccessMsg(`Generated ${generated.report_format.toUpperCase()} report: ${generated.filename}`);
      setHistory((prev) => [generated, ...prev]);

      // Load preview of the newly created report
      await handleLoadPreview(generated.report_id);
    } catch (err: any) {
      setError(err?.message || "Report generation failed. Please verify source telemetry is available.");
    } finally {
      setGenerating(false);
    }
  };

  const handleLoadPreview = async (reportId: string) => {
    try {
      setLoadingPreview(true);
      const prev = await reportsApi.previewReport(reportId);
      setPreview(prev);
    } catch (err: any) {
      console.error("Preview error:", err);
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleDownload = async (reportId: string, filename?: string) => {
    try {
      setDownloadingId(reportId);
      const url = reportsApi.getDownloadUrl(reportId);
      const res = await fetch(url);
      if (!res.ok) {
        throw new Error(`Download failed with status ${res.status}`);
      }

      // Determine downloaded filename
      let resolvedFilename = filename;
      const disposition = res.headers.get("content-disposition");
      if (disposition && disposition.includes("filename=")) {
        const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
        if (match && match[1]) {
          resolvedFilename = match[1].replace(/['"]/g, "");
        }
      }

      const blob = await res.blob();
      const objectUrl = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = objectUrl;
      a.download = resolvedFilename || `ani_report_${reportId}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(objectUrl);
    } catch (err: any) {
      setError(err?.message || "Failed to download report file.");
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = async (reportId: string) => {
    if (!confirm("Are you sure you want to delete this report from disk and archive?")) {
      return;
    }
    try {
      await reportsApi.deleteReport(reportId);
      setHistory((prev) => prev.filter((r) => r.report_id !== reportId));
      if (preview && preview.report_id === reportId) {
        setPreview(null);
      }
      setSuccessMsg(`Report ${reportId} purged successfully.`);
    } catch (err: any) {
      setError(err?.message || "Failed to delete report.");
    }
  };

  const handleCopyJson = () => {
    if (!preview?.raw_content) return;
    navigator.clipboard.writeText(preview.raw_content);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <DashboardLayout>
      <div className="space-y-6 max-w-7xl mx-auto">
        {/* Page Hero Banner */}
        <div className="p-6 rounded-xl border-2 border-[#1D3557] bg-white shadow-[4px_4px_0px_#1D3557] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#457B9D] uppercase tracking-wider mb-1">
              <FileText className="w-4 h-4 text-[#457B9D]" />
              <span>EXECUTIVE AUDIT & DOCUMENTATION</span>
            </div>
            <h1 className="font-heading font-extrabold text-2xl text-[#1D3557] tracking-tight">
              SECURITY REPORTS & AUDIT WORKSTATION
            </h1>
            <p className="text-xs sm:text-sm text-[#457B9D] font-medium mt-1">
              Export enterprise compliance documents, reconnaissance findings, and wire telemetry in PDF, CSV, and JSON formats.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={loadData}
              disabled={loading}
              className="btn-secondary flex items-center gap-1.5 px-3 py-2 text-xs font-mono"
              title="Refresh telemetry sources"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
            <StatusIndicator
              status="operational"
              label="REPORT ENGINE v1.0"
            />
          </div>
        </div>

        {/* Notification Banners */}
        {error && (
          <div className="p-4 rounded-xl border-2 border-[#E63946] bg-[#FFEDED] shadow-[4px_4px_0px_#E63946] flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-[#E63946] shrink-0 mt-0.5" />
            <div className="text-xs font-mono text-[#1D3557]">
              <strong className="font-bold text-[#E63946]">Report Error:</strong> {error}
            </div>
          </div>
        )}

        {successMsg && (
          <div className="p-4 rounded-xl border-2 border-[#2A9D8F] bg-[#E8F8F5] shadow-[4px_4px_0px_#2A9D8F] flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-[#2A9D8F] shrink-0" />
            <div className="text-xs font-mono text-[#1D3557] font-semibold">
              {successMsg}
            </div>
          </div>
        )}

        {/* Primary Interactive Workspace Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Report Configuration & Generator (Left 6 Cols) */}
          <div className="lg:col-span-6 space-y-6">
            <BentoCard
              title="GENERATE AUDIT REPORT"
              subtitle="Select telemetry source, output format, and scope options"
            >
              <form onSubmit={handleGenerate} className="space-y-5 text-xs font-mono text-[#1D3557]">
                {/* 1. Data Domain Selection */}
                <div>
                  <label className="block text-[11px] font-bold text-[#457B9D] uppercase tracking-wider mb-2">
                    1. Telemetry Domain (Data Source)
                  </label>
                  <div className="grid grid-cols-2 gap-2">
                    {[
                      { type: "system_baseline", label: "System Baseline & Telemetry", icon: Server },
                      { type: "tcp_scan", label: "TCP Port Scan", icon: Shield },
                      { type: "udp_scan", label: "UDP Port Scan", icon: Radio },
                      { type: "host_discovery", label: "Host Discovery", icon: Network },
                      { type: "capture_session", label: "Packet Capture", icon: Layers },
                      { type: "traffic_analytics", label: "Traffic Analytics", icon: Activity },
                      { type: "security_events", label: "Security Events", icon: AlertTriangle },
                    ].map((item) => {
                      const Icon = item.icon;
                      const isSelected = selectedType === item.type;
                      return (
                        <button
                          key={item.type}
                          type="button"
                          onClick={() => {
                            setSelectedType(item.type as ReportType);
                            setSelectedSourceId("");
                          }}
                          className={`p-2.5 rounded-lg border-2 text-left transition-all flex items-center gap-2 ${
                            isSelected
                              ? "border-[#1D3557] bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557] font-bold"
                              : "border-gray-200 bg-white hover:border-[#457B9D]"
                          }`}
                        >
                          <Icon
                            className={`w-4 h-4 ${
                              isSelected ? "text-[#E63946]" : "text-[#457B9D]"
                            }`}
                          />
                          <span className="truncate">{item.label}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* 2. Specific Session / Job Selector */}
                <div>
                  <label className="block text-[11px] font-bold text-[#457B9D] uppercase tracking-wider mb-1.5">
                    2. Target Dataset / Session
                  </label>
                  <select
                    value={selectedSourceId}
                    onChange={(e) => setSelectedSourceId(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border-2 border-[#1D3557] bg-white text-xs font-mono focus:outline-none focus:ring-2 focus:ring-[#457B9D]"
                  >
                    <option value="">(Auto) Latest active or completed dataset</option>
                    {matchingSources.map((s) => (
                      <option key={s.source_id} value={s.source_id}>
                        {s.label} [{s.source_id.slice(0, 10)}]
                      </option>
                    ))}
                  </select>
                  <p className="text-[10px] text-[#457B9D] mt-1">
                    {matchingSources.length > 0
                      ? `${matchingSources.length} historical run(s) available for this domain.`
                      : "No dedicated historical runs detected. Latest engine state will be captured."}
                  </p>
                </div>

                {/* 3. Output Format Selector */}
                <div>
                  <label className="block text-[11px] font-bold text-[#457B9D] uppercase tracking-wider mb-2">
                    3. Document Export Format
                  </label>
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      {
                        fmt: "pdf",
                        title: "PDF Audit",
                        desc: "10-Section Formatted Doc",
                        icon: FileText,
                      },
                      {
                        fmt: "csv",
                        title: "CSV Export",
                        desc: "RFC 4180 Escaped Data",
                        icon: FileSpreadsheet,
                      },
                      {
                        fmt: "json",
                        title: "JSON Schema",
                        desc: "Standardized Telemetry",
                        icon: FileCode,
                      },
                    ].map((item) => {
                      const Icon = item.icon;
                      const isSelected = selectedFormat === item.fmt;
                      return (
                        <button
                          key={item.fmt}
                          type="button"
                          onClick={() => setSelectedFormat(item.fmt as ReportFormat)}
                          className={`p-2.5 rounded-lg border-2 text-left transition-all ${
                            isSelected
                              ? "border-[#1D3557] bg-[#F1FAEE] shadow-[2px_2px_0px_#1D3557]"
                              : "border-gray-200 bg-white hover:border-[#457B9D]"
                          }`}
                        >
                          <div className="flex items-center gap-1.5 mb-1">
                            <Icon
                              className={`w-3.5 h-3.5 ${
                                isSelected ? "text-[#E63946]" : "text-[#457B9D]"
                              }`}
                            />
                            <span className="font-bold text-xs">{item.title}</span>
                          </div>
                          <p className="text-[10px] text-[#457B9D]">{item.desc}</p>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* 4. Optional Customization */}
                <div className="space-y-3 pt-1 border-t border-gray-100">
                  <div>
                    <label className="block text-[11px] font-bold text-[#457B9D] uppercase tracking-wider mb-1">
                      Custom Report Title (Optional)
                    </label>
                    <input
                      type="text"
                      maxLength={120}
                      value={customTitle}
                      onChange={(e) => setCustomTitle(e.target.value)}
                      placeholder="e.g. Workstation Baseline Security Verification"
                      className="w-full px-3 py-2 rounded-lg border border-[#1D3557] bg-white text-xs font-mono focus:outline-none focus:ring-2 focus:ring-[#457B9D]"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold text-[#457B9D] uppercase tracking-wider mb-1">
                      Executive / Auditor Notes (Optional)
                    </label>
                    <textarea
                      rows={2}
                      maxLength={500}
                      value={customNotes}
                      onChange={(e) => setCustomNotes(e.target.value)}
                      placeholder="Add compliance context, auditor identity, or specific observations..."
                      className="w-full px-3 py-2 rounded-lg border border-[#1D3557] bg-white text-xs font-mono focus:outline-none focus:ring-2 focus:ring-[#457B9D]"
                    />
                  </div>
                </div>

                {/* Submit Action */}
                <button
                  type="submit"
                  disabled={generating}
                  className="w-full btn-primary flex items-center justify-center gap-2 py-3 text-xs font-mono font-bold tracking-wide shadow-[3px_3px_0px_#1D3557]"
                >
                  {generating ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      COMPILING AUDIT REPORT...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4 text-[#A8DADC]" />
                      GENERATE {selectedFormat.toUpperCase()} REPORT
                    </>
                  )}
                </button>
              </form>
            </BentoCard>
          </div>

          {/* Live Document Preview Panel (Right 6 Cols) */}
          <div className="lg:col-span-6 space-y-6">
            <BentoCard
              title="ACTIVE REPORT PREVIEW"
              subtitle={
                preview
                  ? `${preview.title} (${preview.report_format.toUpperCase()})`
                  : "No report selected for preview"
              }
              action={
                preview && (
                  <div className="flex items-center gap-2">
                    {preview.report_format === "json" && preview.raw_content && (
                      <button
                        onClick={handleCopyJson}
                        className="btn-secondary flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-mono"
                        title="Copy raw JSON payload"
                      >
                        {copiedJson ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-[#2A9D8F]" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5 text-[#1D3557]" />
                            <span>Copy JSON</span>
                          </>
                        )}
                      </button>
                    )}
                    <button
                      onClick={() => handleDownload(preview.report_id, `ani_${preview.report_type}_${preview.report_id}.${preview.report_format}`)}
                      disabled={downloadingId === preview.report_id}
                      className="btn-primary flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono"
                    >
                      <Download className={`w-3.5 h-3.5 ${downloadingId === preview.report_id ? "animate-spin" : ""}`} />
                      <span>Download {preview.report_format.toUpperCase()}</span>
                    </button>
                  </div>
                )
              }
            >
              {loadingPreview ? (
                <div className="p-12 text-center text-xs font-mono text-[#457B9D]">
                  <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-[#1D3557]" />
                  Loading document preview...
                </div>
              ) : preview ? (
                <div className="space-y-4 text-xs font-mono text-[#1D3557]">
                  {/* Executive Header Box */}
                  <div className="p-3.5 rounded-lg border-2 border-[#1D3557] bg-[#F1FAEE] space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-heading font-extrabold text-sm text-[#1D3557]">
                        {preview.title}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          preview.report_format === "pdf"
                            ? "bg-[#E63946] text-white"
                            : preview.report_format === "csv"
                            ? "bg-[#2A9D8F] text-white"
                            : "bg-[#1D3557] text-white"
                        }`}
                      >
                        {preview.report_format}
                      </span>
                    </div>
                    <div className="text-[11px] text-[#457B9D]">
                      Report ID: <span className="font-bold text-[#1D3557]">{preview.report_id}</span> |{" "}
                      Generated: <span className="text-[#1D3557]">{new Date(preview.created_at).toLocaleString()}</span>
                    </div>
                  </div>

                  {/* FORMAT-SPECIFIC PREVIEWS */}
                  {/* MODE A: JSON SCHEMA PREVIEW */}
                  {preview.report_format === "json" ? (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-[11px] text-[#457B9D] font-bold">
                        <span className="flex items-center gap-1.5">
                          <FileCode className="w-3.5 h-3.5 text-[#1D3557]" />
                          STANDARDIZED JSON SCHEMA AUDIT RECORD
                        </span>
                        <span>{preview.total_rows} findings items</span>
                      </div>
                      <div className="rounded-lg border-2 border-[#1D3557] bg-[#0F172A] p-3 overflow-x-auto max-h-[380px] overflow-y-auto">
                        <pre className="text-[11px] font-mono text-[#38BDF8] leading-relaxed whitespace-pre">
                          {preview.raw_content || JSON.stringify(preview.json_preview, null, 2)}
                        </pre>
                      </div>
                    </div>
                  ) : preview.report_format === "csv" ? (
                    /* MODE B: CSV TABULAR PREVIEW */
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-[11px] text-[#457B9D] font-bold">
                        <span className="flex items-center gap-1.5">
                          <FileSpreadsheet className="w-3.5 h-3.5 text-[#2A9D8F]" />
                          RFC 4180 TABULAR CSV PREVIEW
                        </span>
                        <span>{preview.total_rows} rows</span>
                      </div>
                      <div className="rounded-lg border-2 border-[#1D3557] overflow-x-auto bg-white max-h-[380px] overflow-y-auto">
                        <table className="w-full text-left border-collapse text-[11px]">
                          <thead>
                            <tr className="bg-[#1D3557] text-white sticky top-0">
                              {preview.headers.map((h, idx) => (
                                <th key={idx} className="px-2.5 py-1.5 font-bold uppercase tracking-wider">
                                  {h}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-200">
                            {preview.preview_rows.map((row, rIdx) => (
                              <tr key={rIdx} className={rIdx % 2 === 0 ? "bg-white" : "bg-[#F1FAEE]"}>
                                {row.map((cell, cIdx) => (
                                  <td key={cIdx} className="px-2.5 py-1.5 whitespace-nowrap">
                                    {String(cell ?? "—")}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : (
                    /* MODE C: PDF AUDIT PREVIEW */
                    <div className="space-y-3">
                      {preview.summary && (
                        <div className="p-3 rounded-lg border border-[#1D3557] bg-white space-y-2">
                          <span className="text-[10px] font-bold text-[#457B9D] uppercase tracking-wider block">
                            Executive Summary & Metrics
                          </span>
                          {preview.summary.Summary && (
                            <p className="text-[11px] text-[#1D3557] font-sans leading-relaxed">
                              {preview.summary.Summary}
                            </p>
                          )}
                          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2 border-t border-gray-100">
                            {Object.entries(preview.summary)
                              .filter(([k]) => k !== "Summary" && k !== "Message" && k !== "narrative")
                              .slice(0, 6)
                              .map(([key, val]) => (
                                <div key={key} className="p-2 rounded bg-[#F1FAEE] border border-gray-200">
                                  <span className="text-[9px] text-[#457B9D] block uppercase truncate">
                                    {key}
                                  </span>
                                  <span className="font-bold text-xs text-[#1D3557] block truncate">
                                    {String(val)}
                                  </span>
                                </div>
                              ))}
                          </div>
                        </div>
                      )}

                      <div className="space-y-1.5">
                        <div className="flex items-center justify-between text-[11px] text-[#457B9D] font-bold">
                          <span>DOCUMENT FINDINGS ({preview.total_rows} total rows)</span>
                          <span>Showing top {preview.preview_rows.length}</span>
                        </div>
                        <div className="rounded-lg border-2 border-[#1D3557] overflow-x-auto bg-white max-h-[260px] overflow-y-auto">
                          <table className="w-full text-left border-collapse text-[11px]">
                            <thead>
                              <tr className="bg-[#1D3557] text-white sticky top-0">
                                {preview.headers.map((h, idx) => (
                                  <th key={idx} className="px-2.5 py-1.5 font-bold uppercase tracking-wider">
                                    {h}
                                  </th>
                                ))}
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-200">
                              {preview.preview_rows.map((row, rIdx) => (
                                <tr key={rIdx} className={rIdx % 2 === 0 ? "bg-white" : "bg-[#F1FAEE]"}>
                                  {row.map((cell, cIdx) => (
                                    <td key={cIdx} className="px-2.5 py-1.5 whitespace-nowrap">
                                      {cell === "OPEN" || cell === "CRITICAL" || cell === "HIGH" ? (
                                        <span className="font-bold text-[#E63946]">{String(cell)}</span>
                                      ) : cell === "CLOSED" || cell === "RESOLVED" || cell === "online" ? (
                                        <span className="font-bold text-[#2A9D8F]">{String(cell)}</span>
                                      ) : (
                                        String(cell ?? "—")
                                      )}
                                    </td>
                                  ))}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-12 text-center text-xs font-mono text-[#457B9D]">
                  <FileText className="w-8 h-8 text-[#457B9D] opacity-40 mx-auto mb-2" />
                  Select a report from the archive below or generate a new document to inspect preview findings.
                </div>
              )}
            </BentoCard>
          </div>
        </div>

        {/* Report Archive & History Table (Full Width Bento) */}
        <BentoCard
          title="AUDIT DOCUMENT ARCHIVE & HISTORY"
          subtitle="All generated compliance documents, vulnerability reports, and raw exports"
          action={
            <span className="text-xs font-mono font-bold text-[#457B9D]">
              {history.length} REPORT(S) ARCHIVED
            </span>
          }
        >
          {history.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-[#457B9D]">
              No reports have been generated yet in this session. Configure the parameters above and click "Generate Report".
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border-2 border-[#1D3557] bg-white">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-[#1D3557] text-white">
                    <th className="px-3.5 py-2.5 font-bold">Report Title</th>
                    <th className="px-3.5 py-2.5 font-bold">Telemetry Source</th>
                    <th className="px-3.5 py-2.5 font-bold">Format</th>
                    <th className="px-3.5 py-2.5 font-bold">Generated</th>
                    <th className="px-3.5 py-2.5 font-bold">Items</th>
                    <th className="px-3.5 py-2.5 font-bold">Size</th>
                    <th className="px-3.5 py-2.5 font-bold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {history.map((r, idx) => (
                    <tr
                      key={r.report_id}
                      className={`hover:bg-[#F1FAEE] transition-colors ${
                        preview?.report_id === r.report_id ? "bg-[#EBF5FB]" : idx % 2 === 0 ? "bg-white" : "bg-[#FAFBF9]"
                      }`}
                    >
                      <td className="px-3.5 py-2.5 font-bold text-[#1D3557]">
                        {r.title}
                      </td>
                      <td className="px-3.5 py-2.5 text-[#457B9D]">
                        <span className="px-2 py-0.5 rounded bg-gray-100 border border-gray-200 text-[10px] uppercase font-bold text-[#1D3557]">
                          {r.report_type.replace("_", " ")}
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            r.report_format === "pdf"
                              ? "bg-[#E63946] text-white"
                              : r.report_format === "csv"
                              ? "bg-[#2A9D8F] text-white"
                              : "bg-[#1D3557] text-white"
                          }`}
                        >
                          {r.report_format}
                        </span>
                      </td>
                      <td className="px-3.5 py-2.5 text-[#457B9D] text-[11px]">
                        {new Date(r.created_at).toLocaleTimeString([], {
                          hour: "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                        })}
                      </td>
                      <td className="px-3.5 py-2.5 text-[#1D3557] font-semibold">
                        {r.item_count} findings
                      </td>
                      <td className="px-3.5 py-2.5 text-[#457B9D] text-[11px]">
                        {(r.file_size_bytes / 1024).toFixed(1)} KB
                      </td>
                      <td className="px-3.5 py-2.5 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleLoadPreview(r.report_id)}
                            className="p-1.5 rounded hover:bg-[#A8DADC] text-[#1D3557] transition-colors"
                            title="Preview Report"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDownload(r.report_id, r.filename)}
                            disabled={downloadingId === r.report_id}
                            className="p-1.5 rounded hover:bg-[#A8DADC] text-[#2A9D8F] transition-colors"
                            title="Download Report"
                          >
                            <Download className={`w-4 h-4 ${downloadingId === r.report_id ? "animate-spin" : ""}`} />
                          </button>
                          <button
                            onClick={() => handleDelete(r.report_id)}
                            className="p-1.5 rounded hover:bg-red-100 text-[#E63946] transition-colors"
                            title="Purge Report"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </BentoCard>

        {/* Enterprise Compliance Standard Bento Card */}
        <BentoCard
          title="PLATFORM SPECIFICATION & COMPLIANCE SUMMARY"
          subtitle="Verification of safe operation and enterprise architectural standards"
          variant="aqua"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            <div className="p-3.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
              <span className="font-heading font-extrabold text-xs text-[#1D3557] block mb-1">
                Zero Shell Injection
              </span>
              <p className="text-[11px] text-[#457B9D] font-sans">
                All platform probes execute via native Python standard library and Scapy sockets. No arbitrary shell or subprocess calls.
              </p>
            </div>

            <div className="p-3.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
              <span className="font-heading font-extrabold text-xs text-[#1D3557] block mb-1">
                Payload Privacy Standard
              </span>
              <p className="text-[11px] text-[#457B9D] font-sans">
                Application layer payloads (HTTP bodies, credentials, private files) are never persisted or exported in reports.
              </p>
            </div>

            <div className="p-3.5 rounded-lg border-2 border-[#1D3557] bg-white shadow-[2px_2px_0px_#1D3557]">
              <span className="font-heading font-extrabold text-xs text-[#1D3557] block mb-1">
                Bound Reconnaissance Scope
              </span>
              <p className="text-[11px] text-[#457B9D] font-sans">
                Probing is restricted strictly to loopback and private RFC-1918 subnets, protecting unassociated external networks.
              </p>
            </div>
          </div>
        </BentoCard>
      </div>
    </DashboardLayout>
  );
}
