import {
  ApiResponse,
  DiscoveryHistoryItem,
  DiscoveryValidationRequest,
  DiscoveryValidationResponse,
  HealthData,
  HostDiscoveryRequest,
  HostDiscoveryResponse,
  HostDiscoveryStatusData,
  NetworkInterfacesData,
  NetworkSummaryData,
  PortScanRequest,
  ScanExecutionResponse,
  ScanHistoryItem,
  ScannerStatusData,
  ScanValidationRequest,
  ScanValidationResponse,
  TrafficStatusData,
  UdpScanExecutionResponse,
  UdpScanRequest,
} from "./types";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000/api";

export class ApiClientError extends Error {
  code: string;
  status?: number;

  constructor(message: string, code = "NETWORK_ERROR", status?: number) {
    super(message);
    this.name = "ApiClientError";
    this.code = code;
    this.status = status;
  }
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...options.headers,
      },
      // Short cache lifetime for real-time monitoring
      cache: "no-store",
    });

    if (!response.ok) {
      let errorMsg = `Server responded with status ${response.status} (${response.statusText})`;
      let errorCode = "HTTP_ERROR";
      try {
        const errorBody = await response.json();
        if (errorBody?.error?.detail) {
          errorMsg = errorBody.error.detail;
          errorCode = errorBody.error.code || errorCode;
        } else if (errorBody?.detail) {
          errorMsg = errorBody.detail;
        } else if (errorBody?.message) {
          errorMsg = errorBody.message;
        }
      } catch {
        // Fallback to response.statusText
      }
      throw new ApiClientError(errorMsg, errorCode, response.status);
    }

    const json = await response.json();
    if (json && typeof json === "object" && ("data" in json || "success" in json)) {
      const payload = json as ApiResponse<T>;
      if (!payload.success && payload.data === undefined) {
        throw new ApiClientError(payload.message || "API request was unsuccessful", "API_ERROR");
      }
      return payload.data as T;
    }
    return json as T;
  } catch (err: unknown) {
    if (err instanceof ApiClientError) {
      throw err;
    }
    const message = err instanceof Error ? err.message : "Unknown connection failure";
    throw new ApiClientError(
      `Cannot connect to backend service at ${API_BASE_URL}. Ensure the FastAPI server is running. (${message})`,
      "CONNECTION_REFUSED"
    );
  }
}

export const apiClient = {
  getBaseUrl: () => API_BASE_URL,

  getHealth: (): Promise<HealthData> => {
    return request<HealthData>("/health");
  },

  getNetworkInterfaces: (): Promise<NetworkInterfacesData> => {
    return request<NetworkInterfacesData>("/network/interfaces");
  },

  getNetworkSummary: (): Promise<NetworkSummaryData> => {
    return request<NetworkSummaryData>("/network/summary");
  },

  getScannerStatus: (): Promise<ScannerStatusData> => {
    return request<ScannerStatusData>("/scanner/status");
  },

  getTrafficStatus: (): Promise<TrafficStatusData> => {
    return request<TrafficStatusData>("/traffic/status");
  },

  // ==================== TCP SCANNER ====================
  validateScanConfig: (data: ScanValidationRequest): Promise<ScanValidationResponse> => {
    return request<ScanValidationResponse>("/scanner/validate", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  executePortScan: (data: PortScanRequest): Promise<ScanExecutionResponse> => {
    return request<ScanExecutionResponse>("/scanner/scan", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getScanResult: (scanId: string): Promise<ScanExecutionResponse> => {
    return request<ScanExecutionResponse>(`/scanner/scans/${encodeURIComponent(scanId)}`);
  },

  getScanHistory: (): Promise<ScanHistoryItem[]> => {
    return request<ScanHistoryItem[]>("/scanner/history");
  },

  getLatestScan: (): Promise<ScanExecutionResponse | null> => {
    return request<ScanExecutionResponse | null>("/scanner/latest");
  },

  // ==================== UDP SCANNER ====================
  validateUdpScanConfig: (data: ScanValidationRequest): Promise<ScanValidationResponse> => {
    return request<ScanValidationResponse>("/scanner/udp/validate", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  executeUdpPortScan: (data: UdpScanRequest): Promise<UdpScanExecutionResponse> => {
    return request<UdpScanExecutionResponse>("/scanner/udp/scan", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getLatestUdpScan: (): Promise<UdpScanExecutionResponse | null> => {
    return request<UdpScanExecutionResponse | null>("/scanner/udp/latest");
  },

  // ==================== HOST DISCOVERY ====================
  getDiscoveryStatus: (): Promise<HostDiscoveryStatusData> => {
    return request<HostDiscoveryStatusData>("/discovery/status");
  },

  validateDiscoveryConfig: (data: DiscoveryValidationRequest): Promise<DiscoveryValidationResponse> => {
    return request<DiscoveryValidationResponse>("/discovery/validate", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  executeHostDiscovery: (data: HostDiscoveryRequest): Promise<HostDiscoveryResponse> => {
    return request<HostDiscoveryResponse>("/discovery/scan", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getDiscoveryResult: (discoveryId: string): Promise<HostDiscoveryResponse> => {
    return request<HostDiscoveryResponse>(`/discovery/scans/${encodeURIComponent(discoveryId)}`);
  },

  getDiscoveryHistory: (limit = 50): Promise<DiscoveryHistoryItem[]> => {
    return request<DiscoveryHistoryItem[]>(`/discovery/history?limit=${limit}`);
  },

  getLatestDiscovery: (): Promise<HostDiscoveryResponse | null> => {
    return request<HostDiscoveryResponse | null>("/discovery/latest");
  },

  // ==================== PHASE 4: LIVE PACKET CAPTURE ====================
  getCaptureEnvironmentStatus: (): Promise<import("./types").CaptureEnvironmentData> => {
    return request<import("./types").CaptureEnvironmentData>("/capture/status");
  },

  getCaptureInterfaces: (): Promise<import("./types").CaptureInterfaceItem[]> => {
    return request<import("./types").CaptureInterfaceItem[]>("/capture/interfaces");
  },

  startCaptureSession: (data: import("./types").CaptureStartRequest): Promise<import("./types").CaptureSessionResponse> => {
    return request<import("./types").CaptureSessionResponse>("/capture/start", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  stopCaptureSession: (): Promise<import("./types").CaptureSessionResponse> => {
    return request<import("./types").CaptureSessionResponse>("/capture/stop", {
      method: "POST",
    });
  },

  getCaptureSessions: (): Promise<import("./types").CaptureSessionResponse[]> => {
    return request<import("./types").CaptureSessionResponse[]>("/capture/sessions");
  },

  getCaptureSession: (sessionId: string): Promise<import("./types").CaptureSessionResponse> => {
    return request<import("./types").CaptureSessionResponse>(`/capture/sessions/${encodeURIComponent(sessionId)}`);
  },

  getCaptureSessionPackets: (
    sessionId: string,
    params: { offset?: number; limit?: number; protocol?: string; search?: string } = {}
  ): Promise<import("./types").CapturePacketsResponse> => {
    const q = new URLSearchParams();
    if (params.offset !== undefined) q.set("offset", params.offset.toString());
    if (params.limit !== undefined) q.set("limit", params.limit.toString());
    if (params.protocol) q.set("protocol", params.protocol);
    if (params.search) q.set("search", params.search);
    return request<import("./types").CapturePacketsResponse>(`/capture/sessions/${encodeURIComponent(sessionId)}/packets?${q.toString()}`);
  },

  getCaptureSessionStatistics: (sessionId: string): Promise<import("./types").CaptureStatistics> => {
    return request<import("./types").CaptureStatistics>(`/capture/sessions/${encodeURIComponent(sessionId)}/statistics`);
  },

  clearCaptureBuffer: (sessionId: string): Promise<{ session_id: string; cleared: boolean }> => {
    return request<{ session_id: string; cleared: boolean }>(`/capture/sessions/${encodeURIComponent(sessionId)}/clear`, {
      method: "POST",
    });
  },
};

export const analyticsApi = {
  getOverview: (sessionId: string = "latest"): Promise<import("./types").AnalyticsOverviewResponse> => {
    return request<import("./types").AnalyticsOverviewResponse>(`/analytics/${encodeURIComponent(sessionId)}/overview`);
  },
  getProtocols: (sessionId: string = "latest"): Promise<import("./types").ProtocolAnalyticsResponse> => {
    return request<import("./types").ProtocolAnalyticsResponse>(`/analytics/${encodeURIComponent(sessionId)}/protocols`);
  },
  getBandwidth: (sessionId: string = "latest", windowSeconds: number = 1): Promise<import("./types").BandwidthAnalyticsResponse> => {
    return request<import("./types").BandwidthAnalyticsResponse>(`/analytics/${encodeURIComponent(sessionId)}/bandwidth?window_seconds=${windowSeconds}`);
  },
  getTopTalkers: (sessionId: string = "latest"): Promise<import("./types").TopTalkersResponse> => {
    return request<import("./types").TopTalkersResponse>(`/analytics/${encodeURIComponent(sessionId)}/top-talkers`);
  },
  getConnections: (sessionId: string = "latest", limit: number = 100): Promise<import("./types").ConnectionsAnalyticsResponse> => {
    return request<import("./types").ConnectionsAnalyticsResponse>(`/analytics/${encodeURIComponent(sessionId)}/connections?limit=${limit}`);
  },
  getDns: (sessionId: string = "latest"): Promise<import("./types").DnsAnalyticsResponse> => {
    return request<import("./types").DnsAnalyticsResponse>(`/analytics/${encodeURIComponent(sessionId)}/dns`);
  },
  getTimeline: (sessionId: string = "latest"): Promise<import("./types").TrafficTimelineResponse> => {
    return request<import("./types").TrafficTimelineResponse>(`/analytics/${encodeURIComponent(sessionId)}/timeline`);
  },
};

export const securityApi = {
  getStatus: (sessionId?: string): Promise<import("./types").SecurityStatusResponse> => {
    const q = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : "";
    return request<import("./types").SecurityStatusResponse>(`/security/status${q}`);
  },
  getOverview: (sessionId?: string): Promise<import("./types").SecurityOverviewResponse> => {
    const q = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : "";
    return request<import("./types").SecurityOverviewResponse>(`/security/overview${q}`);
  },
  listEvents: (params: {
    sessionId?: string;
    severity?: string;
    category?: string;
    status?: string;
    sourceIp?: string;
    offset?: number;
    limit?: number;
  } = {}): Promise<import("./types").SecurityEventsListResponse> => {
    const q = new URLSearchParams();
    if (params.sessionId) q.set("session_id", params.sessionId);
    if (params.severity) q.set("severity", params.severity);
    if (params.category) q.set("category", params.category);
    if (params.status) q.set("status", params.status);
    if (params.sourceIp) q.set("source_ip", params.sourceIp);
    if (params.offset !== undefined) q.set("offset", params.offset.toString());
    if (params.limit !== undefined) q.set("limit", params.limit.toString());
    return request<import("./types").SecurityEventsListResponse>(`/security/events?${q.toString()}`);
  },
  getEvent: (eventId: string): Promise<import("./types").SecurityEventItem> => {
    return request<import("./types").SecurityEventItem>(`/security/events/${encodeURIComponent(eventId)}`);
  },
  updateEventStatus: (
    eventId: string,
    status: string,
    analystName?: string
  ): Promise<import("./types").SecurityEventItem> => {
    return request<import("./types").SecurityEventItem>(`/security/events/${encodeURIComponent(eventId)}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status, analyst_name: analystName }),
    });
  },
  addEventNote: (
    eventId: string,
    note: string,
    author?: string
  ): Promise<import("./types").SecurityEventItem> => {
    return request<import("./types").SecurityEventItem>(`/security/events/${encodeURIComponent(eventId)}/notes`, {
      method: "POST",
      body: JSON.stringify({ note, author }),
    });
  },
  listRules: (): Promise<import("./types").RuleConfigItem[]> => {
    return request<import("./types").RuleConfigItem[]>("/security/rules");
  },
  updateRule: (
    ruleId: string,
    update: import("./types").RuleUpdateRequest
  ): Promise<import("./types").RuleConfigItem> => {
    return request<import("./types").RuleConfigItem>(`/security/rules/${encodeURIComponent(ruleId)}`, {
      method: "PATCH",
      body: JSON.stringify(update),
    });
  },
  getTimeline: (sessionId?: string): Promise<import("./types").SecurityTimelineResponse> => {
    const q = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : "";
    return request<import("./types").SecurityTimelineResponse>(`/security/timeline${q}`);
  },
};

// ==================== REPORTING & ANALYTICS CLIENT ====================
export const reportsApi = {
  listSources: (): Promise<import("./types").ReportSourcesResponse> => {
    return request<import("./types").ReportSourcesResponse>("/reports/sources");
  },
  generateReport: (
    req: import("./types").ReportGenerateRequest
  ): Promise<import("./types").ReportMetadataItem> => {
    return request<import("./types").ReportMetadataItem>("/reports/generate", {
      method: "POST",
      body: JSON.stringify(req),
    });
  },
  listHistory: (limit = 50): Promise<import("./types").ReportMetadataItem[]> => {
    return request<import("./types").ReportMetadataItem[]>(`/reports/history?limit=${limit}`);
  },
  previewReport: (
    reportId: string
  ): Promise<import("./types").ReportPreviewResponse> => {
    return request<import("./types").ReportPreviewResponse>(
      `/reports/${encodeURIComponent(reportId)}/preview`
    );
  },
  deleteReport: (reportId: string): Promise<boolean> => {
    return request<boolean>(`/reports/${encodeURIComponent(reportId)}`, {
      method: "DELETE",
    });
  },
  getDownloadUrl: (reportId: string): string => {
    return `${API_BASE_URL}/reports/${encodeURIComponent(reportId)}/download`;
  },
};
