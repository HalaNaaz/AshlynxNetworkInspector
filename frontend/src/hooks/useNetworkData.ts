"use client";

import { useState, useEffect, useCallback } from "react";
import { apiClient } from "@/lib/api";
import {
  HealthData,
  NetworkInterface,
  NetworkSummaryData,
  ScannerStatusData,
  TrafficStatusData,
} from "@/lib/types";

export interface NetworkDataState {
  health: HealthData | null;
  interfaces: NetworkInterface[];
  summary: NetworkSummaryData | null;
  scanner: ScannerStatusData | null;
  traffic: TrafficStatusData | null;
  loading: boolean;
  isRefreshing: boolean;
  error: string | null;
  lastUpdated: Date | null;
  refresh: () => Promise<void>;
}

export function useNetworkData(autoRefreshIntervalMs = 10000): NetworkDataState {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [summary, setSummary] = useState<NetworkSummaryData | null>(null);
  const [scanner, setScanner] = useState<ScannerStatusData | null>(null);
  const [traffic, setTraffic] = useState<TrafficStatusData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setIsRefreshing(true);
    }
    setError(null);

    try {
      const [healthRes, ifacesRes, summaryRes, scannerRes, trafficRes] =
        await Promise.allSettled([
          apiClient.getHealth(),
          apiClient.getNetworkInterfaces(),
          apiClient.getNetworkSummary(),
          apiClient.getScannerStatus(),
          apiClient.getTrafficStatus(),
        ]);

      let hasFatalError = false;
      const errorMessages: string[] = [];

      if (healthRes.status === "fulfilled") {
        setHealth(healthRes.value);
      } else {
        hasFatalError = true;
        errorMessages.push(`Health: ${healthRes.reason?.message || "Unavailable"}`);
      }

      if (ifacesRes.status === "fulfilled") {
        setInterfaces(ifacesRes.value.interfaces);
      } else {
        errorMessages.push(`Interfaces: ${ifacesRes.reason?.message || "Unavailable"}`);
      }

      if (summaryRes.status === "fulfilled") {
        setSummary(summaryRes.value);
      } else {
        errorMessages.push(`Summary: ${summaryRes.reason?.message || "Unavailable"}`);
      }

      if (scannerRes.status === "fulfilled") {
        setScanner(scannerRes.value);
      } else {
        errorMessages.push(`Scanner: ${scannerRes.reason?.message || "Unavailable"}`);
      }

      if (trafficRes.status === "fulfilled") {
        setTraffic(trafficRes.value);
      } else {
        errorMessages.push(`Traffic: ${trafficRes.reason?.message || "Unavailable"}`);
      }

      if (hasFatalError && errorMessages.length > 0) {
        setError(errorMessages[0]);
      } else {
        setError(null);
      }

      setLastUpdated(new Date());
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to communicate with ANI backend.";
      setError(msg);
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();

    if (autoRefreshIntervalMs > 0) {
      const timer = setInterval(() => {
        fetchData();
      }, autoRefreshIntervalMs);
      return () => clearInterval(timer);
    }
  }, [fetchData, autoRefreshIntervalMs]);

  const refresh = useCallback(async () => {
    await fetchData(true);
  }, [fetchData]);

  return {
    health,
    interfaces,
    summary,
    scanner,
    traffic,
    loading,
    isRefreshing,
    error,
    lastUpdated,
    refresh,
  };
}

