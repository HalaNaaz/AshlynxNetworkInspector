"use client";

import React, { ReactNode, useState } from "react";
import { AppSidebar } from "./AppSidebar";
import { AppHeader } from "./AppHeader";
import { useNetworkData } from "@/hooks/useNetworkData";

interface DashboardLayoutProps {
  children: ReactNode;
}

export function DashboardLayout({ children }: DashboardLayoutProps) {
  const { health, refresh, isRefreshing, lastUpdated } = useNetworkData(10000);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const backendOnline = !!health && health.backend_status === "operational";

  return (
    <div className="flex min-h-screen bg-[#F1FAEE] text-[#1D3557] antialiased w-full overflow-x-hidden">
      <AppSidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
      />
      <div className="flex-1 flex flex-col min-w-0 w-full overflow-x-hidden">
        <AppHeader
          backendOnline={backendOnline}
          onRefresh={refresh}
          isRefreshing={isRefreshing}
          lastUpdated={lastUpdated}
          onToggleSidebar={() => setSidebarCollapsed(!sidebarCollapsed)}
        />
        <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto overflow-x-hidden min-w-0 w-full max-w-full bg-dot-grid-subtle">
          {children}
        </main>
      </div>
    </div>
  );
}
