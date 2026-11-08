/**
 * Formatting utilities for network telemetry.
 */

export function formatBytes(bytes: number, decimals = 2): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  if (i < 0 || i >= sizes.length) return `${bytes} B`;
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

export function formatPackets(count: number): string {
  return new Intl.NumberFormat().format(count);
}

export function formatSpeed(mbps: number | null): string {
  if (!mbps || mbps <= 0) return "N/A";
  if (mbps >= 1000) return `${(mbps / 1000).toFixed(1)} Gbps`;
  return `${mbps} Mbps`;
}

export function formatBps(bits: number): string {
  if (!bits || bits <= 0) return "0 bps";
  const k = 1000;
  const sizes = ["bps", "Kbps", "Mbps", "Gbps"];
  const i = Math.floor(Math.log(bits) / Math.log(k));
  if (i <= 0) return `${bits.toFixed(0)} bps`;
  if (i >= sizes.length) return `${(bits / Math.pow(k, sizes.length - 1)).toFixed(1)} Gbps`;
  return `${(bits / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

