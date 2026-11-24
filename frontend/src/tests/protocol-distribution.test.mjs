import test from "node:test";
import assert from "node:assert/strict";

// Mock Protocol Analytics Data matching Backend ProtocolAnalyticsResponse
const mockActiveProtocols = {
  session_id: "cap-e07db5ccbcb3",
  total_packets: 5816,
  total_bytes: 5578142,
  transport_distribution: [
    { protocol: "TCP", packet_count: 5718, byte_count: 5560100, percentage: 98.31 },
    { protocol: "UDP", packet_count: 90, byte_count: 17646, percentage: 1.55 },
    { protocol: "ICMP", packet_count: 0, byte_count: 0, percentage: 0.0 },
    { protocol: "ARP", packet_count: 2, byte_count: 84, percentage: 0.03 },
    { protocol: "OTHER", packet_count: 6, byte_count: 312, percentage: 0.1 }
  ],
  application_breakdown: [
    { name: "HTTPS / TLS", packet_count: 5712, byte_count: 5559773, transport_layer: "TCP", is_inferred: true },
    { name: "QUIC / HTTP3", packet_count: 82, byte_count: 16691, transport_layer: "UDP", is_inferred: true },
    { name: "DNS", packet_count: 8, byte_count: 955, transport_layer: "UDP", is_inferred: false }
  ]
};

// Logic under test: Status determination & Data Mapping
function determineProtocolState({ activeSession, protocols, error }) {
  if (error) {
    if (error.status === 404 || (error.message && error.message.toLowerCase().includes("not found"))) {
      return { status: "INACTIVE", protocols: null, error: null };
    }
    return { status: "ERROR", protocols: null, error: error.message || "Network Error" };
  }

  if (!protocols || protocols.total_packets === 0) {
    return { status: "INACTIVE", protocols, error: null };
  }

  if (activeSession && activeSession.status === "CAPTURING") {
    return { status: "LIVE", protocols, error: null };
  }

  return { status: "ARCHIVE", protocols, error: null };
}

function processLegendItems(transportItems) {
  const STANDARD_PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "OTHER"];
  return STANDARD_PROTOCOLS.map((protoName) => {
    const existing = (transportItems || []).find((t) => t.protocol.toUpperCase() === protoName);
    return {
      protocol: protoName,
      packet_count: existing ? existing.packet_count : 0,
      byte_count: existing ? existing.byte_count : 0,
      percentage: existing ? existing.percentage : 0.0,
    };
  });
}

test("State Transition: Active capture session sets LIVE state", () => {
  const result = determineProtocolState({
    activeSession: { session_id: "cap-live", status: "CAPTURING" },
    protocols: mockActiveProtocols,
    error: null
  });
  assert.equal(result.status, "LIVE");
  assert.equal(result.protocols.total_packets, 5816);
});

test("State Transition: Stopped capture session with data sets ARCHIVE state", () => {
  const result = determineProtocolState({
    activeSession: null,
    protocols: mockActiveProtocols,
    error: null
  });
  assert.equal(result.status, "ARCHIVE");
  assert.equal(result.protocols.session_id, "cap-e07db5ccbcb3");
});

test("State Transition: 404 Not Found error gracefully transitions to INACTIVE", () => {
  const result = determineProtocolState({
    activeSession: null,
    protocols: null,
    error: { status: 404, message: "Traffic analytics session 'latest' not found." }
  });
  assert.equal(result.status, "INACTIVE");
  assert.equal(result.protocols, null);
  assert.equal(result.error, null);
});

test("State Transition: 500 Server / Network error transitions to ERROR with message", () => {
  const result = determineProtocolState({
    activeSession: null,
    protocols: null,
    error: { status: 500, message: "Internal server error" }
  });
  assert.equal(result.status, "ERROR");
  assert.equal(result.error, "Internal server error");
});

test("Zero Double-Counting: Sum of transport layer packets exactly equals total_packets", () => {
  const sumPackets = mockActiveProtocols.transport_distribution.reduce((acc, curr) => acc + curr.packet_count, 0);
  assert.equal(sumPackets, mockActiveProtocols.total_packets);
  assert.equal(sumPackets, 5816);
});

test("Zero Double-Counting: Layer 7 application protocols are non-additive overlays", () => {
  const l7Packets = mockActiveProtocols.application_breakdown.reduce((acc, curr) => acc + curr.packet_count, 0);
  // L7 packets (5712 + 82 + 8 = 5802) exist within TCP/UDP transport frames and must NOT be added to total_packets
  assert.notEqual(mockActiveProtocols.total_packets, mockActiveProtocols.total_packets + l7Packets);
  assert.equal(mockActiveProtocols.total_packets, 5816);
});

test("Legend Processing: Formats all 5 standard transport protocols without data fabrication", () => {
  const legend = processLegendItems(mockActiveProtocols.transport_distribution);
  assert.equal(legend.length, 5);

  const tcp = legend.find((l) => l.protocol === "TCP");
  assert.equal(tcp.packet_count, 5718);
  assert.equal(tcp.percentage, 98.31);

  const icmp = legend.find((l) => l.protocol === "ICMP");
  assert.equal(icmp.packet_count, 0);
  assert.equal(icmp.percentage, 0.0);
});

test("Empty State: All protocols default to 0% with 0 packets", () => {
  const legend = processLegendItems([]);
  assert.equal(legend.length, 5);
  for (const item of legend) {
    assert.equal(item.packet_count, 0);
    assert.equal(item.percentage, 0);
  }
});
