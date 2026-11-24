import queue
import time
import pytest
from scapy.layers.inet import IP, TCP

from backend.app.capture.capture_engine import LiveCaptureEngine


def make_mock_packet(seq: int):
    return IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=50000 + seq, dport=80, flags="S")


def test_capture_bounded_queue_isolation():
    """Verifies that LiveCaptureEngine queues packets into a bounded queue without stalling callback."""
    engine = LiveCaptureEngine(
        session_id="test-queue-001",
        interface_id="dummy-if",
        interface_name="eth0",
    )

    # Feed 10 packets via async callback
    for i in range(10):
        pkt = make_mock_packet(i)
        engine._packet_callback(pkt)

    stats = engine.get_statistics()
    assert stats.packets_received == 10
    assert stats.queue_depth == 10
    assert stats.dropped_packets == 0


def test_capture_queue_worker_drains_and_processes():
    """Verifies background processing worker drains the queue and executes metadata & analytics pipeline."""
    engine = LiveCaptureEngine(
        session_id="test-queue-002",
        interface_id="dummy-if",
        interface_name="eth0",
    )

    # Start the worker thread manually (without scapy sniffing loop)
    import threading
    engine.status = "CAPTURING"
    worker = threading.Thread(target=engine._run_processing_loop, daemon=True)
    engine._processing_thread = worker
    worker.start()

    # Enqueue 25 packets
    for i in range(25):
        pkt = make_mock_packet(i)
        engine._packet_callback(pkt)

    # Wait for queue to drain
    engine._packet_queue.join()

    stats = engine.get_statistics()
    assert stats.packets_received == 25
    assert stats.packets_processed == 25
    assert stats.queue_depth == 0
    assert stats.total_captured == 25
    assert stats.tcp_count == 25

    # Stop worker cleanly
    engine._stop_event.set()
    engine._packet_queue.put_nowait(None)
    worker.join(timeout=2.0)


def test_capture_queue_overflow_increments_dropped_packets():
    """Verifies that when the packet queue reaches max capacity, packets are dropped and counted without exception."""
    engine = LiveCaptureEngine(
        session_id="test-queue-overflow",
        interface_id="dummy-if",
        interface_name="eth0",
    )

    # Shrink queue capacity for test
    engine._packet_queue = queue.Queue(maxsize=5)

    # Feed 10 packets without worker running
    for i in range(10):
        pkt = make_mock_packet(i)
        engine._packet_callback(pkt)

    stats = engine.get_statistics()
    assert stats.packets_received == 10
    assert stats.queue_depth == 5
    assert stats.dropped_packets == 5
