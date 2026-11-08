import collections
import statistics
import threading
from typing import Deque, Optional


class SessionBaselineManager:
    """Session-aware behavioral baseline tracker with explicit warm-up states.

    Requires sufficient empirical observations before activating anomaly rules.
    """

    def __init__(self, session_id: str, min_samples: int = 10, max_samples: int = 300):
        self.session_id = session_id
        self.min_samples = min_samples
        self.max_samples = max_samples
        self._lock = threading.RLock()

        self._bps_history: Deque[float] = collections.deque(maxlen=max_samples)
        self._pps_history: Deque[float] = collections.deque(maxlen=max_samples)
        self._dns_history: Deque[float] = collections.deque(maxlen=max_samples)

    @property
    def status(self) -> str:
        with self._lock:
            if len(self._bps_history) >= self.min_samples:
                return "ACTIVE"
            return "WARMING_UP"

    @property
    def sample_count(self) -> int:
        with self._lock:
            return len(self._bps_history)

    def is_ready(self) -> bool:
        """True if sufficient samples have been recorded to evaluate deviations."""
        return self.status == "ACTIVE"

    def feed_sample(self, bps: float, pps: float, dns_rate: float = 0.0) -> None:
        """Appends a 1-second sample to the rolling baseline history."""
        with self._lock:
            self._bps_history.append(max(0.0, float(bps)))
            self._pps_history.append(max(0.0, float(pps)))
            self._dns_history.append(max(0.0, float(dns_rate)))

    def get_stats(self) -> dict:
        """Computes mean and standard deviation across rolling history."""
        with self._lock:
            if len(self._bps_history) < 2:
                mean_bps = self._bps_history[0] if self._bps_history else 0.0
                mean_pps = self._pps_history[0] if self._pps_history else 0.0
                return {
                    "mean_bps": mean_bps,
                    "std_bps": 0.0,
                    "mean_pps": mean_pps,
                    "std_pps": 0.0,
                    "samples": len(self._bps_history),
                    "status": self.status,
                }

            mean_bps = statistics.mean(self._bps_history)
            std_bps = statistics.stdev(self._bps_history)
            mean_pps = statistics.mean(self._pps_history)
            std_pps = statistics.stdev(self._pps_history)

            return {
                "mean_bps": round(mean_bps, 2),
                "std_bps": round(std_bps, 2),
                "mean_pps": round(mean_pps, 2),
                "std_pps": round(std_pps, 2),
                "samples": len(self._bps_history),
                "status": self.status,
            }

    def reset(self) -> None:
        """Resets baseline samples."""
        with self._lock:
            self._bps_history.clear()
            self._pps_history.clear()
            self._dns_history.clear()
