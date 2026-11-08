import math
from typing import Tuple

SEVERITY_BANDS = {
    "INFO": (0, 19),
    "LOW": (20, 39),
    "MEDIUM": (40, 69),
    "HIGH": (70, 89),
    "CRITICAL": (90, 100),
}


class RiskScorer:
    """Calculates explainable, deterministic risk scores and severity classifications.

    Maintains explicit separation between Severity (potential impact) and Confidence (evidence certainty).
    """

    BASE_SCORES = {
        "INFO": 10,
        "LOW": 30,
        "MEDIUM": 55,
        "HIGH": 78,
        "CRITICAL": 92,
    }

    @classmethod
    def calculate_risk_score(
        cls,
        base_severity: str,
        confidence: float,
        observed_ratio: float = 1.0,
        is_correlated: bool = False,
    ) -> Tuple[int, str]:
        """Calculates risk score (0-100) and resulting severity band.

        - base_severity: Rule default severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)
        - confidence: Empirical evidence certainty (0.0 to 1.0)
        - observed_ratio: Ratio of observed value to threshold (>= 1.0)
        - is_correlated: Whether multiple independent rules triggered on this entity
        """
        confidence = max(0.1, min(1.0, confidence))
        base = cls.BASE_SCORES.get(base_severity.upper(), 30)

        # Excess ratio multiplier (capped at 2.0 to prevent runaway scoring)
        excess_multiplier = min(2.0, 1.0 + (math.log(max(1.0, observed_ratio)) * 0.25))

        # Correlation bonus (+10 if multi-vector correlation observed)
        correlation_bonus = 10 if is_correlated else 0

        raw_score = (base * excess_multiplier * (0.5 + (0.5 * confidence))) + correlation_bonus
        final_score = int(max(0, min(100, round(raw_score))))

        # Determine effective severity band
        if final_score >= 90:
            severity = "CRITICAL"
        elif final_score >= 70:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MEDIUM"
        elif final_score >= 20:
            severity = "LOW"
        else:
            severity = "INFO"

        return final_score, severity

