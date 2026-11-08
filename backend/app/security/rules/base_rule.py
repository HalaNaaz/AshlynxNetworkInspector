import abc
from datetime import datetime, timezone
from typing import Dict, Optional
from backend.app.schemas.security import RuleConfigItem, SecurityEventItem


class BaseSecurityRule(abc.ABC):
    """Abstract base class for all passive security detection rules."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        category: str,
        description: str,
        threshold: float,
        window_seconds: int = 10,
        cooldown_seconds: int = 30,
        severity_default: str = "MEDIUM",
        enabled: bool = True,
        is_baseline_dependent: bool = False,
        web_port_threshold: Optional[float] = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.description = description
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.severity_default = severity_default
        self.enabled = enabled
        self.is_baseline_dependent = is_baseline_dependent
        self.web_port_threshold = web_port_threshold

        # Entity deduplication & cooldown tracking (e.g. key: "src_ip" -> last_timestamp)
        self._last_triggered: Dict[str, float] = {}

    def is_in_cooldown(self, entity_key: str, current_epoch: float) -> bool:
        """Returns True if the entity recently triggered an alert within cooldown period."""
        if entity_key in self._last_triggered:
            elapsed = current_epoch - self._last_triggered[entity_key]
            if elapsed < self.cooldown_seconds:
                return True
        return False

    def record_trigger(self, entity_key: str, current_epoch: float) -> None:
        """Records trigger timestamp for alert deduplication and suppression."""
        self._last_triggered[entity_key] = current_epoch

    def update_config(
        self,
        enabled: Optional[bool] = None,
        threshold: Optional[float] = None,
        window_seconds: Optional[int] = None,
        cooldown_seconds: Optional[int] = None,
        web_port_threshold: Optional[float] = None,
    ) -> None:
        """Safely updates rule operational parameters."""
        if enabled is not None:
            self.enabled = enabled
        if threshold is not None and threshold > 0:
            self.threshold = threshold
        if window_seconds is not None and 1 <= window_seconds <= 3600:
            self.window_seconds = window_seconds
        if cooldown_seconds is not None and 1 <= cooldown_seconds <= 86400:
            self.cooldown_seconds = cooldown_seconds
        if web_port_threshold is not None and web_port_threshold > 0:
            self.web_port_threshold = web_port_threshold

    def to_config(self) -> RuleConfigItem:
        """Serializes current rule configuration."""
        return RuleConfigItem(
            rule_id=self.rule_id,
            name=self.name,
            category=self.category,
            description=self.description,
            enabled=self.enabled,
            threshold=self.threshold,
            window_seconds=self.window_seconds,
            cooldown_seconds=self.cooldown_seconds,
            severity_default=self.severity_default,
            is_baseline_dependent=self.is_baseline_dependent,
            web_port_threshold=self.web_port_threshold,
        )

    @abc.abstractmethod
    def evaluate(self, meta, session_id: str, baseline_manager=None) -> Optional[SecurityEventItem]:
        """Evaluates incoming packet metadata against the rule logic."""
        pass

