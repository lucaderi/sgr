from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

# --- POLICY ENGINE DECISION ---

class PolicyAction(StrEnum):
    ALLOW = "ALLOW"
    DROP = "DROP"

class PolicyScope(StrEnum):
    PACKET = "PACKET"
    FLOW = "FLOW"
    WINDOW = "WINDOW"
    SERVICE = "SERVICE"
    DEFAULT = "DEFAULT"


@dataclass(frozen=True, slots=True)
class PolicyFinding:
    rule_id: str
    reason: str
    scope: PolicyScope
    evidence: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    capture_index: int
    flow_id: int | None
    action: PolicyAction

    # first blocking finding, or the service rule that authorized the packet
    rule_id: str | None
    reason: str | None

    findings: tuple[PolicyFinding, ...]

    # relevant rules that could not be evaluated for this packet
    unevaluated_rule_ids: tuple[str, ...]
