from dataclasses import dataclass
from enum import StrEnum

# --- FLOW PROCESS RESULT ---

class FlowExclusionReason(StrEnum):
    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    INVALID_FLOW_KEY = "INVALID_FLOW_KEY"
    INVALID_PACKET_SIZE = "INVALID_PACKET_SIZE"
    NON_INITIAL_FRAGMENT = "NON_INITIAL_FRAGMENT"


@dataclass(frozen=True, slots=True)
class FlowProcessResult:
    # flow_id is set if and only if exclusion_reason is None
    flow_id: int | None
    exclusion_reason: FlowExclusionReason | None = None
