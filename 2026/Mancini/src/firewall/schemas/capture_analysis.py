from collections.abc import Mapping
from dataclasses import dataclass

from firewall.schemas.flow_analysis import FlowAnalysis
from firewall.schemas.flow_process_result import FlowExclusionReason, FlowProcessResult
from firewall.schemas.indexed_packet import IndexedPacket
from firewall.schemas.packet_analysis import PacketAnalysis

# --- CAPTURE ANALYSIS ---

@dataclass(frozen=True, slots=True)
class CaptureAnalysis:
    packets: tuple[IndexedPacket, ...]  # original capture order
    packet_analyses: Mapping[int, PacketAnalysis]
    flow_results: Mapping[int, FlowProcessResult]
    flows: Mapping[int, FlowAnalysis]  # key flow_id

    def flow_id_for(self, capture_index: int) -> int | None:
        result = self.flow_results.get(capture_index)

        if result is None:
            return None

        return result.flow_id

    def flow_for(self, capture_index: int) -> FlowAnalysis | None:
        flow_id = self.flow_id_for(capture_index)

        if flow_id is None:
            return None

        return self.flows.get(flow_id)

    def exclusions(self) -> tuple[tuple[int, FlowExclusionReason], ...]:
        exclusions: list[tuple[int, FlowExclusionReason]] = []

        # iterate packets to preserve original capture order
        for indexed in self.packets:
            result = self.flow_results.get(indexed.capture_index)

            if result is None or result.exclusion_reason is None:
                continue

            exclusions.append((indexed.capture_index, result.exclusion_reason))

        return tuple(exclusions)
