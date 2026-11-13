from collections import Counter
from collections.abc import Mapping
from enum import Enum
import json
from math import isfinite
from pathlib import Path

from firewall.engine.policy_decision import PolicyAction, PolicyDecision
from firewall.schemas.capture_analysis import CaptureAnalysis
from firewall.schemas.flow_analysis import PEAK_PACKET_RATE_WINDOW_SECONDS
from firewall.schemas.packet_analysis import CheckStatus

# --- CONSOLE OUTPUT ---

def print_decisions(decisions: Mapping[int, PolicyDecision]) -> None:
    print("Hybrid Multilayer Firewall")
    print(f"{'Packet':>8} {'Flow':>8} {'Decision':<8} {'Rule':<32} Reason")

    for index in sorted(decisions):
        decision = decisions[index]
        flow = str(decision.flow_id) if decision.flow_id is not None else "-"
        rule = decision.rule_id or "-"
        reason = decision.reason or "-"

        if len(reason) > 72:
            reason = reason[:69] + "..."
        
        print(f"{decision.capture_index:>8} {flow:>8} {decision.action.value:<8} {rule:<32} {reason}")


def print_summary(capture: CaptureAnalysis, decisions: Mapping[int, PolicyDecision]) -> None:
    validate_results(capture, decisions)
    summary = capture_summary(capture, decisions)

    print("\n=== CAPTURE SUMMARY ===")
    print(f"Total packets:       {summary['total_packets']}")
    print(f"ALLOW:               {summary['allowed']}")
    print(f"DROP:                {summary['dropped']}")
    print(f"Total flows:         {summary['total_flows']}")
    print(f"Packets without flow: {summary['packets_without_flow']}")
    print("DROP by main rule:")

    for rule_id, count in summary["drop_by_main_rule"].items():
        print(f"  {rule_id}: {count}")


# --- REPORT DATA ---

def validate_results(capture: CaptureAnalysis, decisions: Mapping[int, PolicyDecision]) -> None:
    indexes = {indexed.capture_index for indexed in capture.packets}

    if len(indexes) != len(capture.packets) or indexes != set(decisions):
        raise ValueError("report requires exactly one decision per capture index")

    for index in indexes:
        if index not in capture.packet_analyses or index not in capture.flow_results:
            raise ValueError(f"missing analysis or flow result for packet {index}")
        
        decision = decisions[index]

        if decision.capture_index != index or decision.flow_id != capture.flow_id_for(index):
            raise ValueError(f"inconsistent decision references for packet {index}")
        
        if decision.flow_id is not None and decision.flow_id not in capture.flows:
            raise ValueError(f"missing flow {decision.flow_id} for packet {index}")


def capture_summary(capture: CaptureAnalysis, decisions: Mapping[int, PolicyDecision]) -> dict:
    actions = Counter(decision.action for decision in decisions.values())
    drops = Counter(decision.rule_id for decision in decisions.values() if decision.action == PolicyAction.DROP)

    return {"total_packets": len(capture.packets),
            "allowed": actions[PolicyAction.ALLOW],
            "dropped": actions[PolicyAction.DROP],
            "total_flows": len(capture.flows),
            "packets_without_flow": sum(capture.flow_results[indexed.capture_index].flow_id is None for indexed in capture.packets),
            "drop_by_main_rule": dict(drops),}


def json_value(value: object) -> object:
    if isinstance(value, Enum):
        return json_value(value.value)
    
    if isinstance(value, float) and not isfinite(value):
        return str(value)
    
    if isinstance(value, Mapping):
        return {key: json_value(item) for key, item in value.items()}
    
    if isinstance(value, (tuple, list)):
        return [json_value(item) for item in value]
    
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    
    raise TypeError(f"unsupported report value: {type(value).__name__}")


# --- OPTIONAL JSON EXPORT ---

def export_report(capture: CaptureAnalysis, decisions: Mapping[int, PolicyDecision], output_path: str | Path) -> None:
    validate_results(capture, decisions)
    packets = []
    diagnostic_statuses = {CheckStatus.INVALID, CheckStatus.INCOMPLETE, CheckStatus.NOT_CHECKED}

    for indexed in capture.packets:
        index = indexed.capture_index
        decision = decisions[index]
        analysis = capture.packet_analyses[index]
        result = capture.flow_results[index]
        packets.append({
            "capture_index": index,
            "flow_id": decision.flow_id,
            "decision": decision.action,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "findings": [{"rule_id": finding.rule_id, "reason": finding.reason,
                        "scope": finding.scope, "evidence": finding.evidence}
                        for finding in decision.findings],
            "unevaluated_rule_ids": decision.unevaluated_rule_ids,
            "packet_diagnostics": {key: {"status": check.status, "reason": check.reason}
                                    for key, check in analysis.checks.items() if check.status in diagnostic_statuses},
            "flow_exclusion_reason": result.exclusion_reason,
            "fragmentation": {
                "characteristics": sorted(analysis.characteristics & {
                    "FRAGMENTED_PACKET", "INITIAL_FRAGMENT", "NON_INITIAL_FRAGMENT", "IPV6_ATOMIC_FRAGMENT"}),
                "offset": analysis.network.ip_fragment_offset,
                "more_fragments": analysis.network.ip_more_fragments,
                "ipv6_fragment_header_present": analysis.network.ip_fragment_header_present,
            } if analysis.network.ip_version in (4, 6) else None,
        })

    report = {
        "summary": capture_summary(capture, decisions),
        "decision_semantics": {"flow": "retrospective", "window": "current_event"},
        "flow_packet_rates": {
            str(flow_id): {
                "packets_per_second": flow.packets_per_second,
                "peak_packets_per_second": flow.peak_packets_per_second,
                "peak_window_seconds": PEAK_PACKET_RATE_WINDOW_SECONDS,
            }
            for flow_id, flow in sorted(capture.flows.items())
        },
        "tcp_flows": {
            str(flow_id): flow.tcp_diagnostics()
            for flow_id, flow in sorted(capture.flows.items())
            if flow.key.transport_protocol == "TCP"
        },
        "packets": packets,
    }

    # serialization
    serialized = json.dumps(json_value(report), ensure_ascii=False, allow_nan=False, indent=2)

    Path(output_path).write_text(serialized + "\n", encoding="utf-8")
