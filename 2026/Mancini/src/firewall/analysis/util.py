from math import isfinite
from typing import TypeGuard

# --- SHARED HELPERS ---

# Scapy flag letter -> descriptive name
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
    "N": "NS",
}

def is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def valid_timestamp(value: object) -> float | None:
    if isinstance(value, bool):
        return None

    if not isinstance(value, (int, float)):
        return None

    try:
        timestamp = float(value)
    except OverflowError:
        # integers too large for a float
        return None

    if not isfinite(timestamp) or timestamp < 0:
        return None

    return timestamp


def tcp_flag_names(raw_flags: str | None) -> frozenset[str]:
    if not raw_flags:
        return frozenset()

    return frozenset(TCP_FLAGS[letter] for letter in raw_flags if letter in TCP_FLAGS)
