from dataclasses import dataclass

from firewall.schemas.packet import Packet

# --- INDEXED PACKET ---

@dataclass(frozen=True, slots=True)
class IndexedPacket:
    capture_index: int  # 1-based position in the captured sequence
    packet: Packet
