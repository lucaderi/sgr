from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class NetSession:
    """
    Stato condiviso dell'applicazione

    Ogni tab riceve la stessa istanza di ``NetSession`` cosi che legga la stessa KB e le stesse info di sessione.

    """

    # ── Workspace & configurazione ───────────────────────────────────────────
    workspace: dict[str, Any] = None
    active_ip: Optional[str] = None
    current_view: str = "chat"
