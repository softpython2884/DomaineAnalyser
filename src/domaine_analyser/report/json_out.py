"""Export JSON d'un rapport, destiné à l'outillage.

Format stable : les clés et les codes de constat ne changent pas d'une version
mineure à l'autre, afin qu'un tableau de bord ou un script de supervision
puisse s'y adosser sans se casser à chaque mise à jour.
"""

from __future__ import annotations

import json

from ..models import DomainReport


def render(report: DomainReport, *, indent: int = 2) -> str:
    """Sérialise le rapport en JSON."""
    payload = {"tool": "domaine-analyser", "schema": 1, **report.to_dict()}
    return json.dumps(payload, ensure_ascii=False, indent=indent, default=str)
