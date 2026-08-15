"""Contrat de résolution DNS attendu par la couche d'analyse.

Protocole structurel : `net.resolver.DnsResolver` s'y conforme sans le savoir
ni l'importer. Les tests fournissent une implémentation adossée à un
dictionnaire, ce qui rend les analyses déterministes et hors ligne.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class DnsLookup(Protocol):
    """Accès en lecture aux seuls types dont l'analyse a besoin."""

    def txt(self, name: str) -> list[str]:
        """Enregistrements TXT, fragments déjà recollés."""
        ...

    def a(self, name: str) -> list[str]:
        """Adresses IPv4."""
        ...

    def aaaa(self, name: str) -> list[str]:
        """Adresses IPv6."""
        ...

    def mx(self, name: str) -> list[str]:
        """Enregistrements MX, au format « préférence hôte »."""
        ...


class StaticLookup:
    """Implémentation figée, alimentée par un dictionnaire.

    Destinée aux tests et au rejeu d'une analyse à partir de données
    enregistrées. Un nom absent de la table est traité comme inexistant, ce
    qui correspond au comportement d'un NXDOMAIN.
    """

    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self._records = {(name.rstrip(".").lower(), rtype.upper()): values
                         for (name, rtype), values in records.items()}

    def _get(self, name: str, rtype: str) -> list[str]:
        return list(self._records.get((name.rstrip(".").lower(), rtype.upper()), []))

    def txt(self, name: str) -> list[str]:
        return self._get(name, "TXT")

    def a(self, name: str) -> list[str]:
        return self._get(name, "A")

    def aaaa(self, name: str) -> list[str]:
        return self._get(name, "AAAA")

    def mx(self, name: str) -> list[str]:
        return self._get(name, "MX")
