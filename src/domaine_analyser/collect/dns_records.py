"""Collecte des enregistrements DNS d'un domaine.

Les requêtes indépendantes partent en parallèle : sur un domaine réel, la
collecte enchaîne une quinzaine d'interrogations dont la latence domine
largement le temps total.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Final

from ..models import DnsRecordSet, MxHost
from ..net.resolver import DnsResolver, parse_mx_value

#: Clé logique -> (préfixe du nom, type). Le préfixe vide désigne le domaine
#: lui-même. Ces noms de clé sont ceux exposés dans le rapport JSON.
RECORD_PLAN: Final[dict[str, tuple[str, str]]] = {
    "A": ("", "A"),
    "AAAA": ("", "AAAA"),
    "MX": ("", "MX"),
    "NS": ("", "NS"),
    "TXT": ("", "TXT"),
    "CNAME": ("", "CNAME"),
    "SOA": ("", "SOA"),
    "CAA": ("", "CAA"),
    "DS": ("", "DS"),
    "DMARC": ("_dmarc", "TXT"),
    "MTA_STS": ("_mta-sts", "TXT"),
    "TLS_RPT": ("_smtp._tls", "TXT"),
    "BIMI": ("default._bimi", "TXT"),
}


def collect_dns(
    resolver: DnsResolver, domain: str, *, max_workers: int = 12
) -> dict[str, DnsRecordSet]:
    """Interroge tous les enregistrements du plan, en parallèle."""
    domain = domain.strip().rstrip(".").lower()

    def fetch(item: tuple[str, tuple[str, str]]) -> tuple[str, DnsRecordSet]:
        key, (prefix, rtype) = item
        name = f"{prefix}.{domain}" if prefix else domain
        return key, resolver.query(name, rtype)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        return dict(pool.map(fetch, RECORD_PLAN.items()))


def collect_caa(resolver: DnsResolver, domain: str) -> tuple[DnsRecordSet, str | None]:
    """Recherche l'enregistrement CAA applicable, en remontant l'arborescence.

    La RFC 8659 §3 impose au valideur de remonter de label en label jusqu'à
    trouver un CAA. Ne regarder que le domaine lui-même conclurait à tort à
    l'absence de contrôle alors qu'un parent en impose un.

    Returns:
        Le jeu d'enregistrements trouvé et, le cas échéant, le domaine dont il
        est hérité (None s'il est publié sur le domaine interrogé).
    """
    domain = domain.strip().rstrip(".").lower()
    labels = domain.split(".")

    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        rrset = resolver.query(candidate, "CAA")
        if rrset.ok and rrset.values:
            return rrset, (candidate if index else None)

    return DnsRecordSet(name=domain, rtype="CAA"), None


def resolve_mx_hosts(
    resolver: DnsResolver, mx_records: list[str], *, max_workers: int = 8
) -> list[MxHost]:
    """Résout chaque hôte MX en adresses, en signalant les cas non conformes.

    Deux anomalies sont détectées ici parce qu'elles exigent une requête
    supplémentaire :

    - un MX pointant vers un CNAME, interdit par la RFC 2181 §10.3 et rejeté
      par certains MTA stricts ;
    - un MX qui ne résout vers aucune adresse, donc un domaine qui ne peut pas
      recevoir de courrier alors qu'il déclare le contraire.
    """
    parsed = [parse_mx_value(value) for value in mx_records]
    hosts = [
        MxHost(preference=preference, hostname=hostname)
        for preference, hostname in parsed
        if hostname not in (".", "")
    ]

    def enrich(host: MxHost) -> MxHost:
        cname = resolver.query(host.hostname, "CNAME")
        host.is_cname = bool(cname.ok and cname.values)

        addresses: list[str] = []
        for rtype in ("A", "AAAA"):
            rrset = resolver.query(host.hostname, rtype)
            if rrset.ok:
                addresses.extend(rrset.values)
        host.addresses = addresses
        host.resolves = bool(addresses)
        return host

    if not hosts:
        return []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        enriched = list(pool.map(enrich, hosts))

    return sorted(enriched, key=lambda h: (h.preference, h.hostname))


def find_txt_prefixed(records: list[str], prefix: str) -> list[str]:
    """Retourne les TXT commençant par un préfixe, comparaison insensible à la casse."""
    lowered = prefix.lower()
    return [value for value in records if value.strip().lower().startswith(lowered)]
