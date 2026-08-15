"""Client WHOIS natif (TCP/43, RFC 3912), utilisé en repli de RDAP.

Implémenté directement sur socket plutôt qu'en appelant un binaire `whois` :
l'outil doit produire le même résultat sur un poste Windows, dans un conteneur
ou sur un runner d'intégration continue, sans dépendance système. Lorsque le
binaire est malgré tout présent, il est utilisé en second recours : il gère
quelques TLD exotiques mieux que notre découverte automatique.

WHOIS n'a pas de format normalisé. L'extraction est donc pilotée par une table
de libellés observés chez les principaux registres, et reste au mieux
« meilleur effort » — d'où la priorité systématiquement donnée à RDAP.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from typing import Final

from dateutil import parser as date_parser

from ..models import RegistrationInfo

_IANA_WHOIS: Final = "whois.iana.org"
_WHOIS_PORT: Final = 43
_READ_LIMIT: Final = 512 * 1024

#: Libellés rencontrés chez les registres, ramenés à un champ normalisé.
#: Les clés sont comparées en minuscules, séparateur « : » retiré.
_FIELD_LABELS: Final[dict[str, str]] = {
    "registrar": "registrar",
    "sponsoring registrar": "registrar",
    "registrar name": "registrar",
    "creation date": "created",
    "created": "created",
    "created on": "created",
    "registered on": "created",
    "domain registration date": "created",
    "registration time": "created",
    "registry expiry date": "expires",
    "expiry date": "expires",
    "expiration date": "expires",
    "registrar registration expiration date": "expires",
    "expires": "expires",
    "expire": "expires",
    "paid-till": "expires",
    "updated date": "updated",
    "last updated": "updated",
    "last-update": "updated",
    "changed": "updated",
    "modified": "updated",
    "registrant organization": "registrant",
    "registrant name": "registrant",
    "registrant": "registrant",
    "org": "registrant",
    "organisation": "registrant",
    "holder": "registrant",
    "registrant country": "country",
    "country": "country",
    "registrar abuse contact email": "abuse_email",
    "abuse-mailbox": "abuse_email",
}

_MULTI_LABELS: Final[dict[str, str]] = {
    "name server": "nameservers",
    "nserver": "nameservers",
    "nameserver": "nameservers",
    "ns": "nameservers",
    "domain status": "statuses",
    "status": "statuses",
    "state": "statuses",
}

#: Réponses de refus. Les détecter évite de présenter « domaine non
#: enregistré » alors que le registre a simplement limité le débit.
_REFUSAL_PATTERNS: Final = re.compile(
    r"(rate.?limit|quota exceeded|too many requests|access denied|"
    r"connection refused|try again later|excessive querying|no match for)",
    re.IGNORECASE,
)


def query_whois(domain: str, *, timeout: float = 10.0) -> RegistrationInfo:
    """Interroge WHOIS et normalise le résultat."""
    domain = domain.strip().rstrip(".").lower()
    tld = domain.rsplit(".", 1)[-1]

    server = _discover_server(tld, timeout=timeout)
    raw = _ask(server, domain, timeout=timeout) if server else None

    # Le registre renvoie souvent une redirection vers le WHOIS du bureau
    # d'enregistrement, seul à détenir les coordonnées du titulaire.
    if raw:
        referral = _extract_referral(raw)
        if referral and referral != server:
            detailed = _ask(referral, domain, timeout=timeout)
            if detailed and len(detailed) > len(raw) // 2:
                raw = detailed

    if not raw:
        raw = _system_whois(domain, timeout=timeout)

    if not raw:
        return RegistrationInfo(source="none", error="aucun serveur WHOIS n'a répondu")

    if _REFUSAL_PATTERNS.search(raw) and len(raw) < 800:
        return RegistrationInfo(
            source="whois",
            raw=raw,
            error="le registre a refusé la requête (limitation de débit ou domaine absent)",
        )

    return _parse(raw)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


def _ask(server: str, query: str, *, timeout: float) -> str | None:
    """Une transaction WHOIS : ouvrir, envoyer, lire jusqu'à fermeture."""
    try:
        with socket.create_connection((server, _WHOIS_PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(f"{query}\r\n".encode())
            chunks: list[bytes] = []
            total = 0
            while total < _READ_LIMIT:
                data = sock.recv(8192)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
    except (TimeoutError, OSError):
        return None

    return b"".join(chunks).decode("utf-8", errors="replace")


def _discover_server(tld: str, *, timeout: float) -> str | None:
    """Demande à l'IANA quel serveur WHOIS fait autorité pour ce TLD."""
    response = _ask(_IANA_WHOIS, tld, timeout=timeout)
    if not response:
        return None
    match = re.search(r"^\s*whois:\s*(\S+)", response, re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else None


def _extract_referral(raw: str) -> str | None:
    match = re.search(
        r"^\s*(?:Registrar WHOIS Server|whois server|ReferralServer):\s*"
        r"(?:whois://)?(\S+?)\s*$",
        raw,
        re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        return None
    return match.group(1).strip().rstrip(".").lower() or None


def _system_whois(domain: str, *, timeout: float) -> str | None:
    """Repli sur le binaire `whois` du système, s'il est installé."""
    binary = shutil.which("whois")
    if not binary:
        return None
    try:
        result = subprocess.run(
            [binary, domain],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout or None


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _parse(raw: str) -> RegistrationInfo:
    info = RegistrationInfo(source="whois", raw=raw)
    nameservers: set[str] = set()
    statuses: list[str] = []

    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith(("%", "#", ">>>")):
            continue
        label, sep, value = line.partition(":")
        if not sep:
            continue
        label = label.strip().lower()
        value = value.strip()
        if not value:
            continue

        if (multi := _MULTI_LABELS.get(label)) is not None:
            if multi == "nameservers":
                # Certains registres ajoutent l'adresse IP après le nom.
                nameservers.add(value.split()[0].rstrip(".").lower())
            else:
                statuses.append(value)
            continue

        field = _FIELD_LABELS.get(label)
        if field is None:
            continue

        if field in ("created", "expires", "updated"):
            parsed = _parse_date(value)
            if parsed and getattr(info, field) is None:
                setattr(info, field, parsed)
        elif getattr(info, field, None) in (None, ""):
            setattr(info, field if field != "country" else "registrant_country", value)

    info.nameservers = sorted(nameservers)
    info.statuses = _dedupe(statuses)
    if "signeddelegation" in raw.lower().replace(" ", "") or "dnssec: signed" in raw.lower():
        info.dnssec_signed = True
    elif "dnssec: unsigned" in raw.lower():
        info.dnssec_signed = False
    return info


def _parse_date(value: str) -> object | None:
    # Nettoie les suffixes courants (« 2019-04-11T12:00:00Z (UTC) »).
    cleaned = re.sub(r"\s*\((?:UTC|GMT)[^)]*\)\s*$", "", value).strip()
    for candidate in (cleaned, cleaned.split()[0] if cleaned else ""):
        if not candidate:
            continue
        try:
            return date_parser.parse(candidate, fuzzy=False)
        except (ValueError, TypeError, OverflowError):
            continue
    return None


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.lower()
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result
