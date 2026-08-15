"""Client RDAP (RFC 7482/7483) pour les domaines et les adresses IP.

RDAP est privilégié sur WHOIS : la réponse est du JSON structuré et daté, là où
WHOIS renvoie du texte libre dont le format varie d'un registre à l'autre. Le
WHOIS textuel reste utilisé en repli (`whois_raw`), notamment pour les TLD qui
n'exposent pas encore de service RDAP.

L'amorçage passe par les fichiers officiels de l'IANA, mis en cache sur disque.
On évite ainsi de dépendre d'un redirecteur tiers pour un outil d'audit.
"""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Any

from dateutil import parser as date_parser

from ..models import RegistrationInfo
from .http import HttpClient

_BOOTSTRAP_URLS = {
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
}

#: Le fichier d'amorçage IANA évolue très lentement ; une semaine de cache est
#: largement suffisante et évite un aller-retour réseau à chaque exécution.
_BOOTSTRAP_TTL = 7 * 24 * 3600

#: Redirecteur communautaire, utilisé uniquement si l'amorçage IANA échoue.
_FALLBACK_BASE = "https://rdap.org"


class RdapClient:
    """Interrogation RDAP avec amorçage IANA mis en cache."""

    def __init__(self, http: HttpClient, cache_dir: Path) -> None:
        self._http = http
        self._cache_dir = cache_dir
        self._bootstrap: dict[str, dict[str, str]] = {}

    # -- domaines -----------------------------------------------------------

    def domain(self, domain: str) -> RegistrationInfo:
        """Récupère et normalise les données d'enregistrement d'un domaine."""
        domain = domain.strip().rstrip(".").lower()
        payload = self._fetch_domain(domain)
        if payload is None:
            return RegistrationInfo(source="none", error="aucun service RDAP n'a répondu")
        return _parse_domain(payload)

    def _fetch_domain(self, domain: str) -> dict[str, Any] | None:
        tld = domain.rsplit(".", 1)[-1]
        base = self._lookup_bootstrap("dns", tld)
        if base:
            payload = self._http.get_json(f"{base.rstrip('/')}/domain/{domain}")
            if isinstance(payload, dict):
                return payload
        payload = self._http.get_json(f"{_FALLBACK_BASE}/domain/{domain}")
        return payload if isinstance(payload, dict) else None

    # -- adresses IP --------------------------------------------------------

    def ip(self, address: str) -> dict[str, Any] | None:
        """Retourne l'objet RDAP brut décrivant la plage contenant cette IP."""
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return None

        family = "ipv4" if parsed.version == 4 else "ipv6"
        base = self._lookup_bootstrap_ip(family, parsed)
        if base:
            payload = self._http.get_json(f"{base.rstrip('/')}/ip/{address}")
            if isinstance(payload, dict):
                return payload
        payload = self._http.get_json(f"{_FALLBACK_BASE}/ip/{address}")
        return payload if isinstance(payload, dict) else None

    # -- amorçage -----------------------------------------------------------

    def _bootstrap_file(self, kind: str) -> dict[str, Any] | None:
        """Charge un fichier d'amorçage IANA, depuis le cache disque si frais."""
        cache_path = self._cache_dir / f"rdap-{kind}.json"
        try:
            if cache_path.is_file() and (time.time() - cache_path.stat().st_mtime) < _BOOTSTRAP_TTL:
                return json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass

        payload = self._http.get_json(_BOOTSTRAP_URLS[kind])
        if not isinstance(payload, dict):
            return None

        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            pass  # cache indisponible : sans conséquence fonctionnelle
        return payload

    def _lookup_bootstrap(self, kind: str, key: str) -> str | None:
        """Résout un TLD vers l'URL de base de son service RDAP."""
        if kind not in self._bootstrap:
            payload = self._bootstrap_file(kind)
            table: dict[str, str] = {}
            if payload:
                for entry in payload.get("services", []):
                    if len(entry) < 2 or not entry[1]:
                        continue
                    url = entry[1][0]
                    for item in entry[0]:
                        table[item.lower()] = url
            self._bootstrap[kind] = table
        return self._bootstrap[kind].get(key.lower())

    def _lookup_bootstrap_ip(
        self, family: str, address: ipaddress.IPv4Address | ipaddress.IPv6Address
    ) -> str | None:
        """Résout une IP vers l'URL du RIR compétent, par plus long préfixe."""
        payload = self._bootstrap_file(family)
        if not payload:
            return None

        best_url: str | None = None
        best_length = -1
        for entry in payload.get("services", []):
            if len(entry) < 2 or not entry[1]:
                continue
            for cidr in entry[0]:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if address in network and network.prefixlen > best_length:
                    best_length = network.prefixlen
                    best_url = entry[1][0]
        return best_url


# ---------------------------------------------------------------------------
# Normalisation des réponses
# ---------------------------------------------------------------------------


def _parse_domain(payload: dict[str, Any]) -> RegistrationInfo:
    info = RegistrationInfo(source="rdap")

    for event in payload.get("events", []) or []:
        action = str(event.get("eventAction", "")).lower()
        date = _parse_date(event.get("eventDate"))
        if date is None:
            continue
        if action == "registration":
            info.created = date
        elif action == "expiration":
            info.expires = date
        elif action in ("last changed", "last update of rdap database"):
            info.updated = info.updated or date

    for entity in payload.get("entities", []) or []:
        roles = {str(r).lower() for r in entity.get("roles", []) or []}
        name = _vcard_field(entity, "fn")
        if "registrar" in roles and name:
            info.registrar = name
        if "registrant" in roles:
            info.registrant = info.registrant or name
            info.registrant_country = info.registrant_country or _vcard_country(entity)
        if "abuse" in roles:
            info.abuse_email = info.abuse_email or _vcard_field(entity, "email")
        # Le contact abuse du registrar est souvent imbriqué d'un niveau.
        for nested in entity.get("entities", []) or []:
            nested_roles = {str(r).lower() for r in nested.get("roles", []) or []}
            if "abuse" in nested_roles:
                info.abuse_email = info.abuse_email or _vcard_field(nested, "email")

    info.nameservers = sorted(
        {
            str(ns.get("ldhName", "")).rstrip(".").lower()
            for ns in payload.get("nameservers", []) or []
            if ns.get("ldhName")
        }
    )
    info.statuses = [str(s) for s in payload.get("status", []) or []]

    secure_dns = payload.get("secureDNS")
    if isinstance(secure_dns, dict):
        signed = secure_dns.get("delegationSigned")
        if isinstance(signed, bool):
            info.dnssec_signed = signed

    return info


def _parse_date(value: Any) -> Any | None:
    if not value:
        return None
    try:
        return date_parser.isoparse(str(value))
    except (ValueError, TypeError):
        try:
            return date_parser.parse(str(value))
        except (ValueError, TypeError, OverflowError):
            return None


def _vcard_entries(entity: dict[str, Any]) -> list[list[Any]]:
    """Extrait les entrées jCard (RFC 7095) d'une entité RDAP."""
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return []
    return [entry for entry in vcard[1] if isinstance(entry, list) and len(entry) >= 4]


def _vcard_field(entity: dict[str, Any], field: str) -> str | None:
    for entry in _vcard_entries(entity):
        if str(entry[0]).lower() == field:
            value = entry[3]
            if isinstance(value, list):
                value = " ".join(str(part) for part in value if part)
            text = str(value).strip()
            if text:
                return text
    return None


def _vcard_country(entity: dict[str, Any]) -> str | None:
    """Le pays d'une adresse jCard est le 7e élément du tableau structuré."""
    for entry in _vcard_entries(entity):
        if str(entry[0]).lower() != "adr":
            continue
        value = entry[3]
        if isinstance(value, list) and len(value) >= 7 and value[6]:
            return str(value[6]).strip()
        params = entry[1] if isinstance(entry[1], dict) else {}
        if params.get("cc"):
            return str(params["cc"]).strip()
    return None


def parse_ip_object(payload: dict[str, Any]) -> dict[str, Any]:
    """Réduit une réponse RDAP d'IP aux champs utiles au profilage."""
    abuse_email: str | None = None
    org: str | None = None
    for entity in payload.get("entities", []) or []:
        roles = {str(r).lower() for r in entity.get("roles", []) or []}
        if "abuse" in roles:
            abuse_email = abuse_email or _vcard_field(entity, "email")
        if roles & {"registrant", "administrative", "technical"}:
            org = org or _vcard_field(entity, "fn")
        for nested in entity.get("entities", []) or []:
            nested_roles = {str(r).lower() for r in nested.get("roles", []) or []}
            if "abuse" in nested_roles:
                abuse_email = abuse_email or _vcard_field(nested, "email")

    return {
        "handle": payload.get("handle"),
        "netname": payload.get("name"),
        "start_address": payload.get("startAddress"),
        "end_address": payload.get("endAddress"),
        "country": payload.get("country"),
        "type": payload.get("type"),
        "organization": org,
        "abuse_email": abuse_email,
    }
