"""Résolution DNS.

Trois exigences qui justifient de ne pas appeler `dns.resolver` directement :

1. **Ne jamais lever d'exception.** Un audit doit rendre un rapport même quand
   la moitié des requêtes échoue. Les erreurs sont des données (`DnsRecordSet.
   error`), pas des interruptions : « aucun DMARC » et « le résolveur n'a pas
   répondu » mènent à des conclusions opposées.

2. **Concaténer correctement les chaînes TXT.** Un enregistrement TXT est
   découpé en fragments de 255 octets maximum, qui doivent être recollés sans
   séparateur (RFC 7208 §3.3, RFC 6376 §3.6.2.2). Une clé DKIM de 2048 bits est
   *toujours* fragmentée : la lire fragment par fragment produit une clé
   invalide et un faux constat.

3. **Mémoriser les réponses.** L'arbre `include:` d'un SPF réel contient
   massivement des doublons ; sans cache, l'analyse d'un domaine émet des
   centaines de requêtes redondantes.
"""

from __future__ import annotations

import threading
from typing import Final

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.rrset

from ..config import DOH_ENDPOINTS, Settings
from ..models import DnsRecordSet

#: Types pour lesquels un repli DNS-over-HTTPS est tenté si le port 53 échoue.
_DOH_RETRY_ERRORS: Final = ("timeout", "no_nameservers")


class DnsResolver:
    """Résolveur DNS thread-safe, avec cache et repli DoH."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._cache: dict[tuple[str, str], DnsRecordSet] = {}
        self._lock = threading.Lock()
        self._query_count = 0
        self._doh_used = False

        resolver = dns.resolver.Resolver(configure=not settings.resolvers)
        if settings.resolvers:
            resolver.nameservers = list(settings.resolvers)
        resolver.timeout = settings.dns_timeout
        resolver.lifetime = settings.dns_lifetime
        # DO=1 demande la validation DNSSEC au résolveur amont ; le drapeau AD
        # de la réponse nous dira si la zone est signée et validée.
        resolver.use_edns(0, dns.flags.DO, 1232)
        self._resolver = resolver

    # -- statistiques -------------------------------------------------------

    @property
    def query_count(self) -> int:
        """Nombre de requêtes réellement émises (hors cache)."""
        return self._query_count

    @property
    def doh_used(self) -> bool:
        """Vrai si au moins une requête a dû passer par DNS-over-HTTPS."""
        return self._doh_used

    # -- API principale -----------------------------------------------------

    def query(self, name: str, rtype: str) -> DnsRecordSet:
        """Interroge le DNS. Ne lève jamais : les erreurs sont dans le résultat."""
        name = name.rstrip(".").lower()
        key = (name, rtype.upper())

        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached

        result = self._query_uncached(name, rtype.upper())

        with self._lock:
            self._cache[key] = result
        return result

    # Les quatre accesseurs ci-dessous forment le protocole `DnsLookup` attendu
    # par la couche d'analyse (cf. `analyze.lookup`). La conformité est
    # structurelle : aucun module d'analyse n'importe cette classe, ce qui
    # permet de lui substituer un résolveur de test sans réseau.

    def txt(self, name: str) -> list[str]:
        """Enregistrements TXT, chaque enregistrement déjà recollé."""
        return self.query(name, "TXT").values

    def a(self, name: str) -> list[str]:
        return self.query(name, "A").values

    def aaaa(self, name: str) -> list[str]:
        return self.query(name, "AAAA").values

    def mx(self, name: str) -> list[str]:
        """Enregistrements MX, au format « préférence hôte »."""
        return self.query(name, "MX").values

    def exists(self, name: str) -> bool:
        """Vrai si le nom existe (A, AAAA ou CNAME)."""
        for rtype in ("A", "AAAA", "CNAME"):
            rrset = self.query(name, rtype)
            if rrset.ok and rrset.values:
                return True
        return False

    def is_dnssec_signed(self, name: str) -> bool:
        """Vrai si la zone est signée et validée par le résolveur amont.

        On s'appuie sur le drapeau AD plutôt que sur la seule présence d'un DS :
        un DS orphelin ou une chaîne rompue laisserait croire à tort que le
        domaine est protégé.
        """
        try:
            qname = dns.name.from_text(name)
            query = dns.message.make_query(qname, dns.rdatatype.SOA, want_dnssec=True)
            nameserver = (self._settings.resolvers or ("1.1.1.1",))[0]
            response = dns.query.udp(
                query, nameserver, timeout=self._settings.dns_timeout
            )
            self._count()
            return bool(response.flags & dns.flags.AD)
        except Exception:
            return False

    # -- implémentation -----------------------------------------------------

    def _count(self) -> None:
        with self._lock:
            self._query_count += 1

    def _query_uncached(self, name: str, rtype: str) -> DnsRecordSet:
        self._count()
        try:
            answer = self._resolver.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return DnsRecordSet(name=name, rtype=rtype, error="NXDOMAIN")
        except dns.resolver.NoAnswer:
            return DnsRecordSet(name=name, rtype=rtype)
        except dns.resolver.NoNameservers:
            return self._maybe_doh(name, rtype, "no_nameservers")
        except dns.exception.Timeout:
            return self._maybe_doh(name, rtype, "timeout")
        except dns.name.LabelTooLong:
            return DnsRecordSet(name=name, rtype=rtype, error="nom_invalide")
        except Exception as exc:  # pragma: no cover - garde-fou
            return DnsRecordSet(name=name, rtype=rtype, error=f"{type(exc).__name__}")

        if answer.rrset is None:
            return DnsRecordSet(name=name, rtype=rtype)

        return DnsRecordSet(
            name=name,
            rtype=rtype,
            values=_render_rrset(answer.rrset, rtype),
            ttl=answer.rrset.ttl,
        )

    def _maybe_doh(self, name: str, rtype: str, error: str) -> DnsRecordSet:
        """Repli DNS-over-HTTPS lorsque le port 53 sortant est filtré."""
        if not self._settings.doh_enabled or error not in _DOH_RETRY_ERRORS:
            return DnsRecordSet(name=name, rtype=rtype, error=error)

        for endpoint in DOH_ENDPOINTS:
            try:
                query = dns.message.make_query(
                    dns.name.from_text(name), dns.rdatatype.from_text(rtype)
                )
                response = dns.query.https(
                    query, endpoint, timeout=self._settings.http_timeout
                )
                self._count()
                self._doh_used = True
            except Exception:
                continue

            if response.rcode() == dns.rcode.NXDOMAIN:
                return DnsRecordSet(name=name, rtype=rtype, error="NXDOMAIN")

            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.from_text(rtype):
                    return DnsRecordSet(
                        name=name,
                        rtype=rtype,
                        values=_render_rrset(rrset, rtype),
                        ttl=rrset.ttl,
                    )
            return DnsRecordSet(name=name, rtype=rtype)

        return DnsRecordSet(name=name, rtype=rtype, error=error)


def _render_rrset(rrset: dns.rrset.RRset, rtype: str) -> list[str]:
    """Rend un jeu d'enregistrements sous forme de chaînes exploitables."""
    values: list[str] = []

    for rdata in rrset:
        if rtype == "TXT":
            # Recollage des fragments de 255 octets, sans séparateur.
            joined = b"".join(rdata.strings)
            values.append(joined.decode("utf-8", errors="replace"))
        elif rtype == "MX":
            # Le « null MX » de la RFC 7505 est l'enregistrement « 0 . » : il
            # déclare que le domaine n'accepte aucun courrier. Retirer le point
            # racine le rendrait indistinguable d'un hôte vide, donc d'une
            # erreur de configuration — deux constats opposés.
            exchange = rdata.exchange.to_text()
            exchange = "." if exchange == "." else exchange.rstrip(".")
            values.append(f"{rdata.preference} {exchange}")
        elif rtype == "CAA":
            tag = rdata.tag.decode() if isinstance(rdata.tag, bytes) else str(rdata.tag)
            value = (
                rdata.value.decode(errors="replace")
                if isinstance(rdata.value, bytes)
                else str(rdata.value)
            )
            values.append(f"{rdata.flags} {tag} {value}")
        elif rtype in ("NS", "CNAME", "PTR"):
            values.append(rdata.target.to_text().rstrip("."))
        elif rtype == "SOA":
            values.append(
                f"{rdata.mname.to_text().rstrip('.')} {rdata.rname.to_text().rstrip('.')} "
                f"{rdata.serial} {rdata.refresh} {rdata.retry} {rdata.expire} {rdata.minimum}"
            )
        else:
            values.append(rdata.to_text())

    return values


def parse_mx_value(value: str) -> tuple[int, str]:
    """Découpe « 10 mx.example.com » en (préférence, hôte).

    L'hôte « . » d'un null MX est préservé tel quel.
    """
    preference_raw, _, hostname = value.partition(" ")
    try:
        preference = int(preference_raw)
    except ValueError:
        return 0, value.strip().lower()

    hostname = hostname.strip().lower()
    if hostname == ".":
        return preference, "."
    return preference, hostname.rstrip(".")


def is_null_mx(records: list[str]) -> bool:
    """Vrai si le domaine déclare explicitement n'accepter aucun courrier."""
    if len(records) != 1:
        return False
    preference, hostname = parse_mx_value(records[0])
    return preference == 0 and hostname in (".", "")
