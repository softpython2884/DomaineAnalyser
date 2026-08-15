"""Analyse statique d'une politique SPF (RFC 7208).

Cet analyseur ne répond pas à « cette adresse IP passe-t-elle ? » — c'est le
rôle de `pyspf`, utilisé ailleurs pour rejouer des adresses réelles. Il répond
à deux questions que l'évaluation ne pose jamais :

**La politique est-elle seulement évaluable ?** Au-delà de dix termes
résolvant un nom, la RFC impose au destinataire de rendre `permerror`
(§4.6.4). Le SPF cesse alors de protéger quoi que ce soit, silencieusement :
rien dans le DNS ne signale l'anomalie, et le propriétaire du domaine continue
de croire sa configuration valide. C'est la panne la plus fréquente et la
moins visible, parce qu'elle survient à l'ajout d'un prestataire dont le
propre `include:` en consomme quatre.

**Quelle surface autorise-t-elle réellement ?** Un `include:` déroulé
représente couramment plusieurs centaines de milliers d'adresses. On déroule
donc l'arbre complet, on fusionne les préfixes obtenus, et on compte. « Ce SPF
autorise 3 200 000 adresses à écrire en votre nom » est une information
autrement plus parlante que « SPF : présent ».
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from ..dataload import load_providers
from ..models import SpfAnalysis, SpfMechanism
from .lookup import DnsLookup
from .malformed import diagnose

#: Limite de termes provoquant une résolution DNS (RFC 7208 §4.6.4).
MAX_LOOKUPS = 10

#: Limite de résolutions sans réponse (RFC 7208 §4.6.4).
MAX_VOID_LOOKUPS = 2

#: Nombre maximal d'enregistrements MX exploités par un mécanisme `mx`.
MAX_MX_RECORDS = 10

#: Garde-fou de profondeur, indépendant de la limite de résolutions : un
#: `include:` circulaire doit être signalé, pas provoquer une récursion infinie.
MAX_DEPTH = 15

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Termes consommant une résolution DNS au sens de la RFC.
_LOOKUP_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})

_TERM_RE = re.compile(
    r"^(?P<qualifier>[+\-~?])?(?P<name>[A-Za-z][A-Za-z0-9_.\-]*)(?P<rest>[:/=].*)?$"
)

#: Une macro (%{i}, %{d}…) n'est expansible qu'au moment de l'évaluation, avec
#: l'IP et l'expéditeur réels. En analyse statique on la signale sans la
#: résoudre, plutôt que de produire un résultat faux.
_MACRO_RE = re.compile(r"%\{[^}]*\}")


@dataclass
class _WalkState:
    """État partagé de la descente dans l'arbre SPF."""

    lookups: int = 0
    void_lookups: int = 0
    visited: set[str] = field(default_factory=set)
    networks: list[IpNetwork] = field(default_factory=list)
    mechanisms: list[SpfMechanism] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    circular: list[str] = field(default_factory=list)
    unresolvable: list[str] = field(default_factory=list)
    uses_ptr: bool = False
    uses_macros: bool = False
    all_qualifier: str | None = None
    permit_everything: bool = False


def extract_spf_records(txt_records: list[str]) -> list[str]:
    """Isole les enregistrements SPF parmi les TXT d'un domaine.

    La comparaison est insensible à la casse et tolère les espaces de tête :
    « V=SPF1 ... » est valide et doit être reconnu, faute de quoi on conclurait
    à tort à l'absence de SPF.
    """
    return [value for value in txt_records if value.strip().lower().startswith("v=spf1")]


def analyze_spf(lookup: DnsLookup, domain: str, txt_records: list[str]) -> SpfAnalysis:
    """Analyse la politique SPF publiée par un domaine."""
    domain = domain.strip().rstrip(".").lower()
    records = extract_spf_records(txt_records)

    analysis = SpfAnalysis(all_records=records)
    analysis.malformed = diagnose(txt_records, "v=spf1")

    if not records:
        return analysis

    analysis.present = True
    analysis.raw = records[0]

    if len(records) > 1:
        # RFC 7208 §4.5 : plusieurs enregistrements SPF rendent le résultat
        # `permerror`. La politique est inexploitable, pas simplement
        # dupliquée — on n'analyse donc pas plus loin.
        analysis.multiple_records = True
        analysis.valid_syntax = False
        analysis.syntax_errors.append(
            f"{len(records)} enregistrements SPF publiés ; la RFC 7208 §4.5 "
            "impose un enregistrement unique, sans quoi l'évaluation rend permerror"
        )
        return analysis

    state = _WalkState()
    _walk(state, lookup, domain, records[0], depth=0)

    analysis.mechanisms = state.mechanisms
    analysis.syntax_errors = state.errors
    analysis.valid_syntax = not state.errors
    analysis.all_qualifier = state.all_qualifier
    analysis.lookup_count = state.lookups
    analysis.void_lookup_count = state.void_lookups
    analysis.exceeds_lookup_limit = state.lookups > MAX_LOOKUPS
    analysis.includes_resolved = state.includes
    analysis.circular_includes = state.circular
    analysis.unresolvable_includes = state.unresolvable
    analysis.uses_ptr = state.uses_ptr

    ipv4, ipv6 = _count_address_space(state.networks, permit_everything=state.permit_everything)
    analysis.ipv4_space = ipv4
    analysis.ipv6_space = ipv6

    analysis.shared_pools = _detect_shared_pools(state.includes)
    analysis.include_tree = {"domain": domain, "includes": state.includes}

    return analysis


# ---------------------------------------------------------------------------
# Descente dans l'arbre
# ---------------------------------------------------------------------------


def _walk(
    state: _WalkState,
    lookup: DnsLookup,
    domain: str,
    record: str,
    *,
    depth: int,
) -> None:
    """Parcourt un enregistrement SPF et, récursivement, ses inclusions."""
    if depth > MAX_DEPTH:
        state.errors.append(f"profondeur d'inclusion excessive à partir de {domain}")
        return

    key = domain.lower()
    if key in state.visited:
        state.circular.append(domain)
        state.errors.append(f"inclusion circulaire détectée sur {domain}")
        return
    state.visited.add(key)

    terms = record.split()[1:]  # le premier terme est « v=spf1 »
    redirect_target: str | None = None
    seen_all = False

    for raw_term in terms:
        match = _TERM_RE.match(raw_term)
        if not match:
            state.errors.append(f"terme illisible « {raw_term} » dans le SPF de {domain}")
            continue

        qualifier = match.group("qualifier") or "+"
        name = match.group("name").lower()
        rest = match.group("rest") or ""

        # Un modificateur s'écrit « nom=valeur » ; tout le reste est un mécanisme.
        if rest.startswith("="):
            value = rest[1:]
            if name == "redirect":
                redirect_target = value
            elif name != "exp":
                # Les modificateurs inconnus sont tolérés par la RFC §6.
                continue
            continue

        if seen_all:
            # RFC 7208 §5.1 : l'évaluation s'arrête au premier `all`. Ce qui
            # suit n'est jamais atteint — souvent le vestige d'une migration.
            state.errors.append(
                f"terme « {raw_term} » placé après « all » : il ne sera jamais évalué"
            )
            continue

        value = rest[1:] if rest.startswith(":") else rest

        if _MACRO_RE.search(value):
            state.uses_macros = True

        mechanism = SpfMechanism(
            qualifier=qualifier,
            kind=name,
            value=value or None,
            depth=depth,
            source_domain=domain,
            costs_lookup=name in _LOOKUP_TERMS,
        )
        state.mechanisms.append(mechanism)

        if name == "all":
            seen_all = True
            if depth == 0:
                state.all_qualifier = qualifier
            if qualifier == "+" and depth == 0:
                state.permit_everything = True
            continue

        _handle_mechanism(state, lookup, domain, name, qualifier, value, depth, raw_term)

    # RFC 7208 §6.1 : `redirect` est ignoré si un `all` est présent.
    if redirect_target and not seen_all:
        _follow_redirect(state, lookup, redirect_target, depth)


def _handle_mechanism(
    state: _WalkState,
    lookup: DnsLookup,
    domain: str,
    name: str,
    qualifier: str,
    value: str,
    depth: int,
    raw_term: str,
) -> None:
    if name in ("ip4", "ip6"):
        _add_literal_network(state, name, qualifier, value, raw_term)
        return

    if name == "ptr":
        state.uses_ptr = True
        state.lookups += 1
        return

    if name == "exists":
        state.lookups += 1
        return

    if name == "a":
        state.lookups += 1
        target, cidr4, cidr6 = _split_dual_cidr(value or domain, domain)
        addresses = lookup.a(target) + lookup.aaaa(target)
        if not addresses:
            state.void_lookups += 1
        if qualifier == "+":
            _add_host_networks(state, addresses, cidr4, cidr6)
        return

    if name == "mx":
        state.lookups += 1
        target, cidr4, cidr6 = _split_dual_cidr(value or domain, domain)
        mx_records = lookup.mx(target)
        if not mx_records:
            state.void_lookups += 1
            return
        for entry in mx_records[:MAX_MX_RECORDS]:
            host = entry.split(" ", 1)[-1].strip().rstrip(".")
            if not host or host == ".":
                continue
            addresses = lookup.a(host) + lookup.aaaa(host)
            if qualifier == "+":
                _add_host_networks(state, addresses, cidr4, cidr6)
        return

    if name == "include":
        state.lookups += 1
        target = value.strip().rstrip(".").lower()
        if not target:
            state.errors.append(f"« include: » sans cible dans le SPF de {domain}")
            return

        state.includes.append(target)

        if _MACRO_RE.search(target):
            # Cible construite dynamiquement : elle n'existe qu'à l'évaluation.
            return

        nested = extract_spf_records(lookup.txt(target))
        if not nested:
            state.void_lookups += 1
            state.unresolvable.append(target)
            # Un include: sans SPF à l'arrivée rend `permerror` (RFC §4.6.4).
            state.errors.append(
                f"« include:{target} » ne renvoie aucun enregistrement SPF ; "
                "l'évaluation rend permerror"
            )
            return
        if len(nested) > 1:
            state.errors.append(
                f"« include:{target} » renvoie {len(nested)} enregistrements SPF ; "
                "l'évaluation rend permerror"
            )
            return

        _walk(state, lookup, target, nested[0], depth=depth + 1)
        return

    state.errors.append(f"mécanisme inconnu « {raw_term} » dans le SPF de {domain}")


def _follow_redirect(
    state: _WalkState, lookup: DnsLookup, target: str, depth: int
) -> None:
    state.lookups += 1
    target = target.strip().rstrip(".").lower()
    if _MACRO_RE.search(target):
        return

    state.includes.append(target)
    nested = extract_spf_records(lookup.txt(target))
    if not nested:
        state.void_lookups += 1
        state.unresolvable.append(target)
        state.errors.append(
            f"« redirect={target} » ne renvoie aucun enregistrement SPF ; "
            "l'évaluation rend permerror"
        )
        return

    _walk(state, lookup, target, nested[0], depth=depth + 1)


# ---------------------------------------------------------------------------
# Espace d'adressage autorisé
# ---------------------------------------------------------------------------


def _add_literal_network(
    state: _WalkState, kind: str, qualifier: str, value: str, raw_term: str
) -> None:
    if not value:
        state.errors.append(f"« {raw_term} » ne précise aucune adresse")
        return
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        state.errors.append(f"adresse ou préfixe invalide dans « {raw_term} »")
        return

    expected_version = 4 if kind == "ip4" else 6
    if network.version != expected_version:
        state.errors.append(
            f"« {raw_term} » déclare une adresse IPv{network.version} "
            f"sous le mécanisme {kind}"
        )
        return

    # Seuls les mécanismes en « + » autorisent : « -ip4:… » exclut au contraire.
    if qualifier == "+":
        state.networks.append(network)


def _add_host_networks(
    state: _WalkState, addresses: list[str], cidr4: int | None, cidr6: int | None
) -> None:
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        prefix = (cidr4 if parsed.version == 4 else cidr6) or parsed.max_prefixlen
        try:
            state.networks.append(
                ipaddress.ip_network(f"{parsed}/{prefix}", strict=False)
            )
        except ValueError:
            continue


def _split_dual_cidr(value: str, default_domain: str) -> tuple[str, int | None, int | None]:
    """Sépare « domaine/24//64 » en (domaine, préfixe IPv4, préfixe IPv6)."""
    cidr4: int | None = None
    cidr6: int | None = None

    if "//" in value:
        value, _, raw6 = value.partition("//")
        cidr6 = int(raw6) if raw6.isdigit() else None
    if "/" in value:
        value, _, raw4 = value.partition("/")
        cidr4 = int(raw4) if raw4.isdigit() else None

    target = value.strip().rstrip(".").lower() or default_domain
    return target, cidr4, cidr6


def _count_address_space(
    networks: list[IpNetwork], *, permit_everything: bool
) -> tuple[int, int]:
    """Fusionne les préfixes autorisés et retourne leur cardinal réel.

    La fusion importe : `include:` d'un même fournisseur cité deux fois, ou
    préfixes imbriqués, gonfleraient artificiellement le total sans elle.
    """
    if permit_everything:
        return 2**32, 2**128

    v4 = [n for n in networks if n.version == 4]
    v6 = [n for n in networks if n.version == 6]

    def total(items: list[Any]) -> int:
        if not items:
            return 0
        try:
            return sum(net.num_addresses for net in ipaddress.collapse_addresses(items))
        except (TypeError, ValueError):
            return sum(net.num_addresses for net in items)

    return total(v4), total(v6)


def _detect_shared_pools(includes: list[str]) -> list[str]:
    """Signale les plateformes dont les IP d'envoi sont mutualisées.

    Autoriser un pool mutualisé revient à faire confiance à l'ensemble des
    clients de la plateforme : n'importe lequel d'entre eux émet depuis une
    adresse que votre SPF déclare légitime.
    """
    pools: list[str] = []
    for provider in load_providers():
        if not provider.get("shared_pool"):
            continue
        patterns = [str(p).lower() for p in provider.get("spf_includes") or []]
        for include in includes:
            lowered = include.lower()
            if any(lowered == p or lowered.endswith("." + p) for p in patterns):
                name = str(provider["name"])
                if name not in pools:
                    pools.append(name)
                break
    return pools


def format_address_space(count: int) -> str:
    """Rend un cardinal d'adresses lisible dans un rapport.

    L'ordre de grandeur prime sur la précision : « 4,3 milliards d'adresses »
    dit ce qu'il faut comprendre, « 4294967296 » ne dit rien à personne.
    """
    if count <= 0:
        return "aucune"
    if count == 1:
        return "1 adresse"

    # Au-delà du billion, seul l'ordre de grandeur a du sens : un espace IPv6
    # se compte en milliers de milliards de milliards d'adresses.
    if count >= 10**12:
        return f"{count:.2e} adresses"

    for threshold, divisor, unit in (
        (10**9, 10**9, "milliards"),
        (10**6, 10**6, "millions"),
    ):
        if count >= threshold:
            return f"{count / divisor:.1f}".replace(".", ",") + f" {unit} d'adresses"

    # Espace fine insécable (U+202F) : séparateur de milliers de la typographie
    # française, qui évite en outre que « 98 304 » se coupe en fin de ligne dans
    # le rapport. Échappée explicitement : un caractère invisible dans le source
    # se fait effacer au premier reformatage, sans que personne ne le remarque.
    return f"{count:,}".replace(",", "\u202f") + " adresses"
