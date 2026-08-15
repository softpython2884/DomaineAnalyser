"""Découverte des sélecteurs DKIM publiés par un domaine.

DKIM n'offre aucun mécanisme d'énumération : le nom du sélecteur est choisi
librement par le signataire et n'apparaît nulle part dans le DNS tant qu'on ne
l'a pas deviné. Le sondage par dictionnaire est donc la seule approche
possible, et elle est structurellement incomplète — un sélecteur aléatoire,
comme ceux d'Amazon SES, restera invisible.

C'est précisément la limite que lèvent les rapports agrégés DMARC : ils
nomment les sélecteurs réellement employés par chaque émetteur. Les sélecteurs
qui en sont issus sont réinjectés ici via `extra_selectors`.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ..dataload import load_selectors
from ..net.resolver import DnsResolver

#: Sondages simultanés. Volontairement modeste : un dictionnaire complet
#: représente une centaine de requêtes, et rien ne justifie de malmener un
#: résolveur public pour gagner quelques secondes.
_MAX_WORKERS = 10


def build_selector_candidates(
    *,
    deep: bool = False,
    extra: tuple[str, ...] = (),
    now: datetime | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Construit la liste des sélecteurs à sonder.

    Args:
        deep: inclut le palier étendu, plus lent mais plus couvrant.
        extra: sélecteurs connus (option `--selector`, découverte via RUA).
        now: date de référence, injectable pour rendre les tests déterministes.

    Returns:
        La liste ordonnée et dédoublonnée des sélecteurs, et la table associant
        un sélecteur au fournisseur qui l'emploie, quand il est connu.
    """
    data = load_selectors()
    now = now or datetime.now(tz=timezone.utc)

    ambiguous = _ambiguous_selectors(data)

    candidates: list[str] = []
    owners: dict[str, str] = {}

    def add(selector: str, provider: str | None = None) -> None:
        selector = selector.strip().lower()
        if not selector:
            return
        # Un sélecteur ambigu n'attribue aucun fournisseur : « s1 » est la
        # convention de SendGrid, mais c'est aussi le nom générique le plus
        # répandu. Conclure sur ce seul indice produirait un faux positif —
        # l'attribution devra venir du SPF ou des MX.
        if provider and selector not in owners and selector not in ambiguous:
            owners[selector] = provider
        if selector not in candidates:
            candidates.append(selector)

    for provider, selectors in (data.get("providers") or {}).items():
        for selector in selectors or []:
            add(str(selector), str(provider))

    generic = data.get("generic") or {}
    for selector in generic.get("default") or []:
        add(str(selector))
    if deep:
        for selector in generic.get("deep") or []:
            add(str(selector))

    for rule in data.get("dynamic") or []:
        if not deep and str(rule.get("tier", "default")) != "default":
            continue
        for selector in _expand_dynamic(rule, now):
            add(selector, rule.get("provider"))

    # Les sélecteurs fournis passent en tête : ce sont les plus susceptibles
    # d'exister, et cela rend leur résultat visible immédiatement.
    for selector in extra:
        cleaned = selector.strip().lower()
        if cleaned and cleaned in candidates:
            candidates.remove(cleaned)
        if cleaned:
            candidates.insert(0, cleaned)

    return candidates, owners


def _ambiguous_selectors(data: dict[str, Any]) -> frozenset[str]:
    """Sélecteurs incapables de désigner un fournisseur à eux seuls.

    Un sélecteur est ambigu s'il figure dans la liste générique, ou s'il est
    revendiqué par plusieurs fournisseurs. Le calculer plutôt que de le
    maintenir à la main garantit que l'ajout d'un fournisseur au fichier de
    données ne crée jamais silencieusement une attribution erronée.
    """
    seen: dict[str, int] = {}
    for selectors in (data.get("providers") or {}).values():
        for selector in selectors or []:
            key = str(selector).strip().lower()
            seen[key] = seen.get(key, 0) + 1

    ambiguous = {selector for selector, count in seen.items() if count > 1}

    generic = data.get("generic") or {}
    for tier in ("default", "deep"):
        for selector in generic.get(tier) or []:
            ambiguous.add(str(selector).strip().lower())

    return frozenset(ambiguous)


def _expand_dynamic(rule: dict[str, Any], now: datetime) -> list[str]:
    """Déroule un motif daté, ex. « cf{year}-{index} » -> cf2026-1, cf2025-1…"""
    template = str(rule.get("template", ""))
    if not template:
        return []

    years_back = int(rule.get("years_back", 1))
    max_index = int(rule.get("max_index", 1))
    with_months = bool(rule.get("months", False))

    result: list[str] = []
    for offset in range(years_back):
        year = now.year - offset
        months = range(1, 13) if with_months else [now.month]
        for month in months:
            # Ne pas générer de sélecteurs postérieurs à aujourd'hui : ils ne
            # peuvent pas exister et gaspilleraient des requêtes.
            if with_months and year == now.year and month > now.month:
                continue
            for index in range(1, max_index + 1):
                try:
                    result.append(template.format(year=year, month=month, index=index))
                except (KeyError, IndexError, ValueError):
                    return []
    return result


#: Sélecteur sentinelle, choisi pour ne pouvoir exister nulle part. S'il
#: répond, c'est que la zone contient un joker `*._domainkey` : tout sélecteur
#: paraîtra alors valide et le sondage n'a plus aucune valeur probante.
_WILDCARD_SENTINEL = "domaineanalyser-wildcard-probe-4f21a9"


@dataclass(slots=True)
class DkimProbeResult:
    """Résultat d'un sondage de sélecteurs."""

    found: dict[str, str]
    owners: dict[str, str]
    probed: int
    #: Valeur renvoyée par le joker, le cas échéant. Sa présence invalide
    #: l'énumération : `found` est alors laissé vide à dessein.
    wildcard_record: str | None = None


def probe_selectors(
    resolver: DnsResolver,
    domain: str,
    *,
    deep: bool = False,
    extra: tuple[str, ...] = (),
    now: datetime | None = None,
) -> DkimProbeResult:
    """Sonde les sélecteurs candidats et retourne ceux qui répondent."""
    domain = domain.strip().rstrip(".").lower()
    candidates, owners = build_selector_candidates(deep=deep, extra=extra, now=now)

    def probe(selector: str) -> tuple[str, str | None]:
        rrset = resolver.query(f"{selector}._domainkey.{domain}", "TXT")
        if not rrset.ok or not rrset.values:
            return selector, None
        # Un nom peut porter plusieurs TXT (jeton de vérification à côté de la
        # clé) : on ne retient que celui qui ressemble à une clé DKIM.
        for value in rrset.values:
            lowered = value.lower()
            if "p=" in lowered or lowered.startswith("v=dkim1"):
                return selector, value
        return selector, None

    # Sondage du joker en premier : sans ce garde-fou, un domaine publiant
    # « *._domainkey » — pratique recommandée pour déclarer qu'aucune clé n'est
    # valide — produirait autant de fausses découvertes que de candidats.
    _, wildcard = probe(_WILDCARD_SENTINEL)
    if wildcard is not None:
        return DkimProbeResult(
            found={}, owners=owners, probed=len(candidates), wildcard_record=wildcard
        )

    with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        results = list(pool.map(probe, candidates))

    found = {selector: value for selector, value in results if value is not None}
    return DkimProbeResult(found=found, owners=owners, probed=len(candidates))
