"""Analyse du transport entrant et de sa cohérence avec la politique d'envoi.

Le contrôle le plus utile ici n'est pas la validité des MX pris isolément,
mais leur **cohérence avec le SPF**. Un domaine dont les MX pointent vers
Microsoft 365 alors que le SPF n'autorise que Google raconte une histoire
précise : une migration inachevée. Les deux configurations coexistent, l'une
des deux ne fonctionne plus, et la fenêtre entre les deux est exactement ce
qu'un attaquant cherche.
"""

from __future__ import annotations

from ..dataload import load_providers
from ..models import MxAnalysis, MxHost
from .providers import _domain_suffix_match


def analyze_mx(
    hosts: list[MxHost],
    *,
    null_mx: bool,
    spf_includes: list[str],
) -> MxAnalysis:
    """Analyse les hôtes MX et leur cohérence avec le SPF publié."""
    analysis = MxAnalysis(hosts=hosts, null_mx=null_mx)

    catalogue = load_providers()
    includes_lower = [include.lower().rstrip(".") for include in spf_includes]

    for host in hosts:
        host.provider = _provider_for_host(host.hostname, catalogue)

    analysis.providers = _dedupe(
        [host.provider for host in hosts if host.provider is not None]
    )

    # Un service de messagerie identifié par ses MX devrait apparaître dans le
    # SPF : c'est par ces mêmes serveurs que partent en général les réponses.
    for provider in catalogue:
        name = str(provider["name"])
        if name not in analysis.providers:
            continue
        if str(provider.get("kind")) == "gateway":
            # Une passerelle de sécurité filtre l'entrant sans émettre :
            # son absence du SPF est normale, pas une incohérence.
            continue
        patterns = [str(p).lower() for p in provider.get("spf_includes") or []]
        if not patterns:
            continue
        if not any(
            _domain_suffix_match(include, pattern)
            for include in includes_lower
            for pattern in patterns
        ):
            analysis.inconsistent_with_spf.append(name)

    return analysis


def _provider_for_host(hostname: str, catalogue: list[dict]) -> str | None:
    hostname = hostname.lower().rstrip(".")
    for provider in catalogue:
        for pattern in (str(p).lower() for p in provider.get("mx") or []):
            if _domain_suffix_match(hostname, pattern):
                return str(provider["name"])
    return None


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
