"""Identification des services rattachés à un domaine.

Le principe est le croisement de signaux. Un seul indice suffit rarement à
conclure : le sélecteur DKIM `s1` est la convention de SendGrid, mais aussi le
nom générique le plus répandu — l'attribuer sur cette seule base produirait un
faux positif. Un `include:` SPF, en revanche, est déclaratif et sans ambiguïté.

Le signal le plus intéressant à l'audit reste le jeton de vérification TXT :
il est déposé à l'ouverture d'un service et, contrairement au MX ou au SPF,
plus personne ne le retire à la fermeture du compte. C'est souvent la seule
trace restante d'un prestataire résilié dont l'accès n'a jamais été révoqué.
"""

from __future__ import annotations

from ..dataload import load_providers
from ..models import ProviderMatch


def detect_providers(
    *,
    mx_hostnames: list[str],
    spf_includes: list[str],
    dkim_selectors: list[str],
    txt_records: list[str],
) -> list[ProviderMatch]:
    """Croise les quatre signaux et retourne les services identifiés."""
    matches: list[ProviderMatch] = []

    mx_lower = [host.lower().rstrip(".") for host in mx_hostnames]
    includes_lower = [include.lower().rstrip(".") for include in spf_includes]
    selectors_lower = [selector.lower() for selector in dkim_selectors]
    txt_lower = [value.strip().lower() for value in txt_records]

    for provider in load_providers():
        signals: list[str] = []

        for pattern in (str(p).lower() for p in provider.get("mx") or []):
            for host in mx_lower:
                if _domain_suffix_match(host, pattern):
                    signals.append(f"MX {host}")
                    break

        for pattern in (str(p).lower() for p in provider.get("spf_includes") or []):
            for include in includes_lower:
                if _domain_suffix_match(include, pattern):
                    signals.append(f"SPF include:{include}")
                    break

        for prefix in (str(p).lower() for p in provider.get("dkim_prefix") or []):
            for selector in selectors_lower:
                if selector == prefix or selector.startswith(prefix):
                    signals.append(f"sélecteur DKIM {selector}")
                    break

        for token in (str(t).lower() for t in provider.get("txt_tokens") or []):
            for value in txt_lower:
                if value.startswith(token):
                    signals.append(f"jeton TXT {token.rstrip('=:')}")
                    break

        if signals:
            matches.append(
                ProviderMatch(
                    name=str(provider["name"]),
                    kind=str(provider.get("kind", "other")),
                    signals=_dedupe(signals),
                    can_send_as_domain=bool(provider.get("can_send_as_domain")),
                )
            )

    # Les services confirmés par plusieurs signaux indépendants remontent en
    # tête : ce sont ceux sur lesquels le rapport peut affirmer sans réserve.
    return sorted(matches, key=lambda m: (-len(m.signals), m.name))


def _domain_suffix_match(candidate: str, pattern: str) -> bool:
    """Correspondance sur une frontière de label.

    Sans cette contrainte, le motif « google.com » reconnaîtrait
    « notgoogle.com » — un domaine qu'un attaquant peut enregistrer.
    """
    return candidate == pattern or candidate.endswith("." + pattern)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def senders_able_to_impersonate(matches: list[ProviderMatch]) -> list[ProviderMatch]:
    """Services techniquement capables d'émettre en affichant ce domaine.

    C'est la surface d'usurpation *légitime* : chacun de ces services constitue
    un chemin d'envoi autorisé, et donc un point de compromission possible.
    """
    return [match for match in matches if match.can_send_as_domain]
