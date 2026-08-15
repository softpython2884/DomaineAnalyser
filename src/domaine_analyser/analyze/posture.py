"""Mécanismes complémentaires de durcissement.

Aucun de ces quatre mécanismes n'empêche l'usurpation à lui seul, mais chacun
ferme une porte que SPF, DKIM et DMARC laissent ouverte :

- **MTA-STS** (RFC 8461) impose le chiffrement du transport vers vos MX. Sans
  lui, SMTP se rabat silencieusement sur du texte clair en cas d'échec TLS —
  un attaquant en position d'interception n'a qu'à provoquer cet échec.
- **TLS-RPT** (RFC 8460) rend visibles ces échecs. Sans lui, une interception
  active ne laisse aucune trace exploitable.
- **DNSSEC** protège les réponses DNS elles-mêmes. Sans lui, tous les
  enregistrements audités ici restent falsifiables en transit.
- **BIMI** n'est pas un contrôle de sécurité mais un indicateur fiable de
  maturité : il exige un DMARC en application stricte pour fonctionner.
"""

from __future__ import annotations

from ..models import DnsRecordSet, PostureAnalysis

_VALID_MTA_STS_MODES = frozenset({"none", "testing", "enforce"})


def analyze_posture(
    records: dict[str, DnsRecordSet],
    *,
    dnssec: bool,
) -> PostureAnalysis:
    """Évalue les mécanismes de durcissement publiés dans le DNS."""
    analysis = PostureAnalysis(dnssec=dnssec)

    mta_sts = _first_matching(records.get("MTA_STS"), "v=stsv1")
    if mta_sts:
        analysis.mta_sts = True
        # Le mode réel vit dans la politique servie en HTTPS sur
        # mta-sts.<domaine>/.well-known/mta-sts.txt. La collecte étant
        # strictement passive, on ne la récupère pas : l'enregistrement DNS
        # atteste seulement de l'existence d'une politique.
        analysis.mta_sts_mode = None

    if _first_matching(records.get("TLS_RPT"), "v=tlsrptv1"):
        analysis.tls_rpt = True

    bimi = _first_matching(records.get("BIMI"), "v=bimi1")
    if bimi:
        analysis.bimi = True
        # Le tag « a= » porte le certificat de marque (VMC), sans lequel la
        # plupart des messageries n'affichent pas le logo.
        analysis.bimi_has_vmc = "a=" in bimi.lower() and "a=;" not in bimi.lower().replace(" ", "")

    return analysis


def _first_matching(record_set: DnsRecordSet | None, prefix: str) -> str | None:
    if record_set is None or not record_set.ok:
        return None
    for value in record_set.values:
        if value.strip().lower().startswith(prefix):
            return value
    return None
