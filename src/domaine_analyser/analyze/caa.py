"""Analyse des enregistrements CAA (RFC 8659).

CAA ne relève pas directement de la sécurité du courrier, mais du même risque
d'usurpation : sans lui, n'importe quelle autorité de certification publique
peut émettre un certificat pour le domaine. Un certificat frauduleux permet
d'usurper le site — et, via MTA-STS ou un webmail, la messagerie qui va avec.

Le champ `iodef` mérite une attention particulière : c'est la seule façon
d'être *prévenu* d'une demande de certificat refusée, donc d'une tentative
d'émission illégitime. Presque personne ne le renseigne.
"""

from __future__ import annotations

from ..models import CaaAnalysis, DnsRecordSet


def analyze_caa(record_set: DnsRecordSet, inherited_from: str | None) -> CaaAnalysis:
    """Analyse les enregistrements CAA applicables au domaine."""
    analysis = CaaAnalysis(inherited_from=inherited_from)

    if not record_set.ok or not record_set.values:
        return analysis

    analysis.present = True
    analysis.records = list(record_set.values)

    for value in record_set.values:
        parts = value.split(None, 2)
        if len(parts) < 3:
            continue
        tag = parts[1].strip().lower()
        target = parts[2].strip().strip('"')

        # La valeur peut porter des paramètres après un « ; » (comptes ACME).
        issuer = target.split(";", 1)[0].strip().lower()

        if tag == "issue" and issuer:
            if issuer not in analysis.issuers:
                analysis.issuers.append(issuer)
        elif tag == "issuewild" and issuer:
            if issuer not in analysis.wildcard_issuers:
                analysis.wildcard_issuers.append(issuer)
        elif tag == "iodef":
            analysis.has_iodef = True

    return analysis


def blocks_all_issuance(analysis: CaaAnalysis) -> bool:
    """Vrai si la politique interdit toute émission de certificat.

    La valeur « ; » (chaîne vide) signifie « aucune autorité autorisée ».
    """
    return analysis.present and analysis.issuers == [""]
