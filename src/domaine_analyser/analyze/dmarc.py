"""Analyse de la politique DMARC (RFC 7489).

DMARC est le seul des trois mécanismes qui protège l'adresse réellement vue
par le destinataire, le `From:`. SPF valide l'enveloppe, DKIM valide une
signature : ni l'un ni l'autre n'empêche d'afficher n'importe quel expéditeur.
C'est pourquoi cet analyseur pèse le plus lourd dans le score.

Deux vérifications sortent de l'ordinaire et justifient ce module :

**L'autorisation des destinations externes (§7.1).** Envoyer ses rapports vers
un domaine tiers — un prestataire d'analyse DMARC, typiquement — exige que ce
tiers publie `<votre-domaine>._report._dmarc.<son-domaine>`. Sans cet
enregistrement, les serveurs conformes *n'envoient rien du tout*. Le symptôme
est indiscernable d'une absence de trafic : la configuration paraît correcte,
la console du prestataire reste vide, et personne ne comprend pourquoi.

**L'héritage organisationnel.** Un sous-domaine sans `_dmarc` propre hérite de
la politique du domaine organisationnel, via `sp` si elle est définie. Ignorer
cette règle conduirait à annoncer « aucun DMARC » sur un sous-domaine
pourtant protégé — ou l'inverse, à croire protégé un sous-domaine que `sp=none`
laisse grand ouvert.
"""

from __future__ import annotations

import re

import tldextract

from ..models import DmarcAnalysis, DmarcReportTarget
from .lookup import DnsLookup
from .malformed import diagnose

_VALID_POLICIES = frozenset({"none", "quarantine", "reject"})
_VALID_ALIGNMENT = frozenset({"r", "s"})

_MAILTO_RE = re.compile(r"^mailto:(?P<address>[^!\s]+)(?:!(?P<limit>\d+[kmgt]?))?$", re.IGNORECASE)


def organizational_domain(domain: str) -> str:
    """Domaine organisationnel au sens de la Public Suffix List.

    « mail.corp.example.co.uk » -> « example.co.uk ». Un découpage naïf sur les
    deux derniers labels donnerait « co.uk », qui n'est pas un domaine
    enregistrable, et fausserait aussi bien l'héritage DMARC que l'évaluation
    de l'alignement.
    """
    extracted = tldextract.extract(domain)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return domain.strip().rstrip(".").lower()


def extract_dmarc_records(txt_records: list[str]) -> list[str]:
    """Isole les enregistrements DMARC parmi les TXT de `_dmarc.<domaine>`."""
    return [value for value in txt_records if value.strip().lower().startswith("v=dmarc1")]


def analyze_dmarc(
    lookup: DnsLookup,
    domain: str,
    dmarc_txt: list[str],
    *,
    check_external: bool = True,
    apex_txt: list[str] | None = None,
) -> DmarcAnalysis:
    """Analyse la politique DMARC applicable à un domaine.

    Args:
        dmarc_txt: enregistrements TXT de `_dmarc.<domaine>`.
        apex_txt: enregistrements TXT du domaine lui-même, examinés pour
            repérer une politique publiée au mauvais endroit — erreur
            fréquente et totalement silencieuse.
    """
    domain = domain.strip().rstrip(".").lower()
    org_domain = organizational_domain(domain)

    records = extract_dmarc_records(dmarc_txt)
    inherited_from: str | None = None

    # Aucun enregistrement propre : la politique du domaine organisationnel
    # s'applique par héritage (§6.6.3).
    if not records and org_domain != domain:
        records = extract_dmarc_records(lookup.txt(f"_dmarc.{org_domain}"))
        if records:
            inherited_from = org_domain

    analysis = DmarcAnalysis(all_records=records, inherited_from=inherited_from)

    # Valeurs présentes sur `_dmarc` qui visaient manifestement une politique
    # DMARC sans respecter la syntaxe : elles seront ignorées par tous les
    # serveurs, alors que leur auteur les croit actives.
    analysis.malformed = diagnose(dmarc_txt, "v=dmarc1")

    # Une politique publiée sur le domaine lui-même n'est jamais consultée :
    # les serveurs interrogent exclusivement `_dmarc.<domaine>`.
    if apex_txt:
        analysis.misplaced_at_apex = extract_dmarc_records(apex_txt)

    if not records:
        return analysis

    analysis.present = True
    analysis.raw = records[0]

    if len(records) > 1:
        # §6.6.3 : en présence de plusieurs enregistrements, le destinataire
        # doit considérer qu'aucune politique n'est publiée. La protection
        # disparaît entièrement — c'est plus grave qu'une simple redondance.
        analysis.multiple_records = True
        analysis.valid_syntax = False
        analysis.syntax_errors.append(
            f"{len(records)} enregistrements DMARC publiés ; la RFC 7489 §6.6.3 impose "
            "au destinataire de les ignorer tous, ce qui annule la politique"
        )
        return analysis

    _parse_record(analysis, records[0])

    # L'enregistrement d'autorisation doit être publié au nom du domaine qui
    # porte la politique : en cas d'héritage, c'est le domaine organisationnel.
    reporting_domain = inherited_from or domain
    mark_external_targets(analysis, reporting_domain)

    if check_external:
        for target in analysis.rua + analysis.ruf:
            if target.is_external:
                _verify_external_target(lookup, reporting_domain, target)

    return analysis


def _parse_record(analysis: DmarcAnalysis, record: str) -> None:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        name, sep, value = part.partition("=")
        if not sep:
            continue
        name = name.strip().lower()
        if name:
            tags[name] = value.strip()

    policy = (tags.get("p") or "").lower()
    if not policy:
        analysis.syntax_errors.append(
            "le tag « p » est absent ; sans politique, l'enregistrement est inopérant"
        )
    elif policy not in _VALID_POLICIES:
        analysis.syntax_errors.append(f"politique « p={policy} » invalide")
    else:
        analysis.policy = policy

    subdomain_policy = (tags.get("sp") or "").lower()
    if subdomain_policy:
        if subdomain_policy in _VALID_POLICIES:
            analysis.subdomain_policy = subdomain_policy
        else:
            analysis.syntax_errors.append(f"politique de sous-domaine « sp={subdomain_policy} » invalide")

    raw_pct = tags.get("pct")
    if raw_pct is not None:
        if raw_pct.isdigit() and 0 <= int(raw_pct) <= 100:
            analysis.percentage = int(raw_pct)
        else:
            analysis.syntax_errors.append(f"valeur « pct={raw_pct} » invalide")

    for tag, attribute in (("adkim", "adkim"), ("aspf", "aspf")):
        value = (tags.get(tag) or "r").lower()
        if value in _VALID_ALIGNMENT:
            setattr(analysis, attribute, value)
        else:
            analysis.syntax_errors.append(f"mode d'alignement « {tag}={value} » invalide")

    if "fo" in tags:
        analysis.failure_options = tags["fo"]

    raw_ri = tags.get("ri")
    if raw_ri is not None and raw_ri.isdigit():
        analysis.report_interval = int(raw_ri)

    analysis.rua = _parse_targets(analysis, tags.get("rua"), "rua")
    analysis.ruf = _parse_targets(analysis, tags.get("ruf"), "ruf")

    analysis.valid_syntax = not analysis.syntax_errors


def _parse_targets(
    analysis: DmarcAnalysis, raw: str | None, tag: str
) -> list[DmarcReportTarget]:
    if not raw:
        return []

    targets: list[DmarcReportTarget] = []
    for uri in (part.strip() for part in raw.split(",")):
        if not uri:
            continue
        match = _MAILTO_RE.match(uri)
        if not match:
            analysis.syntax_errors.append(
                f"destination « {uri} » du tag {tag} illisible ; seul le schéma "
                "mailto: est reconnu par la RFC 7489 §6.2"
            )
            continue
        address = match.group("address")
        _, _, target_domain = address.rpartition("@")
        if not target_domain:
            analysis.syntax_errors.append(f"adresse « {address} » sans domaine dans {tag}")
            continue
        targets.append(DmarcReportTarget(uri=uri, domain=target_domain.lower()))

    return targets


def _verify_external_target(
    lookup: DnsLookup, reporting_domain: str, target: DmarcReportTarget
) -> None:
    """Vérifie l'autorisation publiée par le domaine destinataire (§7.1).

    L'enregistrement attendu est
    `<domaine-émetteur>._report._dmarc.<domaine-destinataire>`, ou sa forme
    générique `*._report._dmarc.<domaine-destinataire>`.
    """
    specific = f"{reporting_domain}._report._dmarc.{target.domain}"
    wildcard = f"*._report._dmarc.{target.domain}"

    for name in (specific, wildcard):
        records = [
            value for value in lookup.txt(name) if value.strip().lower().startswith("v=dmarc1")
        ]
        if records:
            target.authorized = True
            return

    target.authorized = False
    target.authorization_error = (
        f"« {specific} » est absent : les serveurs conformes n'enverront aucun "
        f"rapport vers {target.domain}"
    )


def mark_external_targets(analysis: DmarcAnalysis, domain: str) -> None:
    """Marque les destinations situées hors du domaine organisationnel."""
    org = organizational_domain(domain)
    for target in analysis.rua + analysis.ruf:
        target.is_external = organizational_domain(target.domain) != org
