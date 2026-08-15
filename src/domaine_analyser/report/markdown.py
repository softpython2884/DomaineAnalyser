"""Rendu Markdown d'un rapport d'audit.

Le document suit l'ordre dans lequel on a besoin de l'information, pas l'ordre
dans lequel elle a été collectée : le verdict d'abord, puisque c'est la seule
chose que tout le monde lira ; le plan d'action ensuite, trié par gravité ;
les relevés bruts en fin de document, pour qui doit vérifier.

Chaque risque expose systématiquement trois éléments — ce qui a été observé,
ce qu'un attaquant peut en faire, et quoi corriger. Une liste de constats sans
la colonne « impact » se lit comme une liste de reproches ; c'est ce qui fait
qu'un rapport d'audit finit au fond d'un tiroir.
"""

from __future__ import annotations

from ..analyze.spf import format_address_space
from ..models import DomainReport, Finding, Severity
from ..score import severity_counts

_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 Critique",
    Severity.HIGH: "🟠 Élevé",
    Severity.MEDIUM: "🟡 Moyen",
    Severity.LOW: "🔵 Faible",
    Severity.INFO: "⚪ Information",
}

_GRADE_COMMENT = {
    "A": "Configuration solide.",
    "B": "Bonne configuration, quelques points à durcir.",
    "C": "Configuration perfectible : plusieurs contrôles manquent.",
    "D": "Configuration insuffisante face à l'usurpation.",
    "E": "Configuration très insuffisante.",
    "F": "Domaine sans protection réelle.",
}


def render(report: DomainReport) -> str:
    """Produit le rapport Markdown complet."""
    blocks = [
        _header(report),
        _verdict(report),
        _score_table(report),
        _findings_section(report),
        _action_plan(report),
        _authentication_section(report),
        _providers_section(report),
        _registration_section(report),
        _dns_section(report),
        _ai_section(report),
        _footer(report),
    ]
    return "\n\n".join(block for block in blocks if block).strip() + "\n"


# ---------------------------------------------------------------------------


def _header(report: DomainReport) -> str:
    score = report.score
    stamp = report.analyzed_at.strftime("%d/%m/%Y à %H:%M UTC")
    lines = [
        f"# Audit de sécurité email — {report.domain}",
        "",
        f"**Score : {score.total}/100 (note {score.grade})** — "
        f"{_GRADE_COMMENT.get(score.grade, '')}",
        "",
        f"Analysé le {stamp}. Domaine organisationnel : `{report.organizational_domain}`.",
    ]
    return "\n".join(lines)


def _verdict(report: DomainReport) -> str:
    verdict = report.verdict
    lines = ["## Verdict"]

    if verdict.spoofable:
        lines += [
            "",
            f"> ### ⚠️ Le domaine `{report.domain}` est usurpable",
            ">",
            "> Un tiers peut envoyer un message affichant ce domaine en expéditeur "
            "et atteindre la boîte de réception du destinataire.",
        ]
    else:
        lines += [
            "",
            f"> ### ✅ Le domaine `{report.domain}` est protégé contre l'usurpation directe",
            ">",
            "> Une politique DMARC en application demande aux destinataires de "
            "traiter les messages non alignés.",
        ]

    if verdict.subdomains_spoofable:
        lines += [
            ">",
            "> **Les sous-domaines restent usurpables.** Un message émis depuis "
            f"`facturation.{report.domain}`, nom qui n'a même pas besoin d'exister, "
            "ne se heurte à aucune politique.",
        ]

    if verdict.reasons:
        lines += ["", "Éléments retenus :", ""]
        lines += [f"- {reason}" for reason in verdict.reasons]

    return "\n".join(lines)


def _score_table(report: DomainReport) -> str:
    lines = [
        "## Répartition du score",
        "",
        "| Domaine de contrôle | Obtenu | Maximum |",
        "| --- | ---: | ---: |",
    ]
    for item in report.score.categories:
        lines.append(
            f"| {item.category.label_fr} | {item.earned:.0f} | {item.weight} |"
        )
    lines.append(f"| **Total** | **{report.score.total}** | **100** |")

    lines += [
        "",
        "_DMARC porte le poids le plus élevé : c'est le seul mécanisme qui protège "
        "l'adresse réellement affichée au destinataire. SPF et DKIM ne font que "
        "l'alimenter._",
    ]
    return "\n".join(lines)


def _findings_section(report: DomainReport) -> str:
    if not report.findings:
        return "## Risques détectés\n\nAucun risque relevé."

    counts = severity_counts(report.findings)
    summary = ", ".join(
        f"{counts[severity]} {_SEVERITY_BADGE[severity].split(' ', 1)[1].lower()}"
        for severity in Severity
        if counts[severity]
    )

    lines = ["## Risques détectés", "", f"{len(report.findings)} constats : {summary}.", ""]

    for severity in Severity:
        group = [f for f in report.findings if f.severity is severity]
        if not group:
            continue
        lines += [f"### {_SEVERITY_BADGE[severity]}", ""]
        for finding in group:
            lines += _finding_block(finding)

    return "\n".join(lines)


def _finding_block(finding: Finding) -> list[str]:
    lines = [
        f"#### `{finding.code}` {finding.title}",
        "",
        f"**Constat.** {finding.detail}",
        "",
        f"**Impact.** {finding.impact}",
        "",
        f"**Correction.** {finding.remediation}",
    ]
    if finding.evidence:
        lines += ["", "<details><summary>Relevé</summary>", ""]
        lines += ["```"]
        lines += [item for item in finding.evidence if item]
        lines += ["```", "", "</details>"]
    if finding.refs:
        lines += ["", f"_Référence : {', '.join(finding.refs)}._"]
    lines.append("")
    return lines


def _action_plan(report: DomainReport) -> str:
    actionable = [f for f in report.findings if f.severity is not Severity.INFO]
    if not actionable:
        return ""

    lines = [
        "## Plan d'action",
        "",
        "Par ordre de priorité décroissante.",
        "",
        "| # | Priorité | Action | Réf. |",
        "| ---: | --- | --- | --- |",
    ]
    for index, finding in enumerate(actionable, start=1):
        action = finding.remediation.replace("\n", " ").replace("|", "\\|")
        lines.append(
            f"| {index} | {finding.severity.label_fr} | {action} | `{finding.code}` |"
        )
    return "\n".join(lines)


def _authentication_section(report: DomainReport) -> str:
    lines = ["## Authentification"]

    # -- SPF
    spf = report.spf
    lines += ["", "### SPF", ""]
    if not spf.present:
        lines.append("Aucun enregistrement publié.")
    else:
        lines += [
            "| Élément | Valeur |",
            "| --- | --- |",
            f"| Enregistrement | `{spf.raw}` |",
            f"| Qualificateur terminal | `{spf.all_qualifier or 'absent'}all` |",
            f"| Résolutions DNS | {spf.lookup_count} / 10"
            + (" — **limite dépassée**" if spf.exceeds_lookup_limit else "")
            + " |",
            f"| Résolutions sans réponse | {spf.void_lookup_count} / 2 |",
            f"| Espace IPv4 autorisé | {format_address_space(spf.ipv4_space)} |",
            f"| Espace IPv6 autorisé | {format_address_space(spf.ipv6_space)} |",
        ]
        if spf.includes_resolved:
            includes = ", ".join(f"`{item}`" for item in spf.includes_resolved)
            lines.append(f"| Inclusions résolues | {includes} |")

    # -- DKIM
    dkim = report.dkim
    lines += ["", "### DKIM", ""]
    if dkim.wildcard_record is not None:
        declaration = (
            "Le domaine publie un joker `*._domainkey` **révoquant toute clé** : "
            "aucune signature ne peut être valide, quel que soit le sélecteur."
            if dkim.wildcard_revokes_all
            else "Le domaine publie un joker `*._domainkey` **actif** : n'importe quel "
            "sélecteur renvoie cette clé."
        )
        lines += [declaration, "", f"`{dkim.wildcard_record}`", "", "_L'énumération des "
                  "sélecteurs est sans objet : tout nom interrogé répond._"]
    elif not dkim.keys:
        lines.append(
            f"Aucune clé découverte sur {dkim.selectors_probed} sélecteurs testés. "
            "Un sélecteur non conventionnel resterait invisible au sondage."
        )
    else:
        lines += [
            "| Sélecteur | Type | Taille | État | Service |",
            "| --- | --- | ---: | --- | --- |",
        ]
        for key in dkim.keys:
            if key.revoked:
                state = "révoquée"
            elif key.testing:
                state = "**mode test**"
            elif not key.valid:
                state = "illisible"
            else:
                state = "active"
            size = f"{key.key_bits} bits" if key.key_bits else "—"
            lines.append(
                f"| `{key.selector}` | {key.key_type} | {size} | {state} | "
                f"{key.provider or '—'} |"
            )

    # -- DMARC
    dmarc = report.dmarc
    lines += ["", "### DMARC", ""]
    if not dmarc.present:
        lines.append("Aucune politique publiée.")
    else:
        lines += [
            "| Élément | Valeur |",
            "| --- | --- |",
            f"| Enregistrement | `{dmarc.raw}` |",
            f"| Politique (`p`) | `{dmarc.policy or 'absente'}` |",
            f"| Sous-domaines (`sp`) | `{dmarc.effective_subdomain_policy or 'absente'}`"
            + ("" if dmarc.subdomain_policy else " _(héritée de `p`)_")
            + " |",
            f"| Application (`pct`) | {dmarc.percentage} % |",
            f"| Alignement DKIM / SPF | `{dmarc.adkim}` / `{dmarc.aspf}` |",
        ]
        if dmarc.inherited_from:
            lines.append(f"| Héritée de | `{dmarc.inherited_from}` |")

        if dmarc.rua or dmarc.ruf:
            lines += ["", "| Destination | Type | Externe | Autorisée |", "| --- | --- | --- | --- |"]
            for target, kind in [(t, "rua") for t in dmarc.rua] + [
                (t, "ruf") for t in dmarc.ruf
            ]:
                if target.authorized is None:
                    authorized = "sans objet"
                elif target.authorized:
                    authorized = "oui"
                else:
                    authorized = "**non**"
                lines.append(
                    f"| `{target.uri}` | {kind} | "
                    f"{'oui' if target.is_external else 'non'} | {authorized} |"
                )

    # -- Durcissement
    posture = report.posture
    lines += [
        "",
        "### Durcissement",
        "",
        "| Mécanisme | État |",
        "| --- | --- |",
        f"| DNSSEC | {_yes_no(posture.dnssec)} |",
        f"| MTA-STS | {_yes_no(posture.mta_sts)} |",
        f"| TLS-RPT | {_yes_no(posture.tls_rpt)} |",
        f"| BIMI | {_yes_no(posture.bimi)} |",
        f"| CAA | {_yes_no(report.caa.present)}"
        + (f" _(hérité de `{report.caa.inherited_from}`)_" if report.caa.inherited_from else "")
        + " |",
    ]
    if report.caa.issuers:
        lines.append(
            f"| Autorités autorisées | {', '.join(f'`{i}`' for i in report.caa.issuers)} |"
        )

    return "\n".join(lines)


def _providers_section(report: DomainReport) -> str:
    if not report.providers:
        return ""

    lines = [
        "## Services identifiés",
        "",
        "| Service | Type | Peut émettre au nom du domaine | Signaux |",
        "| --- | --- | :---: | --- |",
    ]
    for match in report.providers:
        signals = ", ".join(match.signals)
        lines.append(
            f"| {match.name} | {match.kind} | "
            f"{'**oui**' if match.can_send_as_domain else 'non'} | {signals} |"
        )

    senders = [m for m in report.providers if m.can_send_as_domain]
    if senders:
        lines += [
            "",
            f"_{len(senders)} service(s) peuvent techniquement émettre en affichant "
            "ce domaine. Chacun constitue un chemin d'envoi légitime, donc un point "
            "de compromission possible : la fin d'un contrat ne révoque ni une clé "
            "DKIM ni un `include:` SPF._",
        ]
    return "\n".join(lines)


def _registration_section(report: DomainReport) -> str:
    info = report.registration
    if info.source == "none" and not info.registrar:
        return ""

    rows = [
        ("Source", info.source.upper()),
        ("Bureau d'enregistrement", info.registrar),
        ("Titulaire", info.registrant),
        ("Pays du titulaire", info.registrant_country),
        ("Créé le", _date(info.created)),
        ("Âge", f"{info.age_days} jours" if info.age_days is not None else None),
        ("Expire le", _date(info.expires)),
        ("Contact abuse", info.abuse_email),
    ]

    lines = ["## Enregistrement du domaine", "", "| Élément | Valeur |", "| --- | --- |"]
    lines += [f"| {label} | {value} |" for label, value in rows if value]

    if info.statuses:
        lines.append(f"| Statuts | {', '.join(f'`{s}`' for s in info.statuses[:6])} |")
    if info.nameservers:
        lines.append(f"| Serveurs de noms | {', '.join(f'`{n}`' for n in info.nameservers)} |")
    return "\n".join(lines)


def _dns_section(report: DomainReport) -> str:
    lines = ["## Relevé DNS", "", "| Type | Nom | TTL | Valeur |", "| --- | --- | ---: | --- |"]

    for key, record in report.dns.items():
        if record.error == "NXDOMAIN" or (record.ok and not record.values):
            lines.append(f"| {key} | `{record.name}` | — | _absent_ |")
            continue
        if not record.ok:
            lines.append(f"| {key} | `{record.name}` | — | _échec : {record.error}_ |")
            continue
        for index, value in enumerate(record.values):
            escaped = value.replace("|", "\\|")
            ttl = str(record.ttl) if index == 0 and record.ttl is not None else ""
            name = f"`{record.name}`" if index == 0 else ""
            label = key if index == 0 else ""
            lines.append(f"| {label} | {name} | {ttl} | `{escaped}` |")

    return "\n".join(lines)


def _ai_section(report: DomainReport) -> str:
    if not report.ai_enrichment:
        return ""
    return "\n".join(
        [
            "## Enrichissement externe (non vérifié)",
            "",
            "> Cette section provient d'une recherche automatisée sur des sources "
            "publiques. Elle n'a **aucun effet sur le score ni sur les constats "
            "ci-dessus**, et chaque affirmation doit être vérifiée via sa source.",
            "",
            report.ai_enrichment,
        ]
    )


def _footer(report: DomainReport) -> str:
    lines = []
    if report.warnings:
        lines += ["## Limites de cet audit", ""]
        lines += [f"- {warning}" for warning in report.warnings]
        lines.append("")

    lines += [
        "---",
        "",
        "_Rapport produit par DomaineAnalyser. Collecte strictement passive : "
        "DNS, RDAP et WHOIS publics uniquement, sans aucune connexion vers "
        "l'infrastructure analysée._",
    ]
    return "\n".join(lines)


def _yes_no(value: bool) -> str:
    return "activé" if value else "**absent**"


def _date(value: object) -> str | None:
    if value is None:
        return None
    try:
        return value.strftime("%d/%m/%Y")  # type: ignore[attr-defined]
    except AttributeError:
        return str(value)
