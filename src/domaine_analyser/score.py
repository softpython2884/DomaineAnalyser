"""Calcul du score de sécurité et du verdict d'usurpation.

Le score est **entièrement déterministe** : mêmes enregistrements DNS, même
résultat, sans appel réseau ni modèle. C'est une exigence, pas un détail — un
score d'audit qui varie d'une exécution à l'autre ne vaut rien comme référence
dans le temps.

Le verdict est volontairement séparé du score. Un domaine peut afficher 70/100
grâce à une hygiène DNS irréprochable tout en restant intégralement usurpable
parce que sa politique DMARC est en observation. Le score mesure la qualité
globale de la configuration ; le verdict répond à la seule question qui
engage : *quelqu'un peut-il écrire en mon nom aujourd'hui ?*
"""

from __future__ import annotations

from .models import (
    Category,
    CategoryScore,
    DmarcAnalysis,
    Finding,
    SecurityScore,
    Severity,
    SpfAnalysis,
    SpoofingVerdict,
)


def compute_score(findings: list[Finding]) -> SecurityScore:
    """Répartit les pénalités par catégorie et agrège le score sur 100.

    La pénalité d'un constat s'exprime en fraction du poids de sa catégorie,
    et non en points absolus : la même gravité a ainsi un effet proportionné,
    qu'elle touche DMARC (30 points) ou l'hygiène DNS (10 points).
    """
    penalties: dict[Category, float] = dict.fromkeys(Category, 0.0)

    for finding in findings:
        penalties[finding.category] += finding.severity.penalty_ratio

    categories: list[CategoryScore] = []
    for category in Category:
        weight = category.weight
        # Une catégorie ne descend jamais sous zéro : accumuler des pénalités
        # au-delà de son poids reviendrait à faire déborder un problème sur
        # les autres domaines de contrôle, qui n'y sont pour rien.
        earned = weight * max(0.0, 1.0 - penalties[category])
        categories.append(CategoryScore(category=category, weight=weight, earned=earned))

    total = round(sum(item.earned for item in categories))
    return SecurityScore(total=max(0, min(100, total)), categories=categories)


def compute_verdict(dmarc: DmarcAnalysis, spf: SpfAnalysis) -> SpoofingVerdict:
    """Détermine si un tiers peut usurper le domaine, et pourquoi.

    Le critère décisif est DMARC : c'est le seul mécanisme qui protège
    l'adresse affichée au destinataire. SPF et DKIM n'interviennent que pour
    expliquer *pourquoi* DMARC ne peut pas remplir son rôle.
    """
    reasons: list[str] = []
    spoofable = False

    if not dmarc.present and dmarc.malformed:
        spoofable = True
        reasons.append(
            "Un enregistrement DMARC est publié mais illisible par les serveurs : "
            "il est visible dans l'interface de l'hébergeur et paraît actif, alors "
            "qu'il ne protège rien."
        )
    elif not dmarc.present:
        spoofable = True
        reasons.append(
            "Aucune politique DMARC n'est publiée : rien n'indique aux destinataires "
            "quoi faire d'un message usurpant ce domaine."
        )
    elif dmarc.multiple_records:
        spoofable = True
        reasons.append(
            "Plusieurs enregistrements DMARC coexistent : la norme impose de les "
            "ignorer tous, ce qui revient à n'avoir aucune politique."
        )
    elif dmarc.policy == "none":
        spoofable = True
        reasons.append(
            "La politique DMARC est en « p=none » : aucune action n'est demandée aux "
            "destinataires, les messages usurpés sont délivrés normalement."
        )
    elif dmarc.percentage < 100:
        spoofable = True
        reasons.append(
            f"La politique ne s'applique qu'à {dmarc.percentage} % des messages : "
            f"{100 - dmarc.percentage} % passent sans contrôle."
        )

    # Un DMARC en application peut malgré tout être contourné si le SPF valide
    # tout Internet : le message obtient « pass » et l'alignement est satisfait.
    if not spoofable and spf.present and spf.all_qualifier == "+":
        spoofable = True
        reasons.append(
            "Le SPF se termine par « +all » : toute adresse obtient « pass », ce qui "
            "satisfait DMARC malgré une politique en application."
        )

    if not spoofable:
        if spf.present and spf.exceeds_lookup_limit and not _has_dkim_fallback(dmarc):
            reasons.append(
                "Le SPF dépasse la limite de résolutions DNS et rend « permerror » : "
                "DMARC ne peut s'appuyer que sur DKIM."
            )
        reasons.append(
            f"La politique DMARC « p={dmarc.policy} » demande aux destinataires de "
            "traiter les messages non alignés."
        )

    effective = dmarc.effective_subdomain_policy
    subdomains_spoofable = not dmarc.present or effective in (None, "none")

    if subdomains_spoofable and not spoofable:
        reasons.append(
            "Les sous-domaines restent usurpables : la politique de sous-domaine "
            "vaut « none »."
        )

    return SpoofingVerdict(
        spoofable=spoofable,
        subdomains_spoofable=subdomains_spoofable,
        reasons=reasons,
    )


def _has_dkim_fallback(dmarc: DmarcAnalysis) -> bool:
    """DMARC est satisfait dès qu'un seul des deux mécanismes s'aligne."""
    return dmarc.adkim in ("r", "s")


def severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    """Compte les constats par gravité, pour le résumé du rapport."""
    counts = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts
