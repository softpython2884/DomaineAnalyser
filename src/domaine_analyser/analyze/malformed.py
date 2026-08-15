"""Diagnostic des enregistrements publiés mais illisibles par les serveurs.

Un enregistrement corrompu est plus dangereux qu'un enregistrement absent :
son auteur le voit dans l'interface de son hébergeur, le croit actif, et ne
comprend pas pourquoi rien ne fonctionne. Le comportement observable est
pourtant identique à celui d'un domaine sans aucune configuration.

Ces corruptions ne sont pas théoriques. Elles proviennent presque toutes des
interfaces web de gestion de zone, qui traitent différemment les guillemets
que réclame la syntaxe DNS : certaines les exigent, d'autres les ajoutent
d'elles-mêmes, quelques-unes les encodent en entités HTML. L'utilisateur ne
peut pas deviner laquelle il a en face.

L'outil ne « répare » jamais silencieusement ces valeurs : si un serveur de
messagerie ne les accepte pas, l'audit ne doit pas faire semblant du contraire.
Il les signale, en nommant la cause probable pour rendre la correction immédiate.
"""

from __future__ import annotations

import re

from ..models import MalformedRecord

#: Corruptions reconnues, dans l'ordre où elles doivent être testées.
#: Chaque entrée associe un motif au diagnostic et à sa cause la plus probable.
_SIGNATURES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"^\s*&quot;", re.IGNORECASE),
        "la valeur commence par l'entité HTML « &quot; » au lieu d'un guillemet",
        "saisie via une interface web qui a encodé les guillemets en HTML",
    ),
    (
        re.compile(r"^\s*&#3[49];"),
        "la valeur commence par une entité HTML numérique au lieu d'un guillemet",
        "saisie via une interface web qui a encodé les guillemets en HTML",
    ),
    (
        re.compile(r"^\s*[\"']"),
        "la valeur inclut des guillemets littéraux dans son contenu",
        "guillemets saisis manuellement alors que l'hébergeur les ajoute déjà",
    ),
    (
        re.compile(r"^\s+"),
        "la valeur commence par un ou plusieurs espaces",
        "espace résiduel lors d'un copier-coller",
    ),
    (
        re.compile(r"^v\s*=\s*\w", re.IGNORECASE),
        "des espaces entourent le signe « = » du tag de version",
        "reformatage automatique par un éditeur de zone",
    ),
)


def diagnose(values: list[str], prefix: str) -> list[MalformedRecord]:
    """Identifie les valeurs qui visaient `prefix` sans l'atteindre.

    Args:
        values: enregistrements TXT trouvés au nom attendu.
        prefix: préfixe normatif recherché, par exemple « v=dmarc1 ».
    """
    prefix = prefix.lower()
    marker = prefix.replace("=", "").replace(" ", "")
    malformed: list[MalformedRecord] = []

    for value in values:
        lowered = value.lower()
        if lowered.startswith(prefix):
            continue

        # La valeur doit *viser* ce type d'enregistrement pour être signalée :
        # un jeton de vérification quelconque n'est pas un SPF cassé.
        normalized = re.sub(r"[^a-z0-9]", "", lowered)
        if marker not in normalized:
            continue

        reason, cause = _classify(value, prefix)
        malformed.append(MalformedRecord(value=value, reason=reason, likely_cause=cause))

    return malformed


def _classify(value: str, prefix: str) -> tuple[str, str]:
    for pattern, reason, cause in _SIGNATURES:
        if pattern.search(value):
            return reason, cause

    if prefix not in value.lower():
        return (
            f"le tag de version « {prefix} » est altéré",
            "faute de frappe ou troncature de la valeur",
        )

    return (
        f"la valeur ne commence pas par « {prefix} », comme l'exige la norme",
        "caractères parasites en tête de valeur",
    )


def repaired_preview(value: str) -> str:
    """Retourne la valeur telle qu'elle devrait être publiée.

    Sert uniquement à illustrer la correction dans le rapport. Cette forme
    n'est jamais utilisée pour l'analyse : ce que les serveurs de messagerie
    lisent est la valeur réelle, pas celle qu'elle aurait dû être.
    """
    cleaned = value.strip()
    for entity in ("&quot;", "&#34;", "&#39;"):
        cleaned = cleaned.replace(entity, "")
    return cleaned.strip().strip("\"'").strip()
