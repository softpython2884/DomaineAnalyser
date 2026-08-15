"""Catalogue des scénarios d'usurpation et interprétation des résultats.

Chaque scénario met à l'épreuve un maillon distinct de la défense. La lecture
du résultat ne présume rien : elle s'appuie sur ce que le serveur récepteur a
réellement fait (dossier de dépôt, verdicts SPF/DKIM/DMARC qu'il a stampés),
croisé avec la politique publiée par le domaine usurpé.
"""

from __future__ import annotations

from .models import (
    AuthResults,
    DeliveryResult,
    Disposition,
    ForgedMessage,
    ForgeMode,
    ScenarioResult,
    SmtpResult,
    SpoofScenario,
)

DEFAULT_SCENARIOS: tuple[SpoofScenario, ...] = (
    SpoofScenario(
        id="exact",
        name="Usurpation directe",
        goal=(
            "Envoyer un message dont l'expéditeur (enveloppe ET en-tête) est le "
            "domaine cible, depuis une IP non autorisée. Met à l'épreuve la "
            "politique DMARC de la cible et son application par le récepteur."
        ),
        mode=ForgeMode.EXACT,
    ),
    SpoofScenario(
        id="realistic",
        name="Usurpation réaliste (attaquant)",
        goal=(
            "Le spoof qu'un vrai attaquant enverrait : nom d'affichage crédible "
            "(« Cible <no-reply@cible> »), sujet neutre, corps HTML bénin, aucun "
            "signal auto-infligé. Mesure ce qui passe réellement quand seule la "
            "défense anti-usurpation du récepteur est en jeu."
        ),
        mode=ForgeMode.REALISTIC,
    ),
    SpoofScenario(
        id="subdomain",
        name="Usurpation de sous-domaine",
        goal=(
            "From: sur un sous-domaine inexistant de la cible. Vérifie que la "
            "politique de sous-domaine (sp=) est bien restrictive."
        ),
        mode=ForgeMode.SUBDOMAIN,
    ),
    SpoofScenario(
        id="lookalike",
        name="Domaine sosie",
        goal=(
            "From: sur un domaine ressemblant (homoglyphe/typo). Le sosie n'a "
            "aucune politique : le test montre s'il atteint la boîte de réception."
        ),
        mode=ForgeMode.LOOKALIKE,
    ),
    SpoofScenario(
        id="display-name",
        name="Nom d'affichage trompeur",
        goal=(
            "Adresse honnête mais nom affichant la cible (« Cible — Support »). "
            "Passe l'authentification et ne trompe que l'œil : le plus efficace "
            "en pratique (BEC). Le plus parlant via un relais authentifié."
        ),
        mode=ForgeMode.DISPLAY_NAME,
        note="En envoi direct (IP non autorisée), ce scénario échoue à "
        "l'authentification comme les autres ; passe-le via --mode relais pour "
        "isoler la tromperie visuelle seule.",
    ),
)


def get_scenarios(ids: tuple[str, ...] = ()) -> list[SpoofScenario]:
    """Retourne les scénarios demandés, ou tous par défaut."""
    if not ids:
        return list(DEFAULT_SCENARIOS)
    wanted = {i.strip().lower() for i in ids}
    return [s for s in DEFAULT_SCENARIOS if s.id in wanted]


# ---------------------------------------------------------------------------
# Interprétation
# ---------------------------------------------------------------------------


def classify_disposition(smtp: SmtpResult, delivery: DeliveryResult) -> Disposition:
    """Déduit ce qu'est devenu le message à partir des faits bruts.

    L'étape d'échec (`stage`) prime sur le code : un refus au HELO est une
    erreur de notre configuration, pas une défense de la cible ; une connexion
    qui n'aboutit pas ne dit rien de la cible non plus.
    """
    if smtp.accepted is None:
        return Disposition.DRY_RUN

    if not smtp.accepted:
        if smtp.stage == "helo":
            return Disposition.SEND_ERROR
        if smtp.stage in ("resolve", "connect", "auth") or smtp.code is None:
            return Disposition.NOT_SENT
        if 400 <= smtp.code < 500:
            return Disposition.DEFERRED
        return Disposition.REJECTED

    # Accepté en SMTP : c'est la relecture IMAP qui tranche.
    if delivery.arrived:
        return Disposition.QUARANTINE if delivery.is_junk else Disposition.DELIVERED
    return Disposition.DROPPED


def interpret(
    scenario: SpoofScenario,
    disposition: Disposition,
    delivery: DeliveryResult,
    smtp: SmtpResult,
    *,
    target: str,
    target_policy: str | None,
) -> str:
    """Rédige la lecture d'un résultat, croisée avec la politique de la cible."""
    auth = _auth_summary(delivery.auth)

    if disposition is Disposition.DRY_RUN:
        return "Simulation : message construit, aucun envoi réel."

    if disposition is Disposition.SEND_ERROR:
        detail = smtp.message or smtp.error or "refus au dialogue SMTP"
        return (
            f"Le serveur a refusé notre envoi ({detail}). Ce n'est pas une défense "
            "de la cible mais un réglage à corriger de notre côté : renseigne "
            "DA_SEND_HELO avec un FQDN valide (le reverse DNS de la machine "
            f"d'envoi ; auto-détecté : « {smtp.helo or 'aucun'} »)."
        )

    if disposition is Disposition.NOT_SENT:
        reason = smtp.error or "MX injoignable"
        return (
            f"Connexion impossible ({reason}) — souvent un port 25 sortant filtré. "
            "Lance le test depuis une machine dont le port 25 est ouvert."
        )

    if disposition is Disposition.REJECTED:
        return (
            f"Le récepteur a refusé le message pendant la session SMTP{auth}. "
            "Défense forte : l'usurpation n'a même pas été mise en file."
        )

    if disposition is Disposition.DEFERRED:
        return (
            "Message différé (probable greylisting). Relance dans quelques minutes "
            "pour obtenir un verdict définitif."
        )

    if disposition is Disposition.DROPPED:
        return (
            f"Accepté en SMTP puis introuvable en boîte{auth}. Il a probablement "
            "été rejeté après acceptation ou classé hors des dossiers relus."
        )

    if disposition is Disposition.QUARANTINE:
        return (
            f"Rangé en indésirables{auth}. L'usurpation est repérée mais pas "
            "bloquée : l'utilisateur peut encore consulter le message."
        )

    # DELIVERED — l'usurpation a réussi. On qualifie la gravité selon la cible.
    base = f"⚠️ Arrivé en BOÎTE DE RÉCEPTION{auth}. L'usurpation a réussi contre ce récepteur."
    if scenario.mode is ForgeMode.DISPLAY_NAME:
        return base + (
            " Attendu pour un nom d'affichage : l'adresse est honnête, seule "
            "l'étiquette trompe. La parade est côté client (afficher l'adresse réelle)."
        )
    if scenario.mode is ForgeMode.LOOKALIKE:
        return base + (
            " Le domaine sosie n'ayant aucune politique, il passe : à surveiller "
            "par de la veille de domaines proches et du filtrage anti-lookalike."
        )
    if target_policy == "reject":
        return base + (
            f" Or « {target} » publie p=reject : c'est donc le récepteur qui "
            "n'applique pas DMARC. À corriger côté serveur récepteur."
        )
    if target_policy in ("none", None):
        return base + (
            f" « {target} » n'a pas de politique DMARC contraignante (p="
            f"{target_policy or 'absente'}) : n'importe qui peut l'usurper partout."
        )
    return base


def _auth_summary(auth: AuthResults) -> str:
    parts = []
    if auth.spf:
        parts.append(f"spf={auth.spf}")
    if auth.dkim:
        parts.append(f"dkim={auth.dkim}")
    if auth.dmarc:
        parts.append(f"dmarc={auth.dmarc}")
    return f" (verdict récepteur : {', '.join(parts)})" if parts else ""


def build_result(
    scenario: SpoofScenario,
    message: ForgedMessage,
    smtp: SmtpResult,
    delivery: DeliveryResult,
    *,
    target: str,
    target_policy: str | None,
) -> ScenarioResult:
    disposition = classify_disposition(smtp, delivery)
    interpretation = interpret(
        scenario, disposition, delivery, smtp, target=target, target_policy=target_policy
    )
    return ScenarioResult(
        scenario=scenario,
        message=message,
        smtp=smtp,
        delivery=delivery,
        disposition=disposition,
        interpretation=interpretation,
    )
