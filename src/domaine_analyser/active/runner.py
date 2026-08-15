"""Orchestration d'une campagne de tests d'usurpation.

Séquence, dans cet ordre non négociable :

1. **Sûreté d'abord.** On vérifie la configuration, le consentement, puis on
   prouve le contrôle de la boîte par une connexion IMAP. Rien n'est envoyé
   avant cette preuve.
2. **Envoi.** Chaque scénario forge un message et le remet, espacé pour ne pas
   marteler le récepteur, dans la limite du budget de messages.
3. **Relecture.** On attend l'arrivée des jetons en IMAP, avec un délai borné.
4. **Verdict.** On croise ce que le récepteur a fait avec la politique publiée
   par le domaine usurpé.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime, timezone

from ..analyze.dmarc import analyze_dmarc
from ..config import Settings
from ..net.resolver import DnsResolver
from . import imap_verify, message, safety, scenarios, smtp_send
from .models import (
    CampaignResult,
    DeliveryResult,
    ForgedMessage,
    ScenarioResult,
    SmtpResult,
    SpoofScenario,
)
from .settings import MailTestConfig

#: Type du rappel de progression (pour la CLI et la future TUI).
ProgressFn = Callable[[str, str], None]


def run_spoof_campaign(
    mail_config: MailTestConfig,
    target: str,
    *,
    settings: Settings,
    selected: list[SpoofScenario] | None = None,
    dry_run: bool = False,
    cleanup: bool = False,
    on_progress: ProgressFn | None = None,
) -> CampaignResult:
    """Exécute la campagne et retourne le résultat consolidé."""
    target = target.strip().rstrip(".").lower()
    resolver = DnsResolver(settings)
    mailbox = mail_config.mailbox

    # En simulation, on peut prévisualiser les messages sans boîte configurée :
    # on substitue un destinataire fictif, jamais utilisé pour un envoi réel.
    placeholder_used = False
    if dry_run and not mailbox.address:
        from .settings import MailboxAccess

        mailbox = MailboxAccess(address="failtest@example.test", imap_host="imap.example.test")
        placeholder_used = True

    recipient = mailbox.address

    def emit(stage: str, detail: str) -> None:
        if on_progress:
            on_progress(stage, detail)

    campaign = CampaignResult(
        target=target,
        mailbox_address=recipient,
        started_at=datetime.now(tz=timezone.utc),
        dry_run=dry_run,
    )

    # -- 1. sûreté ----------------------------------------------------------
    if not dry_run:
        safety.assert_ready(
            mailbox_configured=mailbox.configured, acknowledged=mail_config.acknowledged
        )
        emit("safety", f"preuve de possession de {recipient} (IMAP)…")
        if not imap_verify.verify_login(mailbox):
            raise safety.SafetyError(
                f"Connexion IMAP à {recipient} impossible : le contrôle de la boîte "
                "n'est pas prouvé, la campagne est refusée."
            )
    # Défense en profondeur, quel que soit le mode.
    safety.assert_recipient_is_owned(recipient, mailbox.address)

    campaign.target_policy = _target_policy(resolver, target)

    all_scenarios = selected if selected is not None else scenarios.get_scenarios()
    budget = safety.enforce_message_budget(len(all_scenarios), mail_config.max_messages)
    run_list = all_scenarios[:budget]
    if budget < len(all_scenarios):
        campaign.notes.append(
            f"Budget limité à {budget} messages ; {len(all_scenarios) - budget} scénario(s) omis."
        )
    if dry_run:
        campaign.notes.append("Simulation (--dry-run) : aucun message n'a été émis.")
    if placeholder_used:
        campaign.notes.append(
            "Boîte non configurée : aperçu construit avec un destinataire fictif "
            "(failtest@example.test)."
        )

    # -- 2. envoi -----------------------------------------------------------
    outcomes: list[tuple[SpoofScenario, ForgedMessage, SmtpResult]] = []
    tokens: set[str] = set()
    for index, scenario in enumerate(run_list):
        token = safety.new_token()
        tokens.add(token)
        forged = message.build_forged_message(
            scenario, target=target, mailbox=mailbox, token=token
        )
        emit("send", f"{scenario.name} — From: {forged.from_header}")

        if dry_run:
            smtp = SmtpResult(accepted=None, message="dry-run")
        else:
            smtp = smtp_send.send_message(
                mail_config.send, forged, recipient, resolver=resolver
            )
            if index < len(run_list) - 1:
                time.sleep(mail_config.send_delay)
        outcomes.append((scenario, forged, smtp))

    # -- 3. relecture -------------------------------------------------------
    deliveries: dict[str, DeliveryResult] = {}
    if not dry_run and any(o[2].accepted for o in outcomes):
        emit("verify", f"attente des messages en IMAP (≤ {mail_config.verify_timeout:.0f}s)…")
        deliveries = imap_verify.wait_for_tokens(
            mailbox, tokens, timeout=mail_config.verify_timeout
        )

    # -- 4. verdict ---------------------------------------------------------
    for scenario, forged, smtp in outcomes:
        delivery = deliveries.get(forged.token, DeliveryResult())
        result: ScenarioResult = scenarios.build_result(
            scenario, forged, smtp, delivery, target=target, target_policy=campaign.target_policy
        )
        campaign.results.append(result)
        emit("result", f"{scenario.name} → {result.disposition.label_fr}")

    if cleanup and not dry_run:
        removed = imap_verify.cleanup_tokens(mailbox, tokens)
        if removed:
            campaign.notes.append(f"{removed} message(s)-test supprimé(s) de la boîte.")

    return campaign


def _target_policy(resolver: DnsResolver, target: str) -> str | None:
    """Politique DMARC publiée par le domaine usurpé (pour l'interprétation)."""
    try:
        dmarc_txt = resolver.txt(f"_dmarc.{target}")
        analysis = analyze_dmarc(resolver, target, dmarc_txt, check_external=False)
    except Exception:
        return None
    if analysis.multiple_records or analysis.malformed:
        return "none"  # une politique cassée équivaut à aucune protection
    return analysis.policy
