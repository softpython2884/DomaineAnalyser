"""Garde-fous des tests actifs.

Ce module concentre les invariants qui font de l'outil un dispositif d'auto-test
et non un moteur d'envoi anonyme. Ils sont volontairement regroupés ici pour
être lisibles d'un coup d'œil et testables isolément.

Invariant central : **on ne livre qu'à la boîte dont on a prouvé le contrôle.**
La preuve est une connexion IMAP réussie à cette boîte (voir `imap_verify`).
Le runner refuse de démarrer sans elle, et refuse tout destinataire qui ne
serait pas exactement cette boîte.
"""

from __future__ import annotations

import secrets

#: Marqueur humain présent dans le sujet et le corps de chaque message.
MARKER = "Test de sécurité DomaineAnalyser"

#: En-têtes techniques ajoutés à chaque message, pour la corrélation IMAP et
#: pour qu'un administrateur reconnaisse immédiatement un test.
TOKEN_HEADER = "X-DomaineAnalyser-Test"
SCENARIO_HEADER = "X-DomaineAnalyser-Scenario"


class SafetyError(Exception):
    """Levée quand un invariant de sûreté n'est pas satisfait.

    N'est jamais rattrapée silencieusement : elle interrompt la campagne.
    """


def new_token() -> str:
    """Jeton unique et imprévisible identifiant un message-test.

    Sert de clé de corrélation entre l'envoi et la relecture IMAP. Imprévisible
    (secrets) pour qu'un tiers ne puisse pas deviner le sujet d'un test et le
    fabriquer.
    """
    return f"DAT-{secrets.token_hex(8)}"


def normalize_address(address: str) -> str:
    return address.strip().strip("<>").lower()


def assert_recipient_is_owned(recipient: str, owned_mailbox: str) -> None:
    """Vérifie que le destinataire est exactement la boîte contrôlée.

    Défense en profondeur : par construction le runner n'envoie qu'à
    `owned_mailbox`, mais cette assertion garantit qu'aucune évolution du code
    ne pourra livrer ailleurs sans échouer bruyamment.
    """
    if normalize_address(recipient) != normalize_address(owned_mailbox):
        raise SafetyError(
            "Destinataire refusé : les tests actifs ne peuvent livrer qu'à la boîte "
            f"dont le contrôle est prouvé ({owned_mailbox}), pas à {recipient}."
        )


def assert_ready(*, mailbox_configured: bool, acknowledged: bool) -> None:
    """Vérifie les préconditions avant toute campagne réelle."""
    if not mailbox_configured:
        raise SafetyError(
            "Boîte de vérification non configurée. Renseigne DA_IMAP_HOST, "
            "DA_IMAP_USER et DA_IMAP_PASSWORD dans .env — l'outil doit pouvoir "
            "relire la boîte pour prouver que tu la contrôles."
        )
    if not acknowledged:
        raise SafetyError(
            "Consentement manquant. Mets DA_TEST_ACK=true dans .env pour confirmer "
            "que tu mènes un test autorisé sur une infrastructure que tu possèdes "
            "ou pour laquelle tu as reçu une autorisation."
        )


def enforce_message_budget(requested: int, maximum: int) -> int:
    """Borne le nombre de messages d'une campagne (anti-emballement)."""
    if requested <= 0:
        return 0
    return min(requested, maximum)


def build_body(token: str, scenario_name: str, target: str) -> str:
    """Corps du message-test : explicite, traçable, sans ambiguïté.

    Un administrateur qui tombe dessus doit comprendre en une ligne que c'est
    un test contrôlé, et pouvoir remonter à son auteur.
    """
    return (
        f"{MARKER}\n"
        "Powered by ForgeNetwork\n"
        "\n"
        "Ceci est un message de test de sécurité email, émis dans le cadre d'une\n"
        "évaluation autorisée de la résistance à l'usurpation.\n"
        "\n"
        f"  Scénario  : {scenario_name}\n"
        f"  Cible      : usurpation de l'identité « {target} »\n"
        f"  Jeton      : {token}\n"
        "\n"
        "Aucune action n'est attendue. Si vous recevez ce message sans en être\n"
        "l'auteur, un test a été mal configuré : ignorez-le et signalez-le.\n"
    )
