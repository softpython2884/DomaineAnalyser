"""Configuration des tests actifs, lue depuis l'environnement / .env.

Séparée de `config.Settings` (audit passif) parce qu'elle porte des
identifiants sensibles — mot de passe IMAP, éventuel relais SMTP — et ne
concerne qu'un sous-système optionnel. Rien ici n'est requis pour l'audit.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from ..config import load_settings


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or "").strip() or default


def _env_int(key: str, default: int) -> int:
    raw = _env(key)
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = _env(key).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "oui")


@dataclass(slots=True)
class MailboxAccess:
    """La boîte de vérification — et donc l'unique destinataire autorisé.

    L'adresse `address` est celle à laquelle les messages-tests sont livrés ;
    les identifiants IMAP servent à la fois à relire les résultats et à *prouver*
    que l'opérateur contrôle bien cette boîte. Les deux sont indissociables :
    c'est ce lien qui empêche de tester une boîte qu'on ne possède pas.
    """

    address: str
    imap_host: str
    imap_port: int = 993
    imap_ssl: bool = True
    imap_user: str = ""
    imap_password: str = ""

    def __post_init__(self) -> None:
        if not self.imap_user:
            self.imap_user = self.address

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2].lower()

    @property
    def configured(self) -> bool:
        return bool(self.address and "@" in self.address and self.imap_host and self.imap_password)


@dataclass(slots=True)
class SendConfig:
    """Comment et d'où le message forgé est émis.

    `direct` : connexion directe au MX du destinataire, comme le ferait un
    spoofeur externe. Réaliste, mais nécessite le port 25 sortant ouvert.
    `relay` : passage par un serveur SMTP authentifié (utile si le port 25 est
    filtré, ou pour tester une usurpation par nom d'affichage depuis un compte
    légitime).
    """

    mode: str = "direct"  # direct | relay
    helo: str = ""  # nom présenté en EHLO ; défaut = nom d'hôte de la machine
    timeout: float = 30.0
    starttls: bool = True  # STARTTLS opportuniste en mode direct
    relay_host: str = ""
    relay_port: int = 587
    relay_user: str = ""
    relay_password: str = ""

    @property
    def relay_configured(self) -> bool:
        return bool(self.relay_host)


@dataclass(slots=True)
class MailTestConfig:
    mailbox: MailboxAccess
    send: SendConfig
    #: L'opérateur reconnaît mener un test autorisé (DA_TEST_ACK). Garde-fou de
    #: consentement, distinct de la preuve technique de possession de la boîte.
    acknowledged: bool = False
    #: Plafond dur du nombre de messages par campagne — anti-emballement.
    max_messages: int = 25
    #: Délai entre deux envois, pour ne pas marteler le MX récepteur.
    send_delay: float = 1.0
    #: Durée d'attente de l'arrivée des messages en IMAP.
    verify_timeout: float = 120.0

    @property
    def ready(self) -> bool:
        return self.mailbox.configured


def load_mail_test_config() -> MailTestConfig:
    """Assemble la configuration des tests actifs depuis l'environnement."""
    # Déclenche le chargement du .env (mis en cache par load_settings).
    load_settings()

    mailbox = MailboxAccess(
        address=_env("DA_TEST_MAILBOX") or _env("DA_IMAP_USER"),
        imap_host=_env("DA_IMAP_HOST"),
        imap_port=_env_int("DA_IMAP_PORT", 993),
        imap_ssl=_env_bool("DA_IMAP_SSL", True),
        imap_user=_env("DA_IMAP_USER"),
        imap_password=_env("DA_IMAP_PASSWORD"),
    )

    send = SendConfig(
        mode=_env("DA_SEND_MODE", "direct").lower(),
        helo=_env("DA_SEND_HELO"),
        timeout=float(_env_int("DA_SEND_TIMEOUT", 30)),
        starttls=_env_bool("DA_SEND_STARTTLS", True),
        relay_host=_env("DA_SMTP_RELAY_HOST"),
        relay_port=_env_int("DA_SMTP_RELAY_PORT", 587),
        relay_user=_env("DA_SMTP_RELAY_USER"),
        relay_password=_env("DA_SMTP_RELAY_PASSWORD"),
    )

    return MailTestConfig(
        mailbox=mailbox,
        send=send,
        acknowledged=_env_bool("DA_TEST_ACK", False),
        max_messages=_env_int("DA_TEST_MAX_MESSAGES", 25),
        send_delay=float(_env_int("DA_TEST_SEND_DELAY", 1)),
        verify_timeout=float(_env_int("DA_TEST_VERIFY_TIMEOUT", 120)),
    )
