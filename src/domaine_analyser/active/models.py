"""Types des tests actifs.

Comme pour l'audit passif, la mesure et son interprétation sont séparées. Les
résultats bruts — code SMTP, dossier de dépôt, en-tête `Authentication-Results`
stampé par le récepteur — sont des faits. Le verdict n'en est qu'une lecture,
recalculable, jamais figée dans la collecte.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ForgeMode(str, Enum):
    """Comment l'expéditeur est falsifié dans un scénario."""

    EXACT = "exact"  # From: et enveloppe = domaine cible, adresse nue
    REALISTIC = "realistic"  # spoof soigné : nom d'affichage, sujet et corps crédibles
    SUBDOMAIN = "subdomain"  # From: = sous-domaine inexistant de la cible
    LOOKALIKE = "lookalike"  # From: = domaine sosie de la cible
    DISPLAY_NAME = "display_name"  # nom d'affichage trompeur, adresse honnête


@dataclass(frozen=True, slots=True)
class SpoofScenario:
    """Un scénario d'usurpation à tester."""

    id: str
    name: str
    goal: str  # ce que le scénario cherche à mettre en évidence
    mode: ForgeMode
    note: str = ""


class Disposition(str, Enum):
    """Ce que le serveur récepteur a fait du message."""

    REJECTED = "rejected"  # refusé par le récepteur (MAIL/RCPT/DATA en 5xx)
    DROPPED = "dropped"  # accepté puis disparu (ni inbox ni spam)
    QUARANTINE = "quarantine"  # rangé en indésirables
    DELIVERED = "delivered"  # arrivé en boîte de réception
    DEFERRED = "deferred"  # différé (4xx / greylisting)
    PENDING = "pending"  # envoi effectué, vérification non concluante
    NOT_SENT = "not_sent"  # connexion impossible (port 25 filtré, MX injoignable)
    SEND_ERROR = "send_error"  # notre configuration d'envoi est fautive (HELO…)
    DRY_RUN = "dry_run"  # simulation, aucun envoi réel

    @property
    def label_fr(self) -> str:
        return _DISPOSITION_LABEL[self]

    @property
    def spoof_succeeded(self) -> bool:
        """Vrai si l'usurpation a atteint la boîte de réception."""
        return self is Disposition.DELIVERED


_DISPOSITION_LABEL: dict[Disposition, str] = {
    Disposition.REJECTED: "Rejeté à la connexion",
    Disposition.DROPPED: "Accepté puis supprimé",
    Disposition.QUARANTINE: "Mis en quarantaine (indésirables)",
    Disposition.DELIVERED: "Délivré en boîte de réception",
    Disposition.DEFERRED: "Différé (greylisting ?)",
    Disposition.PENDING: "Indéterminé",
    Disposition.NOT_SENT: "Non envoyé (injoignable)",
    Disposition.SEND_ERROR: "Erreur d'envoi (config)",
    Disposition.DRY_RUN: "Simulation",
}


@dataclass(slots=True)
class ForgedMessage:
    """Le message construit pour un scénario, prêt à être émis."""

    token: str
    scenario_id: str
    from_header: str  # valeur affichée dans From:
    envelope_from: str  # MAIL FROM de l'enveloppe SMTP
    subject: str
    raw: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "scenario_id": self.scenario_id,
            "from_header": self.from_header,
            "envelope_from": self.envelope_from,
            "subject": self.subject,
            "size_bytes": len(self.raw),
        }


@dataclass(slots=True)
class SmtpResult:
    """Issue de la remise SMTP au MX du destinataire."""

    accepted: bool | None  # None = pas d'envoi (dry-run)
    code: int | None = None
    message: str = ""
    error: str | None = None
    mx_host: str | None = None
    used_starttls: bool = False
    #: Étape où l'échec s'est produit : resolve, connect, helo, mailfrom, rcpt,
    #: data. Décisif pour distinguer « injoignable » de « refusé par le serveur ».
    stage: str | None = None
    helo: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "code": self.code,
            "message": self.message[:200],
            "error": self.error,
            "mx_host": self.mx_host,
            "used_starttls": self.used_starttls,
            "stage": self.stage,
            "helo": self.helo,
        }


@dataclass(slots=True)
class AuthResults:
    """Verdicts d'authentification stampés par le serveur récepteur.

    C'est la mesure la plus fiable : elle vient du récepteur lui-même, pas de
    notre interprétation. Un champ à None signifie que le récepteur ne l'a pas
    renseigné.
    """

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    compauth: str | None = None
    raw: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "spf": self.spf,
            "dkim": self.dkim,
            "dmarc": self.dmarc,
            "compauth": self.compauth,
        }


@dataclass(slots=True)
class DeliveryResult:
    """Ce que la relecture IMAP a trouvé pour un jeton donné."""

    arrived: bool = False
    folder: str | None = None
    is_junk: bool = False
    auth: AuthResults = field(default_factory=AuthResults)
    received_count: int = 0
    seen_from: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "arrived": self.arrived,
            "folder": self.folder,
            "is_junk": self.is_junk,
            "auth": self.auth.to_dict(),
            "received_count": self.received_count,
            "seen_from": self.seen_from,
        }


@dataclass(slots=True)
class ScenarioResult:
    scenario: SpoofScenario
    message: ForgedMessage
    smtp: SmtpResult
    delivery: DeliveryResult
    disposition: Disposition
    interpretation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": {
                "id": self.scenario.id,
                "name": self.scenario.name,
                "mode": self.scenario.mode.value,
            },
            "message": self.message.to_dict(),
            "smtp": self.smtp.to_dict(),
            "delivery": self.delivery.to_dict(),
            "disposition": self.disposition.value,
            "disposition_label": self.disposition.label_fr,
            "interpretation": self.interpretation,
        }


@dataclass(slots=True)
class CampaignResult:
    """Résultat d'une campagne de tests contre un domaine usurpé."""

    target: str  # domaine dont on a usurpé l'identité
    mailbox_address: str  # destinataire (boîte contrôlée)
    started_at: datetime
    dry_run: bool = False
    target_policy: str | None = None  # politique DMARC de la cible, si connue
    results: list[ScenarioResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def breaches(self) -> list[ScenarioResult]:
        """Scénarios où l'usurpation a atteint la boîte de réception."""
        return [r for r in self.results if r.disposition.spoof_succeeded]

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "mailbox_address": self.mailbox_address,
            "started_at": self.started_at.isoformat(),
            "dry_run": self.dry_run,
            "target_policy": self.target_policy,
            "breaches": len(self.breaches),
            "results": [r.to_dict() for r in self.results],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Sonde de transport MX (passive)
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MxTlsResult:
    """État TLS/SMTP d'un hôte MX, obtenu sans envoyer de message."""

    mx_host: str
    preference: int
    connected: bool = False
    banner: str | None = None
    esmtp_features: list[str] = field(default_factory=list)
    starttls_offered: bool = False
    tls_version: str | None = None
    cert_subject: str | None = None
    cert_issuer: str | None = None
    cert_not_after: str | None = None
    cert_matches_host: bool | None = None
    auth_mechanisms: list[str] = field(default_factory=list)
    requires_auth_before_tls: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mx_host": self.mx_host,
            "preference": self.preference,
            "connected": self.connected,
            "banner": self.banner,
            "starttls_offered": self.starttls_offered,
            "tls_version": self.tls_version,
            "cert_subject": self.cert_subject,
            "cert_issuer": self.cert_issuer,
            "cert_not_after": self.cert_not_after,
            "cert_matches_host": self.cert_matches_host,
            "auth_mechanisms": list(self.auth_mechanisms),
            "error": self.error,
        }
