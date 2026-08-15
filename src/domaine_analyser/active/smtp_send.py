"""Émission des messages-tests.

Deux chemins. En **direct**, on se connecte au MX du destinataire sur le port
25 et on remet le message comme le ferait un spoofeur externe — c'est le test
le plus réaliste, mais il exige un port 25 sortant ouvert. En **relais**, on
passe par un serveur SMTP authentifié (utile si le port 25 est filtré, ou pour
n'exercer que la tromperie par nom d'affichage depuis un compte légitime).

On distingue soigneusement *où* une remise échoue. Un échec de connexion (MX
injoignable, port filtré) n'a rien à voir avec un refus du serveur pendant le
dialogue SMTP : le premier n'apprend rien sur la cible, le second est justement
la défense qu'on cherche à mesurer. Le champ `stage` de `SmtpResult` porte cette
distinction.
"""

from __future__ import annotations

import contextlib
import smtplib
import socket
import ssl
from functools import lru_cache

from ..net.resolver import DnsResolver, parse_mx_value
from .models import ForgedMessage, SmtpResult
from .settings import SendConfig

_SMTP_PORT = 25


def resolve_mx(resolver: DnsResolver, domain: str) -> list[str]:
    """Hôtes MX du domaine, par préférence croissante.

    Sans MX, la RFC 5321 §5.1 impose de se rabattre sur l'enregistrement A du
    domaine (« implicit MX ») — c'est ce que fait tout MTA.
    """
    rrset = resolver.query(domain, "MX")
    hosts: list[str] = []
    if rrset.ok and rrset.values:
        parsed = sorted(parse_mx_value(v) for v in rrset.values)
        hosts = [host for _, host in parsed if host not in (".", "")]
    if not hosts and resolver.query(domain, "A").values:
        hosts = [domain]
    return hosts


def _valid_fqdn(name: str) -> bool:
    name = (name or "").strip().strip(".").lower()
    return "." in name and not name.startswith("localhost") and name != "localhost.localdomain"


@lru_cache(maxsize=1)
def _autodetect_helo() -> str:
    """Devine un nom HELO valide pour la machine d'envoi.

    Un serveur strict (Stalwart, Postfix avec `reject_non_fqdn_helo`) refuse un
    HELO qui n'est pas un FQDN. Le nom d'hôte brut d'un serveur (« srv01 ») ne
    passe pas. On tente donc, dans l'ordre : le FQDN système, puis le reverse
    DNS de l'IP de sortie — le nom qu'un récepteur verrait de toute façon.
    """
    fqdn = socket.getfqdn()
    if _valid_fqdn(fqdn):
        return fqdn
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("1.1.1.1", 53))  # UDP : aucun paquet émis
        ip = probe.getsockname()[0]
        probe.close()
        name = socket.gethostbyaddr(ip)[0]
        if _valid_fqdn(name):
            return name
    except OSError:
        pass
    return ""


def effective_helo(config: SendConfig, fallback_domain: str) -> str:
    """Nom HELO effectif : override explicite, sinon auto-détection, sinon repli."""
    return config.helo or _autodetect_helo() or fallback_domain


def _unverified_context() -> ssl.SSLContext:
    """Contexte TLS opportuniste pour le port 25.

    Le chiffrement inter-MTA est opportuniste : le certificat n'a pas à être
    valide pour que la remise ait lieu. On ne vérifie donc pas ici — l'analyse
    du certificat, elle, relève de la sonde MX dédiée.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send_message(
    config: SendConfig,
    message: ForgedMessage,
    recipient: str,
    *,
    resolver: DnsResolver,
) -> SmtpResult:
    """Émet un message selon le mode configuré."""
    if config.mode == "relay":
        return _send_via_relay(config, message, recipient)
    return _send_direct(config, message, recipient, resolver=resolver)


def _send_direct(
    config: SendConfig,
    message: ForgedMessage,
    recipient: str,
    *,
    resolver: DnsResolver,
) -> SmtpResult:
    domain = recipient.rpartition("@")[2].lower()
    mx_hosts = resolve_mx(resolver, domain)
    if not mx_hosts:
        return SmtpResult(accepted=False, error=f"aucun MX ni A pour {domain}", stage="resolve")

    helo = effective_helo(config, domain)
    conn_error: str | None = None

    for host in mx_hosts:
        try:
            # Le host DOIT passer par le constructeur : c'est lui qui renseigne
            # self._host, ensuite réutilisé comme nom SNI par STARTTLS. Sans ça,
            # le handshake TLS lève « server_hostname cannot be empty ». La
            # connexion (et ses éventuelles erreurs) a lieu ici même.
            server = smtplib.SMTP(host, _SMTP_PORT, local_hostname=helo, timeout=config.timeout)
        except (OSError, smtplib.SMTPException) as exc:
            # Échec au niveau connexion : on tente le MX suivant. Cause la plus
            # fréquente : port 25 sortant filtré, ou MX injoignable.
            conn_error = f"{type(exc).__name__}: {exc}"
            continue

        # Connexion établie : au-delà, une erreur est un refus du serveur, pas
        # un défaut de joignabilité — inutile d'essayer un autre MX.
        try:
            return _handshake_and_send(server, config, message, recipient, host, helo)
        finally:
            with contextlib.suppress(Exception):
                server.quit()

    return SmtpResult(
        accepted=False,
        error=conn_error or "connexion impossible à tous les MX",
        stage="connect",
        helo=helo,
    )


def _handshake_and_send(
    server: smtplib.SMTP,
    config: SendConfig,
    message: ForgedMessage,
    recipient: str,
    host: str,
    helo: str,
) -> SmtpResult:
    try:
        server.ehlo_or_helo_if_needed()
    except smtplib.SMTPHeloError as exc:
        return SmtpResult(
            accepted=False,
            code=exc.smtp_code,
            message=f"HELO « {helo} » refusé : {_decode(exc.smtp_error)}",
            mx_host=host,
            stage="helo",
            helo=helo,
            error="helo_rejected",
        )
    except smtplib.SMTPException as exc:
        return SmtpResult(
            accepted=False, mx_host=host, stage="helo", helo=helo, error=f"{type(exc).__name__}: {exc}"
        )

    used_tls = False
    if config.starttls and server.has_extn("starttls"):
        try:
            server.starttls(context=_unverified_context())
            server.ehlo()
            used_tls = True
        except (smtplib.SMTPException, ssl.SSLError, ValueError, OSError):
            # STARTTLS a échoué : on poursuit en clair, la remise reste possible.
            # ValueError couvre les cas de nom SNI invalide ; on ne laisse jamais
            # un incident TLS faire tomber toute la campagne.
            pass

    return _transact(server, message, recipient, host, helo, used_tls)


def _send_via_relay(config: SendConfig, message: ForgedMessage, recipient: str) -> SmtpResult:
    if not config.relay_configured:
        return SmtpResult(
            accepted=False, error="mode relais demandé mais DA_SMTP_RELAY_HOST vide", stage="resolve"
        )

    helo = effective_helo(config, recipient.rpartition("@")[2].lower())
    try:
        if config.relay_port == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                config.relay_host,
                465,
                local_hostname=helo,
                timeout=config.timeout,
                context=ssl.create_default_context(),
            )
        else:
            server = smtplib.SMTP(
                config.relay_host, config.relay_port, local_hostname=helo, timeout=config.timeout
            )
        with server:
            server.ehlo_or_helo_if_needed()
            used_tls = config.relay_port == 465
            if config.relay_port != 465 and server.has_extn("starttls"):
                # Sur un relais authentifié, on vérifie le certificat.
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                used_tls = True
            if config.relay_user:
                server.login(config.relay_user, config.relay_password)
            return _transact(server, message, recipient, config.relay_host, helo, used_tls)
    except smtplib.SMTPAuthenticationError as exc:
        return SmtpResult(
            accepted=False, error=f"authentification relais refusée: {exc}", stage="auth", helo=helo
        )
    except (smtplib.SMTPException, OSError) as exc:
        return SmtpResult(accepted=False, error=f"{type(exc).__name__}: {exc}", stage="connect", helo=helo)


def _transact(
    server: smtplib.SMTP,
    message: ForgedMessage,
    recipient: str,
    host: str,
    helo: str,
    used_tls: bool,
) -> SmtpResult:
    """Déroule MAIL FROM / RCPT TO / DATA en capturant chaque code."""
    code, resp = server.mail(message.envelope_from)
    if code >= 400:
        return _refusal(code, resp, host, helo, used_tls, stage="mailfrom")

    code, resp = server.rcpt(recipient)
    if code >= 400:
        # Un refus ici = le récepteur bloque avant d'accepter le corps.
        return _refusal(code, resp, host, helo, used_tls, stage="rcpt")

    code, resp = server.data(message.raw)
    accepted = 200 <= code < 300
    return SmtpResult(
        accepted=accepted,
        code=code,
        message=_decode(resp),
        mx_host=host,
        helo=helo,
        used_starttls=used_tls,
        stage="data",
        error=None if accepted else f"DATA a répondu {code}",
    )


def _refusal(
    code: int, resp: bytes, host: str, helo: str, used_tls: bool, *, stage: str
) -> SmtpResult:
    return SmtpResult(
        accepted=False,
        code=code,
        message=f"{stage}: {_decode(resp)}",
        mx_host=host,
        helo=helo,
        used_starttls=used_tls,
        stage=stage,
    )


def _decode(resp: bytes | str) -> str:
    if isinstance(resp, bytes):
        return resp.decode("utf-8", errors="replace").strip()
    return str(resp).strip()
