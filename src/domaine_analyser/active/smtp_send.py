"""Émission des messages-tests.

Deux chemins. En **direct**, on se connecte au MX du destinataire sur le port
25 et on remet le message comme le ferait un spoofeur externe — c'est le test
le plus réaliste, mais il exige un port 25 sortant ouvert. En **relais**, on
passe par un serveur SMTP authentifié (utile si le port 25 est filtré, ou pour
n'exercer que la tromperie par nom d'affichage depuis un compte légitime).

On capture le code de réponse à chaque étape (MAIL FROM, RCPT TO, DATA), car
c'est là que se lit une défense forte : un récepteur qui applique DMARC en ligne
refuse dès le RCPT, avant même de recevoir le corps.
"""

from __future__ import annotations

import smtplib
import ssl

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
        return SmtpResult(accepted=False, error=f"aucun MX ni A pour {domain}")

    last_error: str | None = None
    for host in mx_hosts:
        try:
            with smtplib.SMTP(host, _SMTP_PORT, timeout=config.timeout) as server:
                if config.helo:
                    server.local_hostname = config.helo
                server.ehlo_or_helo_if_needed()

                used_tls = False
                if config.starttls and server.has_extn("starttls"):
                    server.starttls(context=_unverified_context())
                    server.ehlo()
                    used_tls = True

                return _transact(server, message, recipient, host, used_tls)
        except (smtplib.SMTPConnectError, TimeoutError, ConnectionError, OSError) as exc:
            # Échec au niveau connexion : on tente le MX suivant. La cause la
            # plus fréquente ici est un port 25 sortant filtré par le FAI.
            last_error = f"{type(exc).__name__}: {exc}"
            continue
        except smtplib.SMTPException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            continue

    return SmtpResult(accepted=False, error=last_error or "connexion impossible à tous les MX")


def _send_via_relay(config: SendConfig, message: ForgedMessage, recipient: str) -> SmtpResult:
    if not config.relay_configured:
        return SmtpResult(accepted=False, error="mode relais demandé mais DA_SMTP_RELAY_HOST vide")

    try:
        if config.relay_port == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                config.relay_host, 465, timeout=config.timeout, context=ssl.create_default_context()
            )
        else:
            server = smtplib.SMTP(config.relay_host, config.relay_port, timeout=config.timeout)
        with server:
            if config.helo:
                server.local_hostname = config.helo
            server.ehlo_or_helo_if_needed()
            used_tls = config.relay_port == 465
            if config.relay_port != 465 and server.has_extn("starttls"):
                # Sur un relais authentifié, on vérifie le certificat.
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                used_tls = True
            if config.relay_user:
                server.login(config.relay_user, config.relay_password)
            return _transact(server, message, recipient, config.relay_host, used_tls)
    except smtplib.SMTPAuthenticationError as exc:
        return SmtpResult(accepted=False, error=f"authentification relais refusée: {exc}")
    except (smtplib.SMTPException, OSError) as exc:
        return SmtpResult(accepted=False, error=f"{type(exc).__name__}: {exc}")


def _transact(
    server: smtplib.SMTP,
    message: ForgedMessage,
    recipient: str,
    host: str,
    used_tls: bool,
) -> SmtpResult:
    """Déroule MAIL FROM / RCPT TO / DATA en capturant chaque code."""
    code, resp = server.mail(message.envelope_from)
    if code >= 400:
        return _refusal(code, resp, host, used_tls, stage="MAIL FROM")

    code, resp = server.rcpt(recipient)
    if code >= 400:
        # Un refus ici = le récepteur bloque avant d'accepter le corps.
        return _refusal(code, resp, host, used_tls, stage="RCPT TO")

    code, resp = server.data(message.raw)
    accepted = 200 <= code < 300
    return SmtpResult(
        accepted=accepted,
        code=code,
        message=_decode(resp),
        mx_host=host,
        used_starttls=used_tls,
        error=None if accepted else f"DATA a répondu {code}",
    )


def _refusal(code: int, resp: bytes, host: str, used_tls: bool, *, stage: str) -> SmtpResult:
    return SmtpResult(
        accepted=False,
        code=code,
        message=f"{stage}: {_decode(resp)}",
        mx_host=host,
        used_starttls=used_tls,
    )


def _decode(resp: bytes | str) -> str:
    if isinstance(resp, bytes):
        return resp.decode("utf-8", errors="replace").strip()
    return str(resp).strip()
