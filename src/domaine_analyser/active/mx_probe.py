"""Sonde de transport des serveurs MX (sans envoi de message).

Se connecte à chaque MX, lit la bannière et les capacités ESMTP, tente
STARTTLS et inspecte le certificat présenté. Aucun message n'est jamais émis :
la session s'arrête à QUIT. C'est le seul test « actif » sûr à lancer contre
l'infrastructure d'un tiers, puisqu'il n'écrit rien dans ses journaux au-delà
d'une connexion SMTP ouverte puis refermée.

Le certificat est capturé même lorsqu'il est invalide (auto-signé, expiré,
mauvais nom) : la connexion TLS se fait sans vérification, et la validité est
ensuite jugée nous-mêmes avec `cryptography`. C'est justement l'invalidité qu'on
veut pouvoir signaler.
"""

from __future__ import annotations

import contextlib
import smtplib
import ssl

from cryptography import x509

from ..net.resolver import DnsResolver, parse_mx_value
from .models import MxTlsResult

_SMTP_PORT = 25


def probe_domain(
    resolver: DnsResolver, domain: str, *, timeout: float = 15.0
) -> list[MxTlsResult]:
    """Sonde tous les MX d'un domaine."""
    domain = domain.strip().rstrip(".").lower()
    rrset = resolver.query(domain, "MX")

    hosts: list[tuple[int, str]] = []
    if rrset.ok and rrset.values:
        hosts = sorted(parse_mx_value(v) for v in rrset.values if parse_mx_value(v)[1] not in (".", ""))
    elif resolver.query(domain, "A").values:
        hosts = [(0, domain)]  # implicit MX

    return [_probe_host(pref, host, timeout) for pref, host in hosts]


def _probe_host(preference: int, host: str, timeout: float) -> MxTlsResult:
    result = MxTlsResult(mx_host=host, preference=preference)
    try:
        server = smtplib.SMTP(timeout=timeout)
        code, banner = server.connect(host, _SMTP_PORT)
        result.connected = 200 <= code < 400
        result.banner = _decode(banner)
    except (OSError, smtplib.SMTPException) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    try:
        code, features = server.ehlo()
        if 200 <= code < 300:
            result.esmtp_features = _decode(features).splitlines()[1:]
        result.starttls_offered = server.has_extn("starttls")
        result.auth_mechanisms = _auth_mechs(server)

        if result.starttls_offered:
            _inspect_tls(server, host, result)
    except (OSError, smtplib.SMTPException) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        with contextlib.suppress(OSError, smtplib.SMTPException):
            server.quit()

    return result


def _inspect_tls(server: smtplib.SMTP, host: str, result: MxTlsResult) -> None:
    """Établit STARTTLS sans vérifier, puis analyse le certificat obtenu."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        code, _ = server.starttls(context=ctx)
    except (ssl.SSLError, smtplib.SMTPException, OSError) as exc:
        result.error = f"STARTTLS: {type(exc).__name__}"
        return
    if not 200 <= code < 300:
        return

    sock = server.sock
    if isinstance(sock, ssl.SSLSocket):
        result.tls_version = sock.version()
        der = sock.getpeercert(binary_form=True)
        if der:
            _parse_cert(der, host, result)

    # AUTH après TLS : certains serveurs ne l'annoncent qu'une fois chiffrés.
    try:
        server.ehlo()
        result.auth_mechanisms = _auth_mechs(server) or result.auth_mechanisms
    except (OSError, smtplib.SMTPException):
        pass


def _parse_cert(der: bytes, host: str, result: MxTlsResult) -> None:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return
    result.cert_subject = _name(cert.subject)
    result.cert_issuer = _name(cert.issuer)
    try:
        result.cert_not_after = cert.not_valid_after_utc.isoformat()
    except AttributeError:  # cryptography < 42
        result.cert_not_after = cert.not_valid_after.isoformat()
    result.cert_matches_host = _host_matches(cert, host)


def _host_matches(cert: x509.Certificate, host: str) -> bool:
    """Le nom d'hôte figure-t-il dans le SAN (ou le CN à défaut) ?"""
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names.extend(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    for attr in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        names.append(str(attr.value))

    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and host.split(".", 1)[-1] == name[2:]:
            return True
    return False


def _auth_mechs(server: smtplib.SMTP) -> list[str]:
    raw = server.esmtp_features.get("auth", "")
    return sorted({m.strip().upper() for m in raw.replace("=", " ").split() if m.strip()})


def _name(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _decode(value: bytes | str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value).strip()
