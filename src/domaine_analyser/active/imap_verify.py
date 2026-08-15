"""Relecture IMAP de la boîte contrôlée.

Ce module remplit deux rôles indissociables. Le premier est la preuve de
possession : réussir à se connecter à la boîte, c'est démontrer qu'on la
contrôle, condition sans laquelle aucune campagne ne démarre. Le second est la
mesure : retrouver chaque message-test par son jeton, déterminer son dossier de
dépôt (réception ou indésirables) et extraire les verdicts d'authentification
que le serveur récepteur a inscrits — la source de vérité du test.
"""

from __future__ import annotations

import contextlib
import imaplib
import re
import time
from email.message import Message
from email.parser import BytesParser
from email.policy import default as default_policy

from .models import AuthResults, DeliveryResult
from .settings import MailboxAccess

#: Motifs de dossiers d'indésirables, à défaut de drapeau \Junk exploitable.
_JUNK_HINTS = ("junk", "spam", "bulk", "indésir", "unwanted")

_AUTH_FIELD = re.compile(
    r"\b(spf|dkim|dmarc|compauth)\s*=\s*([a-z]+)", re.IGNORECASE
)


class ImapError(Exception):
    """Erreur de connexion ou de dialogue IMAP."""


def verify_login(mailbox: MailboxAccess) -> bool:
    """Preuve de possession : la connexion IMAP réussit-elle ?"""
    try:
        conn = _connect(mailbox)
    except Exception:
        return False
    with contextlib.suppress(Exception):
        conn.logout()
    return True


def _connect(mailbox: MailboxAccess) -> imaplib.IMAP4:
    if mailbox.imap_ssl:
        conn: imaplib.IMAP4 = imaplib.IMAP4_SSL(mailbox.imap_host, mailbox.imap_port)
    else:
        conn = imaplib.IMAP4(mailbox.imap_host, mailbox.imap_port)
    conn.login(mailbox.imap_user, mailbox.imap_password)
    return conn


def _discover_folders(conn: imaplib.IMAP4) -> list[tuple[str, bool]]:
    """Liste (nom, est_indésirable) des dossiers à examiner.

    La réception passe en premier ; on ajoute tout dossier marqué \\Junk ou dont
    le nom évoque les indésirables. Distinguer les deux est essentiel : « en
    réception » et « en spam » sont deux verdicts opposés.
    """
    folders: list[tuple[str, bool]] = [("INBOX", False)]
    try:
        status, data = conn.list()
    except imaplib.IMAP4.error:
        return folders
    if status != "OK":
        return folders

    for raw in data:
        if not raw:
            continue
        line = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
        flags = line.lower()
        name = _folder_name(line)
        if not name or name.upper() == "INBOX":
            continue
        is_junk = "\\junk" in flags or any(h in name.lower() for h in _JUNK_HINTS)
        if is_junk:
            folders.append((name, True))
    return folders


def _folder_name(list_line: str) -> str:
    # Format LIST : (flags) "sep" "Nom" — on prend le dernier champ entre
    # guillemets, sinon le dernier mot.
    quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', list_line)
    if quoted:
        return quoted[-1].replace('\\"', '"')
    return list_line.split()[-1] if list_line.split() else ""


def wait_for_tokens(
    mailbox: MailboxAccess,
    tokens: set[str],
    *,
    timeout: float,
    poll_interval: float = 5.0,
    now: float | None = None,
) -> dict[str, DeliveryResult]:
    """Attend l'arrivée des messages identifiés par `tokens`.

    Interroge en boucle réception et indésirables jusqu'à ce que tous les jetons
    soient trouvés ou que le délai expire. Les jetons non trouvés restent
    absents du résultat : pour eux, le message n'est jamais arrivé.
    """
    found: dict[str, DeliveryResult] = {}
    conn = _connect(mailbox)
    try:
        folders = _discover_folders(conn)
        deadline = (now if now is not None else time.monotonic()) + timeout
        while True:
            remaining = tokens - found.keys()
            if not remaining:
                break
            for folder, is_junk in folders:
                for token, result in _scan_folder(conn, folder, is_junk, remaining).items():
                    found[token] = result
            if tokens - found.keys() and time.monotonic() < deadline:
                time.sleep(poll_interval)
            else:
                break
    finally:
        with contextlib.suppress(Exception):
            conn.logout()
    return found


def _scan_folder(
    conn: imaplib.IMAP4, folder: str, is_junk: bool, wanted: set[str]
) -> dict[str, DeliveryResult]:
    """Cherche les messages-tests dans un dossier et les analyse."""
    results: dict[str, DeliveryResult] = {}
    try:
        status, _ = conn.select(_quote(folder), readonly=True)
        if status != "OK":
            return results
        # Tous nos sujets contiennent le préfixe de jeton « DAT- » : une seule
        # recherche par dossier suffit, on trie ensuite par jeton.
        status, data = conn.search(None, "SUBJECT", "DAT-")
    except imaplib.IMAP4.error:
        return results
    if status != "OK" or not data or not data[0]:
        return results

    for num in data[0].split():
        try:
            status, msg_data = conn.fetch(num, "(BODY.PEEK[HEADER])")
        except imaplib.IMAP4.error:
            continue
        if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
            continue
        headers = BytesParser(policy=default_policy).parsebytes(msg_data[0][1])
        token = str(headers.get("X-DomaineAnalyser-Test", "")).strip()
        if token in wanted and token not in results:
            results[token] = _build_delivery(headers, folder, is_junk)
    return results


def _build_delivery(headers: Message, folder: str, is_junk: bool) -> DeliveryResult:
    auth = parse_auth_results(headers)
    received = headers.get_all("Received", [])
    seen_from = str(headers.get("From", "")).strip()
    return DeliveryResult(
        arrived=True,
        folder=folder,
        is_junk=is_junk,
        auth=auth,
        received_count=len(received),
        seen_from=seen_from or None,
    )


def parse_auth_results(headers: Message) -> AuthResults:
    """Extrait les verdicts SPF/DKIM/DMARC stampés par le récepteur."""
    values: list[str] = []
    for name in ("Authentication-Results", "ARC-Authentication-Results"):
        values.extend(str(v) for v in (headers.get_all(name, []) or []))

    auth = AuthResults(raw="; ".join(values) or None)
    # La première mention l'emporte : l'Authentication-Results le plus récent
    # (celui du récepteur final) est en tête de liste des en-têtes.
    for blob in values:
        for field, verdict in _AUTH_FIELD.findall(blob):
            slot = field.lower()
            if getattr(auth, slot, None) is None:
                setattr(auth, slot, verdict.lower())
    return auth


def _quote(folder: str) -> str:
    return f'"{folder}"' if " " in folder else folder


def cleanup_tokens(mailbox: MailboxAccess, tokens: set[str]) -> int:
    """Supprime les messages-tests pour ne pas encombrer la boîte.

    Best-effort : les échecs sont silencieux. Retourne le nombre de messages
    supprimés.
    """
    if not tokens:
        return 0
    removed = 0
    try:
        conn = _connect(mailbox)
    except Exception:
        return 0
    try:
        for folder, _ in _discover_folders(conn):
            try:
                if conn.select(_quote(folder))[0] != "OK":
                    continue
                status, data = conn.search(None, "SUBJECT", "DAT-")
                if status != "OK" or not data or not data[0]:
                    continue
                for num in data[0].split():
                    status, msg_data = conn.fetch(num, "(BODY.PEEK[HEADER])")
                    if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                        continue
                    headers = BytesParser(policy=default_policy).parsebytes(msg_data[0][1])
                    if str(headers.get("X-DomaineAnalyser-Test", "")).strip() in tokens:
                        conn.store(num, "+FLAGS", "\\Deleted")
                        removed += 1
                conn.expunge()
            except imaplib.IMAP4.error:
                continue
    finally:
        with contextlib.suppress(Exception):
            conn.logout()
    return removed
