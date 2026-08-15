"""Construction des messages-tests.

Chaque scénario produit un message dont l'expéditeur est falsifié d'une manière
précise. Le destinataire, lui, est toujours la boîte contrôlée — cette
asymétrie est le cœur du modèle de sûreté.

Tous les messages portent le marqueur visible, le jeton de corrélation et les
en-têtes d'identification (voir `safety`). On ne cherche jamais à masquer qu'il
s'agit d'un test.
"""

from __future__ import annotations

from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from . import safety
from .models import ForgedMessage, ForgeMode, SpoofScenario
from .settings import MailboxAccess

#: Partie locale des adresses forgées. Explicite à dessein.
_FORGED_LOCAL = "security-test"


def lookalike_domain(domain: str) -> str:
    """Fabrique un domaine sosie plausible de `domain`.

    Utilisé uniquement comme expéditeur affiché d'un message qu'on s'envoie à
    soi-même : il n'est jamais enregistré ni contacté. Sert à vérifier qu'un
    domaine ressemblant atteint bien la boîte de réception.
    """
    labels = domain.lower().split(".")
    name = labels[0]
    for src, dst in (("o", "0"), ("l", "1"), ("i", "1"), ("e", "3"), ("a", "4")):
        if src in name:
            labels[0] = name.replace(src, dst, 1)
            return ".".join(labels)
    # Aucun caractère substituable : on double la première lettre (« paypal »
    # -> « ppaypal »), tromperie visuelle classique.
    labels[0] = name[0] + name
    return ".".join(labels)


def build_forged_message(
    scenario: SpoofScenario,
    *,
    target: str,
    mailbox: MailboxAccess,
    token: str,
) -> ForgedMessage:
    """Construit le message d'un scénario, prêt à l'émission."""
    target = target.strip().rstrip(".").lower()
    recipient = mailbox.address
    mailbox_domain = mailbox.domain

    from_header, envelope_from = _forge_sender(
        scenario.mode, target=target, mailbox_domain=mailbox_domain, mailbox=recipient, token=token
    )

    subject = f"[{safety.MARKER}] {scenario.name} — {token}"

    msg = EmailMessage()
    msg["From"] = from_header
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    # Message-ID cohérent avec le domaine affiché, pour le réalisme du test.
    msg["Message-ID"] = make_msgid(domain=_addr_domain(from_header) or mailbox_domain)
    msg["Reply-To"] = recipient
    msg[safety.TOKEN_HEADER] = token
    msg[safety.SCENARIO_HEADER] = scenario.id
    msg.set_content(safety.build_body(token, scenario.name, target))

    return ForgedMessage(
        token=token,
        scenario_id=scenario.id,
        from_header=from_header,
        envelope_from=envelope_from,
        subject=subject,
        raw=msg.as_bytes(),
    )


def _forge_sender(
    mode: ForgeMode,
    *,
    target: str,
    mailbox_domain: str,
    mailbox: str,
    token: str,
) -> tuple[str, str]:
    """Retourne (valeur de l'en-tête From, adresse d'enveloppe MAIL FROM).

    L'enveloppe est choisie pour rester livrable : quand le domaine affiché
    n'existe pas (sosie) ou n'est pas censé router (sous-domaine), on rebascule
    l'enveloppe sur le domaine contrôlé afin que le récepteur applique bien ses
    contrôles au lieu de rejeter faute d'expéditeur résolvable.
    """
    bounce = f"bounce-{token}@{mailbox_domain}"

    if mode is ForgeMode.EXACT:
        addr = f"{_FORGED_LOCAL}@{target}"
        return addr, addr

    if mode is ForgeMode.HEADER_ONLY:
        return f"{_FORGED_LOCAL}@{target}", bounce

    if mode is ForgeMode.SUBDOMAIN:
        sub = f"secure-{token[-6:]}.{target}"
        return f"{_FORGED_LOCAL}@{sub}", bounce

    if mode is ForgeMode.LOOKALIKE:
        return f"{_FORGED_LOCAL}@{lookalike_domain(target)}", bounce

    if mode is ForgeMode.DISPLAY_NAME:
        # Adresse honnête (le domaine contrôlé), mais nom d'affichage trompeur.
        return f'"{target} — Support" <{mailbox}>', mailbox

    raise ValueError(f"mode de falsification inconnu : {mode}")


def _addr_domain(header_value: str) -> str:
    """Extrait le domaine d'une valeur d'en-tête From (avec ou sans nom)."""
    inner = header_value
    if "<" in header_value and ">" in header_value:
        inner = header_value[header_value.index("<") + 1 : header_value.index(">")]
    return inner.rpartition("@")[2].strip().lower()
