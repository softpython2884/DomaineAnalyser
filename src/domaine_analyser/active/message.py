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

#: Partie locale des adresses forgées « textbook ». Explicite à dessein.
_FORGED_LOCAL = "security-test"

#: Partie locale d'un expéditeur soigné, telle qu'un vrai émetteur l'emploierait.
_REALISTIC_LOCAL = "no-reply"


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
        scenario.mode, target=target, mailbox=recipient, token=token
    )

    msg = EmailMessage()
    msg["From"] = from_header
    msg["To"] = recipient
    msg["Date"] = formatdate(localtime=True)
    # Message-ID cohérent avec le domaine affiché, pour le réalisme du test.
    msg["Message-ID"] = make_msgid(domain=_addr_domain(from_header) or mailbox_domain)
    # Pas de Reply-To : le fixer sur le destinataire déclenche les règles
    # anti-spoof SPOOF_REPLYTO / REPLYTO_EQ_TO_ADDR (11 pts de spam), un signal
    # qu'on s'infligerait soi-même et qui fausserait la mesure de la défense réelle.
    msg[safety.TOKEN_HEADER] = token
    msg[safety.SCENARIO_HEADER] = scenario.id

    if scenario.mode is ForgeMode.REALISTIC:
        # Spoof soigné : sujet neutre crédible (sans jeton — la corrélation se
        # fait sur l'en-tête), corps HTML+texte bénin. Le but est d'isoler la
        # défense anti-usurpation : rien dans le contenu ne doit ajouter de score.
        # Sujet plausible en ASCII pur : évite l'encodage MIME (=?utf-8?…?=)
        # qui trahirait un peu la nature « fabriquée » du message.
        subject = f"Information - {_org_name(target)}"
        msg["Subject"] = subject
        text, html = _realistic_bodies(token, target)
        msg.set_content(text)
        msg.add_alternative(html, subtype="html")
    else:
        subject = f"[{safety.MARKER}] {scenario.name} — {token}"
        msg["Subject"] = subject
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
    mailbox: str,
    token: str,
) -> tuple[str, str]:
    """Retourne (valeur de l'en-tête From, adresse d'enveloppe MAIL FROM).

    L'enveloppe est portée par le domaine cible (résolvable, jamais local au
    serveur récepteur), afin que le récepteur applique ses contrôles sans
    rejeter faute d'expéditeur résolvable, et sans que le Return-Path ni une
    éventuelle signature DKIM ne fassent apparaître notre propre domaine.
    """
    bounce = f"bounce-{token}@{target}"

    if mode is ForgeMode.EXACT:
        addr = f"{_FORGED_LOCAL}@{target}"
        return addr, addr

    if mode is ForgeMode.REALISTIC:
        addr = f"{_REALISTIC_LOCAL}@{target}"
        return f'"{_org_name(target)}" <{addr}>', addr

    if mode is ForgeMode.SUBDOMAIN:
        sub = f"secure-{token[-6:]}.{target}"
        return f"{_FORGED_LOCAL}@{sub}", bounce

    if mode is ForgeMode.LOOKALIKE:
        return f"{_FORGED_LOCAL}@{lookalike_domain(target)}", bounce

    if mode is ForgeMode.DISPLAY_NAME:
        # Adresse honnête (le domaine contrôlé), mais nom d'affichage trompeur.
        return f'"{_org_name(target)} — Support" <{mailbox}>', mailbox

    raise ValueError(f"mode de falsification inconnu : {mode}")


def _org_name(target: str) -> str:
    """Nom d'organisation plausible dérivé du domaine (« solutions-corp.org »
    -> « Solutions Corp »)."""
    label = target.split(".")[0]
    return " ".join(part.capitalize() for part in label.replace("_", "-").split("-") if part)


def _realistic_bodies(token: str, target: str) -> tuple[str, str]:
    """Corps texte + HTML d'un message crédible mais bénin et traçable."""
    footer = (
        f"{safety.MARKER} · Powered by ForgeNetwork · jeton {token}. "
        "Message de test de sécurité autorisé, livré uniquement à cette boîte."
    )
    text = (
        "Bonjour,\n\n"
        "Ce message vous est adressé dans le cadre d'un contrôle de routine. "
        "Aucune action n'est requise de votre part.\n\n"
        f"Cordialement,\n{_org_name(target)}\n\n"
        f"-- \n{footer}\n"
    )
    html = (
        '<html><body style="font-family:Arial,sans-serif;color:#222">'
        "<p>Bonjour,</p>"
        "<p>Ce message vous est adressé dans le cadre d'un contrôle de routine. "
        "Aucune action n'est requise de votre part.</p>"
        f"<p>Cordialement,<br>{_org_name(target)}</p>"
        f'<hr><p style="color:#888;font-size:12px">{footer}</p>'
        "</body></html>"
    )
    return text, html


def _addr_domain(header_value: str) -> str:
    """Extrait le domaine d'une valeur d'en-tête From (avec ou sans nom)."""
    inner = header_value
    if "<" in header_value and ">" in header_value:
        inner = header_value[header_value.index("<") + 1 : header_value.index(">")]
    return inner.rpartition("@")[2].strip().lower()
