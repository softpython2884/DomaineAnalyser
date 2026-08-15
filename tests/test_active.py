"""Tests hors ligne du sous-système de tests actifs.

Ne touchent jamais le réseau : on vérifie la construction des messages, la
classification des résultats, le parsing des verdicts d'authentification et —
surtout — les garde-fous de sûreté.
"""

from __future__ import annotations

from email import message_from_string

import pytest

from domaine_analyser.active import safety, scenarios
from domaine_analyser.active.imap_verify import parse_auth_results
from domaine_analyser.active.message import build_forged_message, lookalike_domain
from domaine_analyser.active.models import (
    DeliveryResult,
    Disposition,
    ForgeMode,
    SmtpResult,
)
from domaine_analyser.active.scenarios import DEFAULT_SCENARIOS, classify_disposition
from domaine_analyser.active.settings import MailboxAccess

MAILBOX = MailboxAccess(
    address="failtest@capibara.fr",
    imap_host="mail.capibara.fr",
    imap_password="secret",
)


def _scenario(mode: ForgeMode):
    return next(s for s in DEFAULT_SCENARIOS if s.mode is mode)


# --- sûreté ------------------------------------------------------------------


def test_jeton_unique_et_prefixe():
    a, b = safety.new_token(), safety.new_token()
    assert a != b
    assert a.startswith("DAT-")


def test_destinataire_non_possede_refuse():
    # Le cœur du modèle : impossible de viser une boîte qu'on ne contrôle pas.
    with pytest.raises(safety.SafetyError):
        safety.assert_recipient_is_owned("victime@autrui.fr", "failtest@capibara.fr")


def test_destinataire_possede_accepte():
    safety.assert_recipient_is_owned("FailTest@Capibara.fr", "failtest@capibara.fr")


def test_campagne_refusee_sans_consentement():
    with pytest.raises(safety.SafetyError):
        safety.assert_ready(mailbox_configured=True, acknowledged=False)


def test_campagne_refusee_sans_boite():
    with pytest.raises(safety.SafetyError):
        safety.assert_ready(mailbox_configured=False, acknowledged=True)


def test_budget_de_messages_borne():
    assert safety.enforce_message_budget(50, 25) == 25
    assert safety.enforce_message_budget(3, 25) == 3
    assert safety.enforce_message_budget(0, 25) == 0


# --- domaines sosies ---------------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "expected_changed"),
    [
        ("paypal.com", True),   # a/o/l substituables
        ("google.com", True),
        ("bbc.co.uk", True),
    ],
)
def test_lookalike_diffère_de_loriginal(domain: str, expected_changed: bool):
    lk = lookalike_domain(domain)
    assert (lk != domain) is expected_changed
    # même nombre de labels : reste un domaine plausible
    assert lk.count(".") == domain.count(".")


# --- construction des messages ----------------------------------------------


def test_message_exact_aligne_enveloppe_et_entete():
    sc = _scenario(ForgeMode.EXACT)
    msg = build_forged_message(sc, target="paypal.com", mailbox=MAILBOX, token="DAT-abc123")
    assert msg.from_header == "security-test@paypal.com"
    assert msg.envelope_from == "security-test@paypal.com"


def test_message_realistic_a_nom_daffichage_et_corps_html():
    sc = _scenario(ForgeMode.REALISTIC)
    msg = build_forged_message(sc, target="solutions-corp.org", mailbox=MAILBOX, token="DAT-abc123")
    # nom d'affichage plausible dérivé du domaine + adresse sur la cible
    assert "Solutions Corp" in msg.from_header
    assert "no-reply@solutions-corp.org" in msg.from_header
    assert msg.envelope_from == "no-reply@solutions-corp.org"
    # sujet crédible SANS jeton (corrélation par en-tête), corps multipart HTML
    assert "DAT-" not in msg.subject
    raw = msg.raw.decode()
    assert "text/html" in raw
    assert "DAT-abc123" in raw  # le jeton reste traçable dans l'en-tête + le pied


def test_message_sous_domaine_enveloppe_sur_la_cible():
    sc = _scenario(ForgeMode.SUBDOMAIN)
    msg = build_forged_message(sc, target="paypal.com", mailbox=MAILBOX, token="DAT-abc123")
    assert msg.from_header.endswith(".paypal.com")
    # enveloppe sur le domaine cible (résolvable, jamais notre domaine local)
    assert msg.envelope_from.endswith("@paypal.com")
    assert "capibara.fr" not in msg.envelope_from


def test_message_display_name_adresse_honnete():
    sc = _scenario(ForgeMode.DISPLAY_NAME)
    msg = build_forged_message(sc, target="paypal.com", mailbox=MAILBOX, token="DAT-abc123")
    assert "Paypal" in msg.from_header  # nom trompeur
    assert "failtest@capibara.fr" in msg.from_header  # adresse honnête
    assert msg.envelope_from == "failtest@capibara.fr"


def test_message_porte_marqueur_jeton_et_destinataire_controle():
    sc = _scenario(ForgeMode.EXACT)
    token = "DAT-deadbeef"
    msg = build_forged_message(sc, target="paypal.com", mailbox=MAILBOX, token=token)
    raw = msg.raw.decode()
    assert token in msg.subject
    assert safety.MARKER in raw
    assert "ForgeNetwork" in raw
    assert f"{safety.TOKEN_HEADER}: {token}" in raw
    # Le destinataire est TOUJOURS la boîte contrôlée.
    assert "To: failtest@capibara.fr" in raw


# --- classification des résultats -------------------------------------------


def test_delivered_quand_recu_en_inbox():
    smtp = SmtpResult(accepted=True, code=250)
    delivery = DeliveryResult(arrived=True, folder="INBOX", is_junk=False)
    assert classify_disposition(smtp, delivery) is Disposition.DELIVERED


def test_quarantine_quand_recu_en_spam():
    smtp = SmtpResult(accepted=True, code=250)
    delivery = DeliveryResult(arrived=True, folder="Junk", is_junk=True)
    assert classify_disposition(smtp, delivery) is Disposition.QUARANTINE


def test_dropped_quand_accepte_mais_absent():
    smtp = SmtpResult(accepted=True, code=250)
    assert classify_disposition(smtp, DeliveryResult(arrived=False)) is Disposition.DROPPED


def test_rejected_sur_5xx():
    smtp = SmtpResult(accepted=False, code=550, message="rejected")
    assert classify_disposition(smtp, DeliveryResult()) is Disposition.REJECTED


def test_deferred_sur_4xx():
    smtp = SmtpResult(accepted=False, code=451, message="greylisted")
    assert classify_disposition(smtp, DeliveryResult()) is Disposition.DEFERRED


def test_not_sent_sur_echec_connexion():
    smtp = SmtpResult(accepted=False, code=None, error="port 25 filtré", stage="connect")
    assert classify_disposition(smtp, DeliveryResult()) is Disposition.NOT_SENT


def test_send_error_sur_helo_refuse():
    # Un HELO refusé est une erreur de NOTRE config, pas une défense de la cible.
    # Ne doit surtout pas être lu comme « usurpation bloquée ».
    smtp = SmtpResult(accepted=False, code=550, stage="helo", message="Invalid EHLO domain")
    assert classify_disposition(smtp, DeliveryResult()) is Disposition.SEND_ERROR


def test_rejet_5xx_au_rcpt_est_une_defense():
    smtp = SmtpResult(accepted=False, code=550, stage="rcpt", message="DMARC reject")
    assert classify_disposition(smtp, DeliveryResult()) is Disposition.REJECTED


def test_dry_run():
    smtp = SmtpResult(accepted=None)
    assert classify_disposition(smtp, DeliveryResult()) is Disposition.DRY_RUN


# --- parsing des verdicts d'authentification --------------------------------


def test_parse_authentication_results():
    raw = (
        "Authentication-Results: mail.capibara.fr;\n"
        "  spf=fail smtp.mailfrom=security-test@paypal.com;\n"
        "  dkim=none;\n"
        "  dmarc=fail (p=reject) header.from=paypal.com\n"
        "Subject: test\n\n corps\n"
    )
    auth = parse_auth_results(message_from_string(raw))
    assert auth.spf == "fail"
    assert auth.dkim == "none"
    assert auth.dmarc == "fail"


def test_parse_absence_dauthentication_results():
    auth = parse_auth_results(message_from_string("Subject: x\n\n corps\n"))
    assert auth.spf is None
    assert auth.dmarc is None


# --- catalogue ---------------------------------------------------------------


def test_selection_de_scenarios():
    picked = scenarios.get_scenarios(("exact", "lookalike"))
    assert {s.id for s in picked} == {"exact", "lookalike"}


def test_scenarios_par_defaut_non_vide():
    assert len(scenarios.get_scenarios()) >= 4
