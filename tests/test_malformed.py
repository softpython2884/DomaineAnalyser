"""Tests du diagnostic des enregistrements corrompus."""

from __future__ import annotations

import pytest

from domaine_analyser.analyze.malformed import diagnose, repaired_preview


def test_guillemets_html_echappes():
    result = diagnose(['&quot;v=DMARC1; p=reject&quot;'], "v=dmarc1")
    assert len(result) == 1
    assert "&quot;" in result[0].reason
    assert "interface web" in result[0].likely_cause


def test_guillemets_litteraux():
    result = diagnose(['"v=spf1 -all"'], "v=spf1")
    assert len(result) == 1
    assert "littéraux" in result[0].reason


def test_espaces_en_tete():
    result = diagnose(["   v=spf1 -all"], "v=spf1")
    assert len(result) == 1
    assert "espaces" in result[0].reason


def test_valeur_correcte_non_signalee():
    assert diagnose(["v=spf1 -all"], "v=spf1") == []


def test_casse_differente_non_signalee():
    # « V=SPF1 » est valide ; le signaler comme corrompu serait un faux positif.
    assert diagnose(["V=SPF1 -all"], "v=spf1") == []


def test_txt_sans_rapport_ignore():
    values = ["google-site-verification=abc", "MS=ms12345", "un texte quelconque"]
    assert diagnose(values, "v=spf1") == []
    assert diagnose(values, "v=dmarc1") == []


def test_un_spf_nest_pas_un_dmarc_corrompu():
    assert diagnose(["v=spf1 -all"], "v=dmarc1") == []


def test_plusieurs_valeurs_corrompues():
    result = diagnose(['&quot;v=spf1 -all&quot;', '"v=spf1 ~all"'], "v=spf1")
    assert len(result) == 2


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ('&quot;v=DMARC1; p=reject&quot;', "v=DMARC1; p=reject"),
        ('"v=spf1 -all"', "v=spf1 -all"),
        ("   v=spf1 -all  ", "v=spf1 -all"),
        ('&quot;v=DMARC1; p=reject&quot;; fo=1', "v=DMARC1; p=reject; fo=1"),
    ],
)
def test_apercu_de_la_valeur_corrigee(raw: str, expected: str):
    assert repaired_preview(raw) == expected
