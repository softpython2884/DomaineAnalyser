"""Tests de l'analyseur DMARC."""

from __future__ import annotations

import pytest

from conftest import lookup_from
from domaine_analyser.analyze.dmarc import (
    analyze_dmarc,
    extract_dmarc_records,
    organizational_domain,
)


def analyze(
    records: dict[tuple[str, str], list[str]],
    domain: str = "example.com",
    **kwargs: object,
):
    lookup = lookup_from(records)
    return analyze_dmarc(lookup, domain, lookup.txt(f"_dmarc.{domain}"), **kwargs)  # type: ignore[arg-type]


# --- domaine organisationnel -------------------------------------------------


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", "example.com"),
        ("mail.example.com", "example.com"),
        ("a.b.c.example.com", "example.com"),
        # Un découpage sur les deux derniers labels donnerait « co.uk », qui
        # n'est pas un domaine enregistrable : l'héritage serait faux.
        ("mail.example.co.uk", "example.co.uk"),
        ("example.gouv.fr", "example.gouv.fr"),
    ],
)
def test_domaine_organisationnel(domain: str, expected: str):
    assert organizational_domain(domain) == expected


# --- présence et politique ---------------------------------------------------


def test_absence_de_politique():
    result = analyze({})
    assert not result.present
    assert result.policy is None


@pytest.mark.parametrize("policy", ["none", "quarantine", "reject"])
def test_politiques_valides(policy: str):
    result = analyze({("_dmarc.example.com", "TXT"): [f"v=DMARC1; p={policy}"]})
    assert result.present
    assert result.policy == policy
    assert result.enforcing is (policy in ("quarantine", "reject"))


def test_politique_invalide_signalee():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=bloque"]})
    assert result.policy is None
    assert any("invalide" in error for error in result.syntax_errors)


def test_politique_absente_signalee():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; rua=mailto:a@example.com"]})
    assert result.policy is None
    assert any("« p » est absent" in error for error in result.syntax_errors)


def test_enregistrements_multiples_annulent_la_politique():
    result = analyze(
        {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject", "v=DMARC1; p=none"]}
    )
    assert result.multiple_records
    assert not result.valid_syntax


# --- sous-domaines -----------------------------------------------------------


def test_politique_de_sous_domaine_heritee_de_p():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]})
    assert result.subdomain_policy is None
    assert result.effective_subdomain_policy == "reject"


def test_sp_explicite_prime_sur_p():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=none"]})
    assert result.effective_subdomain_policy == "none"


def test_heritage_depuis_le_domaine_organisationnel():
    result = analyze(
        {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; sp=quarantine"]},
        domain="mail.example.com",
    )
    assert result.present
    assert result.inherited_from == "example.com"
    assert result.effective_subdomain_policy == "quarantine"


# --- tags --------------------------------------------------------------------


def test_pourcentage_par_defaut_a_cent():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]})
    assert result.percentage == 100


def test_pourcentage_partiel():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; pct=20"]})
    assert result.percentage == 20


def test_pourcentage_invalide_signale():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; pct=150"]})
    assert result.percentage == 100
    assert any("pct" in error for error in result.syntax_errors)


def test_modes_dalignement():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; adkim=s; aspf=s"]})
    assert result.adkim == "s"
    assert result.aspf == "s"


def test_alignement_relache_par_defaut():
    result = analyze({("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject"]})
    assert result.adkim == "r"
    assert result.aspf == "r"


# --- destinations de rapports ------------------------------------------------


def test_destination_interne_non_marquee_externe():
    result = analyze(
        {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@example.com"]}
    )
    assert len(result.rua) == 1
    assert not result.rua[0].is_external
    assert result.rua[0].authorized is None


def test_destination_externe_autorisee():
    result = analyze(
        {
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@analyse.test"],
            ("example.com._report._dmarc.analyse.test", "TXT"): ["v=DMARC1"],
        }
    )
    assert result.rua[0].is_external
    assert result.rua[0].authorized is True


def test_destination_externe_non_autorisee():
    # Cas fréquent et totalement silencieux : les rapports ne partent jamais.
    result = analyze(
        {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@analyse.test"]}
    )
    assert result.rua[0].is_external
    assert result.rua[0].authorized is False
    assert "_report._dmarc" in (result.rua[0].authorization_error or "")


def test_autorisation_par_joker():
    result = analyze(
        {
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@analyse.test"],
            ("*._report._dmarc.analyse.test", "TXT"): ["v=DMARC1"],
        }
    )
    assert result.rua[0].authorized is True


def test_destinations_multiples():
    result = analyze(
        {
            ("_dmarc.example.com", "TXT"): [
                "v=DMARC1; p=none; rua=mailto:a@example.com,mailto:b@analyse.test"
            ]
        }
    )
    assert len(result.rua) == 2
    assert [t.is_external for t in result.rua] == [False, True]


def test_limite_de_taille_toleree_dans_luri():
    result = analyze(
        {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@example.com!10m"]}
    )
    assert len(result.rua) == 1


def test_schema_non_mailto_signale():
    result = analyze(
        {("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=https://exemple.test/dmarc"]}
    )
    assert not result.rua
    assert any("mailto" in error for error in result.syntax_errors)


# --- enregistrements corrompus ou mal placés ---------------------------------


def test_guillemets_html_echappes_detectes():
    result = analyze(
        {
            ("_dmarc.example.com", "TXT"): [
                "&quot;v=DMARC1; p=reject; rua=mailto:d@example.com&quot;; fo=1"
            ]
        }
    )
    assert not result.present
    assert len(result.malformed) == 1
    assert "&quot;" in result.malformed[0].reason
    assert "interface web" in result.malformed[0].likely_cause


def test_politique_publiee_a_lapex_detectee():
    result = analyze(
        {},
        apex_txt=["v=spf1 -all", "v=DMARC1; p=quarantine; rua=mailto:d@example.com"],
    )
    assert result.misplaced_at_apex == ["v=DMARC1; p=quarantine; rua=mailto:d@example.com"]


def test_txt_sans_rapport_non_signale_comme_corrompu():
    result = analyze({("_dmarc.example.com", "TXT"): ["google-site-verification=abc123"]})
    assert not result.malformed


def test_extraction_ignore_les_autres_txt():
    values = ["v=spf1 -all", "v=DMARC1; p=none", "autre"]
    assert extract_dmarc_records(values) == ["v=DMARC1; p=none"]
