"""Tests de l'analyseur SPF."""

from __future__ import annotations

import pytest

from conftest import lookup_from
from domaine_analyser.analyze.spf import (
    MAX_LOOKUPS,
    analyze_spf,
    extract_spf_records,
    format_address_space,
)


def analyze(records: dict[tuple[str, str], list[str]], domain: str = "example.com"):
    lookup = lookup_from(records)
    return analyze_spf(lookup, domain, lookup.txt(domain))


# --- présence et unicité -----------------------------------------------------


def test_absence_de_spf():
    result = analyze({("example.com", "TXT"): ["google-site-verification=abc"]})
    assert not result.present
    assert not result.malformed


def test_reconnaissance_insensible_a_la_casse():
    # Un enregistrement « V=SPF1 » est valide : le conclure absent produirait
    # un constat entièrement faux.
    result = analyze({("example.com", "TXT"): ["V=SPF1 ip4:192.0.2.1 -all"]})
    assert result.present


def test_enregistrements_multiples_invalident_la_politique():
    result = analyze(
        {("example.com", "TXT"): ["v=spf1 ip4:192.0.2.1 -all", "v=spf1 include:a.test ~all"]}
    )
    assert result.multiple_records
    assert not result.valid_syntax
    # L'analyse s'arrête : une politique en permerror n'a pas de sens à dérouler.
    assert result.lookup_count == 0


# --- qualificateur terminal --------------------------------------------------


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ("v=spf1 ip4:192.0.2.1 -all", "-"),
        ("v=spf1 ip4:192.0.2.1 ~all", "~"),
        ("v=spf1 ip4:192.0.2.1 ?all", "?"),
        ("v=spf1 ip4:192.0.2.1 +all", "+"),
        ("v=spf1 ip4:192.0.2.1 all", "+"),
        ("v=spf1 ip4:192.0.2.1", None),
    ],
)
def test_qualificateur_terminal(record: str, expected: str | None):
    result = analyze({("example.com", "TXT"): [record]})
    assert result.all_qualifier == expected


def test_plus_all_autorise_tout_lespace_ipv4():
    result = analyze({("example.com", "TXT"): ["v=spf1 +all"]})
    assert result.ipv4_space == 2**32


# --- comptage des résolutions DNS --------------------------------------------


def test_comptage_des_lookups_a_travers_les_inclusions():
    result = analyze(
        {
            ("example.com", "TXT"): ["v=spf1 include:a.test include:b.test -all"],
            ("a.test", "TXT"): ["v=spf1 ip4:10.0.0.0/24 include:c.test ~all"],
            ("b.test", "TXT"): ["v=spf1 ip4:10.0.1.0/24 ~all"],
            ("c.test", "TXT"): ["v=spf1 a:host.test ~all"],
            ("host.test", "A"): ["192.0.2.5"],
        }
    )
    # include a, include b, include c, a:host -> 4
    assert result.lookup_count == 4
    assert set(result.includes_resolved) == {"a.test", "b.test", "c.test"}
    assert not result.exceeds_lookup_limit


def test_depassement_de_la_limite_de_dix_resolutions():
    records: dict[tuple[str, str], list[str]] = {
        ("example.com", "TXT"): [
            "v=spf1 " + " ".join(f"include:i{i}.test" for i in range(12)) + " -all"
        ]
    }
    for index in range(12):
        records[(f"i{index}.test", "TXT")] = ["v=spf1 ip4:192.0.2.1 ~all"]

    result = analyze(records)
    assert result.lookup_count == 12
    assert result.exceeds_lookup_limit
    assert result.lookup_count > MAX_LOOKUPS


def test_les_mecanismes_ip_ne_consomment_aucune_resolution():
    result = analyze(
        {("example.com", "TXT"): ["v=spf1 " + " ".join(f"ip4:10.0.{i}.0/24" for i in range(20)) + " -all"]}
    )
    assert result.lookup_count == 0
    assert not result.exceeds_lookup_limit


def test_inclusion_circulaire_detectee_sans_recursion_infinie():
    result = analyze(
        {
            ("example.com", "TXT"): ["v=spf1 include:y.test -all"],
            ("y.test", "TXT"): ["v=spf1 include:example.com -all"],
        }
    )
    assert result.circular_includes
    assert any("circulaire" in error for error in result.syntax_errors)


def test_include_sans_spf_compte_comme_resolution_vide():
    result = analyze(
        {
            ("example.com", "TXT"): ["v=spf1 include:absent.test -all"],
            ("absent.test", "TXT"): [],
        }
    )
    assert result.unresolvable_includes == ["absent.test"]
    assert result.void_lookup_count == 1
    assert any("permerror" in error for error in result.syntax_errors)


# --- espace d'adressage ------------------------------------------------------


def test_fusion_des_prefixes_chevauchants():
    # Le /24 est contenu dans le /16 : le total doit valoir le /16 seul, sinon
    # le rapport annoncerait un espace autorisé supérieur à la réalité.
    result = analyze(
        {("example.com", "TXT"): ["v=spf1 ip4:10.0.0.0/16 ip4:10.0.1.0/24 -all"]}
    )
    assert result.ipv4_space == 2**16


def test_addition_des_prefixes_disjoints():
    result = analyze(
        {("example.com", "TXT"): ["v=spf1 ip4:10.0.0.0/24 ip4:192.0.2.0/24 -all"]}
    )
    assert result.ipv4_space == 512


def test_les_mecanismes_negatifs_nautorisent_rien():
    result = analyze({("example.com", "TXT"): ["v=spf1 -ip4:10.0.0.0/8 ip4:192.0.2.1 -all"]})
    assert result.ipv4_space == 1


def test_resolution_des_mecanismes_a_et_mx():
    result = analyze(
        {
            ("example.com", "TXT"): ["v=spf1 a mx -all"],
            ("example.com", "A"): ["192.0.2.1"],
            ("example.com", "MX"): ["10 mail.example.com"],
            ("mail.example.com", "A"): ["192.0.2.2"],
        }
    )
    assert result.lookup_count == 2
    assert result.ipv4_space == 2


def test_prefixe_cidr_sur_le_mecanisme_a():
    result = analyze(
        {
            ("example.com", "TXT"): ["v=spf1 a/24 -all"],
            ("example.com", "A"): ["192.0.2.10"],
        }
    )
    assert result.ipv4_space == 256


# --- anomalies ---------------------------------------------------------------


def test_mecanisme_ptr_signale():
    result = analyze({("example.com", "TXT"): ["v=spf1 ptr -all"]})
    assert result.uses_ptr


def test_terme_apres_all_signale_comme_inatteignable():
    result = analyze({("example.com", "TXT"): ["v=spf1 -all ip4:192.0.2.1"]})
    assert any("jamais évalué" in error for error in result.syntax_errors)


def test_redirect_ignore_en_presence_de_all():
    # RFC 7208 §6.1 : « all » l'emporte, redirect ne doit pas être suivi.
    result = analyze(
        {
            ("example.com", "TXT"): ["v=spf1 -all redirect=other.test"],
            ("other.test", "TXT"): ["v=spf1 ip4:10.0.0.0/8 ~all"],
        }
    )
    assert result.lookup_count == 0
    assert result.ipv4_space == 0


def test_redirect_suivi_en_absence_de_all():
    result = analyze(
        {
            ("example.com", "TXT"): ["v=spf1 redirect=other.test"],
            ("other.test", "TXT"): ["v=spf1 ip4:192.0.2.0/24 -all"],
        }
    )
    assert result.lookup_count == 1
    assert result.ipv4_space == 256


def test_macro_non_expansee_sans_erreur():
    # Une macro n'est résoluble qu'à l'évaluation, avec l'IP réelle. Elle doit
    # être comptée comme résolution sans provoquer d'erreur ni de requête.
    result = analyze({("example.com", "TXT"): ["v=spf1 exists:%{i}._spf.example.com -all"]})
    assert result.lookup_count == 1
    assert result.valid_syntax


def test_adresse_invalide_signalee():
    result = analyze({("example.com", "TXT"): ["v=spf1 ip4:999.1.1.1 -all"]})
    assert any("invalide" in error for error in result.syntax_errors)


def test_famille_dadresse_incoherente_signalee():
    result = analyze({("example.com", "TXT"): ["v=spf1 ip4:2001:db8::1 -all"]})
    assert any("IPv6" in error for error in result.syntax_errors)


# --- utilitaires -------------------------------------------------------------


def test_extraction_ignore_les_autres_txt():
    values = ["google-site-verification=x", "v=spf1 -all", "v=DMARC1; p=none"]
    assert extract_spf_records(values) == ["v=spf1 -all"]


@pytest.mark.parametrize(
    ("count", "expected"),
    [
        (0, "aucune"),
        (1, "1 adresse"),
        (512, "512 adresses"),
        # Séparateur de milliers : espace fine insécable (U+202F), conforme à
        # la typographie française et qui empêche le nombre de se couper.
        (98_304, "98 304 adresses"),
        (3_200_000, "3,2 millions d'adresses"),
        (2**32, "4,3 milliards d'adresses"),
    ],
)
def test_formatage_de_lespace_dadressage(count: int, expected: str):
    assert format_address_space(count) == expected


def test_le_separateur_de_milliers_est_insecable():
    # Garde-fou : un reformatage qui remplacerait U+202F par un espace normal
    # réintroduirait des coupures de ligne au milieu des nombres du rapport.
    assert " " in format_address_space(98_304)
    assert " " not in format_address_space(98_304).removesuffix(" adresses")


def test_formatage_des_tres_grands_espaces_ipv6():
    rendered = format_address_space(2**80)
    assert "e+" in rendered
