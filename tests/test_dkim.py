"""Tests de l'analyseur DKIM."""

from __future__ import annotations

import pytest

from domaine_analyser.analyze.dkim import (
    analyze_dkim,
    infer_provider_from_selector,
    parse_dkim_key,
)


def test_cle_rsa_2048_reconnue(rsa_2048_b64: str):
    key = parse_dkim_key("selector1", f"v=DKIM1; k=rsa; p={rsa_2048_b64}")
    assert key.valid
    assert key.key_type == "rsa"
    assert key.key_bits == 2048
    assert not key.revoked
    assert not key.testing


def test_cle_rsa_1024_reconnue(rsa_1024_b64: str):
    key = parse_dkim_key("k1", f"v=DKIM1; k=rsa; p={rsa_1024_b64}")
    assert key.valid
    assert key.key_bits == 1024


def test_cle_ed25519_brute(ed25519_b64: str):
    # RFC 8463 : la clé Ed25519 est publiée brute sur 32 octets, sans DER.
    key = parse_dkim_key("ed", f"v=DKIM1; k=ed25519; p={ed25519_b64}")
    assert key.valid
    assert key.key_type == "ed25519"
    assert key.key_bits == 256


def test_valeur_p_vide_signifie_revocation(rsa_2048_b64: str):
    key = parse_dkim_key("old", "v=DKIM1; k=rsa; p=")
    assert key.revoked
    assert not key.valid
    assert key.key_bits is None


def test_drapeau_de_test(rsa_2048_b64: str):
    key = parse_dkim_key("s1", f"v=DKIM1; k=rsa; t=y; p={rsa_2048_b64}")
    assert key.testing
    # La clé reste valide : c'est le drapeau qui la rend inopérante, pas sa forme.
    assert key.valid


def test_drapeau_strict(rsa_2048_b64: str):
    key = parse_dkim_key("s1", f"v=DKIM1; k=rsa; t=s; p={rsa_2048_b64}")
    assert key.strict_subdomain
    assert not key.testing


def test_drapeaux_combines(rsa_2048_b64: str):
    key = parse_dkim_key("s1", f"v=DKIM1; k=rsa; t=y:s; p={rsa_2048_b64}")
    assert key.testing
    assert key.strict_subdomain


def test_base64_invalide_signale():
    key = parse_dkim_key("bad", "v=DKIM1; k=rsa; p=ceci-nest-pas-du-base64!!")
    assert not key.valid
    assert key.parse_error is not None


def test_espaces_dans_la_cle_toleres(rsa_2048_b64: str):
    # Certains éditeurs de zone réinsèrent des blancs dans la base64 : les
    # refuser produirait un faux constat de clé invalide.
    espace = rsa_2048_b64[:40] + " " + rsa_2048_b64[40:]
    key = parse_dkim_key("s1", f"v=DKIM1; k=rsa; p={espace}")
    assert key.valid
    assert key.key_bits == 2048


def test_type_par_defaut_rsa(rsa_2048_b64: str):
    key = parse_dkim_key("s1", f"v=DKIM1; p={rsa_2048_b64}")
    assert key.key_type == "rsa"
    assert key.key_bits == 2048


# --- attribution des sélecteurs ----------------------------------------------


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        ("cf2024-1", "Cloudflare Email"),
        ("cf2026-3", "Cloudflare Email"),
        ("ovhmo1234567-selector1", "OVHcloud"),
        ("a" * 32, "Amazon SES"),
        # Les sélecteurs génériques ne doivent désigner aucun fournisseur :
        # « s1 » est la convention de SendGrid, mais aussi le nom générique
        # le plus répandu. Conclure ici produirait un faux positif.
        ("s1", None),
        ("default", None),
        ("selector1", None),
        ("mail", None),
    ],
)
def test_deduction_du_fournisseur(selector: str, expected: str | None):
    assert infer_provider_from_selector(selector) == expected


# --- agrégation --------------------------------------------------------------


def test_signataire_deja_confirme_non_signale_comme_externe(rsa_2048_b64: str):
    analysis = analyze_dkim(
        {"cf2024-1": f"v=DKIM1; k=rsa; p={rsa_2048_b64}"},
        owners={},
        selectors_probed=50,
        domain_providers=("Cloudflare Email",),
    )
    assert analysis.present
    assert analysis.external_signers == []


def test_signataire_inattendu_signale(rsa_2048_b64: str):
    analysis = analyze_dkim(
        {"cf2024-1": f"v=DKIM1; k=rsa; p={rsa_2048_b64}"},
        owners={},
        selectors_probed=50,
        domain_providers=("Google Workspace",),
    )
    assert analysis.external_signers == ["Cloudflare Email"]


def test_absence_de_cle():
    analysis = analyze_dkim({}, owners={}, selectors_probed=78)
    assert not analysis.present
    assert analysis.selectors_probed == 78
    assert analysis.wildcard_record is None


# --- joker `*._domainkey` ----------------------------------------------------


def test_joker_revoquant_reconnu_comme_declaration_volontaire():
    # « v=DKIM1; p= » sur le joker est l'équivalent DKIM du null MX : le
    # domaine déclare qu'aucune signature ne peut le concerner.
    analysis = analyze_dkim({}, owners={}, selectors_probed=78, wildcard_record="v=DKIM1; p=")
    assert analysis.wildcard_record == "v=DKIM1; p="
    assert analysis.wildcard_revokes_all


def test_joker_actif_ne_revoque_rien(rsa_2048_b64: str):
    analysis = analyze_dkim(
        {}, owners={}, selectors_probed=78, wildcard_record=f"v=DKIM1; k=rsa; p={rsa_2048_b64}"
    )
    assert analysis.wildcard_record is not None
    assert not analysis.wildcard_revokes_all


def test_le_joker_annule_lenumeration(rsa_2048_b64: str):
    # Sans ce garde-fou, chaque sélecteur candidat produirait une fausse
    # découverte : un domaine à joker paraîtrait publier des dizaines de clés.
    analysis = analyze_dkim(
        {"default": f"v=DKIM1; p={rsa_2048_b64}", "s1": f"v=DKIM1; p={rsa_2048_b64}"},
        owners={},
        selectors_probed=78,
        wildcard_record="v=DKIM1; p=",
    )
    assert analysis.keys == []
    assert not analysis.present
