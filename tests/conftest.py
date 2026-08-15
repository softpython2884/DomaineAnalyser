"""Outillage commun aux tests.

Aucun test du jeu par défaut n'accède au réseau : la résolution DNS est
remplacée par `StaticLookup`, alimenté par un dictionnaire. Un audit doit
produire le même résultat sur n'importe quelle machine, et un test qui dépend
d'un domaine réel se met à échouer le jour où son propriétaire change une
ligne de sa zone.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from domaine_analyser.analyze.lookup import StaticLookup


def make_lookup(**records: list[str]) -> StaticLookup:
    """Construit un résolveur figé à partir de clés « nom__TYPE ».

    Exemple : `make_lookup(**{"example.com__TXT": ["v=spf1 -all"]})`.
    La notation évite d'écrire des tuples partout dans les tests.
    """
    table: dict[tuple[str, str], list[str]] = {}
    for key, values in records.items():
        name, _, rtype = key.rpartition("__")
        table[(name, rtype)] = values
    return StaticLookup(table)


def lookup_from(table: dict[tuple[str, str], list[str]]) -> StaticLookup:
    return StaticLookup(table)


def _public_key_b64(key: object) -> str:
    der = key.public_key().public_bytes(  # type: ignore[attr-defined]
        encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


@pytest.fixture(scope="session")
def rsa_2048_b64() -> str:
    """Clé publique RSA de 2048 bits, encodée comme dans un enregistrement DKIM."""
    return _public_key_b64(rsa.generate_private_key(public_exponent=65537, key_size=2048))


@pytest.fixture(scope="session")
def rsa_1024_b64() -> str:
    """Clé publique RSA de 1024 bits — taille jugée insuffisante aujourd'hui."""
    return _public_key_b64(rsa.generate_private_key(public_exponent=65537, key_size=1024))


@pytest.fixture(scope="session")
def ed25519_b64() -> str:
    """Clé publique Ed25519 : 32 octets bruts, sans encapsulation DER (RFC 8463)."""
    raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()
