"""Analyse des clés publiques DKIM (RFC 6376 §3.6.1).

Trois anomalies méritent d'être distinguées, parce qu'elles se ressemblent
dans le DNS mais n'ont pas du tout les mêmes conséquences :

- **`p=` vide** : la clé est *révoquée*. Toute signature qui la référence est
  rejetée. Sur un sélecteur encore utilisé, tout le courrier signé tombe.
- **`t=y`** : le domaine se déclare en phase de test. La RFC §3.6.1 demande
  aux destinataires de traiter le message comme s'il n'était pas signé. Un
  drapeau oublié après une migration désarme donc DKIM en silence — la clé est
  là, valide, publiée, et ne sert à rien.
- **clé de 1024 bits** : signature encore acceptée partout, mais la taille est
  aujourd'hui considérée comme insuffisante. C'est le défaut le plus répandu,
  parce que la clé a été générée il y a des années et jamais renouvelée.
"""

from __future__ import annotations

import base64
import binascii
import re

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from ..models import DkimAnalysis, DkimKey

#: Sélecteurs Cloudflare : « cf2024-1 ». L'année étant variable, seule une
#: expression régulière permet de les reconnaître de façon durable.
_CLOUDFLARE_SELECTOR = re.compile(r"^cf\d{4}-\d+$")

#: Sélecteurs OVHcloud : « ovhmo1234567-selector1 », le nombre étant propre
#: à chaque domaine et donc impossible à énumérer.
_OVH_SELECTOR = re.compile(r"^ovhmo\d+-selector\d+$")

#: Amazon SES génère des sélecteurs aléatoires en base32 de 32 caractères.
_SES_SELECTOR = re.compile(r"^[a-z0-9]{32}$")

#: En deçà, la clé n'offre plus la garantie attendue.
MIN_SAFE_KEY_BITS = 2048


def parse_dkim_key(selector: str, record: str, *, discovered_via: str = "probe") -> DkimKey:
    """Transforme un enregistrement DKIM brut en clé analysée."""
    key = DkimKey(selector=selector, raw=record, discovered_via=discovered_via)
    tags = _parse_tags(record)

    key.key_type = (tags.get("k") or "rsa").lower()

    flags = {flag.strip().lower() for flag in (tags.get("t") or "").split(":") if flag.strip()}
    key.testing = "y" in flags
    key.strict_subdomain = "s" in flags

    public = (tags.get("p") or "").strip()
    if not public:
        # RFC 6376 §3.6.1 : « An empty value means that this public key has
        # been revoked. »
        key.revoked = True
        key.valid = False
        return key

    key.key_bits, key.parse_error = _key_size(public, key.key_type)
    key.valid = key.parse_error is None
    key.provider = infer_provider_from_selector(selector)
    return key


def _parse_tags(record: str) -> dict[str, str]:
    """Découpe un enregistrement en paires `tag=valeur`.

    Les espaces à l'intérieur de `p=` sont supprimés : certains éditeurs de
    zone réinsèrent des blancs dans la base64, ce qui rendrait le décodage
    faussement invalide.
    """
    tags: dict[str, str] = {}
    for part in record.split(";"):
        name, sep, value = part.partition("=")
        if not sep:
            continue
        name = name.strip().lower()
        if not name:
            continue
        tags[name] = re.sub(r"\s+", "", value) if name == "p" else value.strip()
    return tags


def _key_size(public_b64: str, key_type: str) -> tuple[int | None, str | None]:
    """Retourne la taille de la clé en bits, ou la raison de l'échec."""
    try:
        der = base64.b64decode(public_b64, validate=True)
    except (binascii.Error, ValueError):
        return None, "la valeur p= n'est pas du base64 valide"

    if not der:
        return None, "clé publique vide après décodage"

    if key_type == "ed25519":
        # RFC 8463 : la clé Ed25519 est publiée brute, sur 32 octets, et non
        # encapsulée dans une structure DER comme les clés RSA.
        if len(der) == 32:
            return 256, None
        return None, f"clé Ed25519 de {len(der)} octets au lieu de 32"

    try:
        loaded = load_der_public_key(der)
    except Exception:
        return None, "la clé publique n'est pas une structure DER exploitable"

    if isinstance(loaded, rsa.RSAPublicKey):
        return loaded.key_size, None
    if isinstance(loaded, ed25519.Ed25519PublicKey):
        return 256, None
    if isinstance(loaded, ec.EllipticCurvePublicKey):
        return loaded.curve.key_size, None
    return None, f"type de clé non reconnu ({type(loaded).__name__})"


def infer_provider_from_selector(selector: str) -> str | None:
    """Déduit le fournisseur d'un sélecteur dont le nom suit une convention.

    Ne traite que les motifs sans ambiguïté possible. Les sélecteurs
    génériques (`s1`, `default`, `mail`…) ne sont volontairement pas traités
    ici : leur attribution exige une corroboration par le SPF ou les MX.
    """
    selector = selector.strip().lower()
    if _CLOUDFLARE_SELECTOR.match(selector):
        return "Cloudflare Email"
    if _OVH_SELECTOR.match(selector):
        return "OVHcloud"
    if _SES_SELECTOR.match(selector):
        return "Amazon SES"
    return None


def analyze_dkim(
    found: dict[str, str],
    owners: dict[str, str],
    selectors_probed: int,
    *,
    domain_providers: tuple[str, ...] = (),
    wildcard_record: str | None = None,
) -> DkimAnalysis:
    """Assemble l'analyse DKIM à partir des enregistrements découverts.

    Args:
        found: sélecteur -> enregistrement TXT brut.
        owners: attribution issue du dictionnaire de sélecteurs.
        selectors_probed: nombre de sélecteurs testés, pour situer la couverture.
        domain_providers: services déjà confirmés par ailleurs (SPF, MX).
            Sert à distinguer un signataire attendu d'un signataire tiers.
        wildcard_record: valeur d'un joker `*._domainkey`. Sa présence rend
            l'énumération sans objet : aucune clé n'est alors retenue.
    """
    analysis = DkimAnalysis(selectors_probed=selectors_probed, wildcard_record=wildcard_record)
    if wildcard_record is not None:
        return analysis

    for selector in sorted(found):
        key = parse_dkim_key(selector, found[selector])
        key.provider = key.provider or owners.get(selector)
        analysis.keys.append(key)

    known = {name.lower() for name in domain_providers}
    for key in analysis.keys:
        if (
            key.provider
            and key.provider.lower() not in known
            and key.provider not in analysis.external_signers
        ):
            analysis.external_signers.append(key.provider)

    return analysis
