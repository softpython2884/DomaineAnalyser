"""Profilage passif d'une adresse IP.

Trois sources, toutes publiques et sans authentification :

- **DNS inverse**, complété d'une *confirmation directe* : on vérifie que le
  nom obtenu pointe bien en retour vers l'adresse de départ. Sans cette
  vérification, un rDNS est déclaratif — le détenteur de la plage y écrit ce
  qu'il veut, et un `mail-google-com.attaquant.net` passerait pour Google.

- **Service Team Cymru**, interrogé en DNS, qui donne le numéro d'AS, le
  préfixe BGP annoncé et le pays. Choisi plutôt qu'une API HTTP pour rester
  cohérent avec le reste de la collecte, et parce qu'il n'impose aucun quota.

- **RDAP du RIR**, pour le nom de la plage, l'organisation et le contact abuse.
"""

from __future__ import annotations

import ipaddress

from ..models import IpProfile
from ..net.rdap import RdapClient, parse_ip_object
from ..net.resolver import DnsResolver

_CYMRU_IPV4 = "origin.asn.cymru.com"
_CYMRU_IPV6 = "origin6.asn.cymru.com"
_CYMRU_AS = "asn.cymru.com"


def profile_ip(
    resolver: DnsResolver,
    address: str,
    *,
    rdap: RdapClient | None = None,
) -> IpProfile:
    """Construit le profil public d'une adresse IP."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return IpProfile(address=address, error="adresse IP invalide")

    profile = IpProfile(address=str(parsed))

    if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
        profile.error = "adresse non routable sur Internet"
        return profile

    _fill_rdns(resolver, profile, parsed)
    _fill_asn(resolver, profile, parsed)

    if rdap is not None:
        payload = rdap.ip(str(parsed))
        if payload:
            fields = parse_ip_object(payload)
            profile.netname = fields.get("netname")
            profile.organization = fields.get("organization")
            profile.abuse_email = fields.get("abuse_email")
            profile.country = profile.country or fields.get("country")

    return profile


def _fill_rdns(
    resolver: DnsResolver,
    profile: IpProfile,
    parsed: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> None:
    pointer = ipaddress.ip_address(str(parsed)).reverse_pointer
    rrset = resolver.query(pointer, "PTR")
    if not rrset.ok or not rrset.values:
        return

    profile.rdns = rrset.values[0].rstrip(".").lower()

    # Confirmation directe : le nom doit se résoudre vers l'IP de départ.
    for rtype in ("A", "AAAA"):
        forward = resolver.query(profile.rdns, rtype)
        if forward.ok and str(parsed) in forward.values:
            profile.forward_confirmed = True
            return


def _fill_asn(
    resolver: DnsResolver,
    profile: IpProfile,
    parsed: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> None:
    if parsed.version == 4:
        query = f"{'.'.join(reversed(str(parsed).split('.')))}.{_CYMRU_IPV4}"
    else:
        nibbles = parsed.exploded.replace(":", "")
        query = f"{'.'.join(reversed(nibbles))}.{_CYMRU_IPV6}"

    origin = resolver.query(query, "TXT")
    if not origin.ok or not origin.values:
        return

    # Format : « 15169 | 8.8.8.0/24 | US | arin | 1992-12-01 »
    fields = [part.strip() for part in origin.values[0].split("|")]
    if not fields:
        return

    # Une IP peut être annoncée par plusieurs AS (multi-homing) ; on retient
    # le premier, en conservant l'information dans le nom.
    asn_text = fields[0].split()[0] if fields[0] else ""
    if asn_text.isdigit():
        profile.asn = int(asn_text)
    if len(fields) > 1:
        profile.bgp_prefix = fields[1] or None
    if len(fields) > 2:
        profile.country = fields[2] or None
    if len(fields) > 3:
        profile.registry = fields[3] or None

    if profile.asn is None:
        return

    as_info = resolver.query(f"AS{profile.asn}.{_CYMRU_AS}", "TXT")
    if as_info.ok and as_info.values:
        # Format : « 15169 | US | arin | 1992-12-01 | GOOGLE, US »
        as_fields = [part.strip() for part in as_info.values[0].split("|")]
        if len(as_fields) >= 5 and as_fields[4]:
            profile.as_name = as_fields[4]
