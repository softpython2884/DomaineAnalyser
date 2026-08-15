"""Orchestration d'un audit de domaine.

Seul endroit où les trois couches se rencontrent. Il fixe l'ordre des étapes,
qui n'est pas arbitraire : l'attribution DKIM dépend des services déjà
confirmés par le SPF et les MX, faute de quoi un sélecteur générique
produirait une fausse identification.

Les collectes indépendantes — DNS, enregistrement du domaine, sondage DKIM —
partent en parallèle. L'interrogation RDAP domine le temps total, et rien ne
justifie d'attendre sa réponse pour commencer le reste.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .analyze import rules
from .analyze.caa import analyze_caa
from .analyze.dkim import analyze_dkim
from .analyze.dmarc import analyze_dmarc, organizational_domain
from .analyze.mx import analyze_mx
from .analyze.posture import analyze_posture
from .analyze.providers import detect_providers
from .analyze.spf import analyze_spf
from .collect.dkim_probe import probe_selectors
from .collect.dns_records import collect_caa, collect_dns, resolve_mx_hosts
from .config import Settings
from .models import DomainReport, RegistrationInfo, sort_findings
from .net.http import HttpClient
from .net.rdap import RdapClient
from .net.resolver import DnsResolver, is_null_mx
from .net.whois_raw import query_whois
from .score import compute_score, compute_verdict


def analyze_domain(
    domain: str,
    settings: Settings,
    *,
    deep: bool = False,
    extra_selectors: tuple[str, ...] = (),
    skip_registration: bool = False,
) -> DomainReport:
    """Exécute un audit complet et retourne le rapport.

    Args:
        deep: étend le dictionnaire de sélecteurs DKIM sondés.
        extra_selectors: sélecteurs DKIM connus à tester en priorité.
        skip_registration: n'interroge ni RDAP ni WHOIS. Utile en lot, où ces
            services limitent le débit bien avant le DNS.
    """
    domain = domain.strip().rstrip(".").lower()
    resolver = DnsResolver(settings)

    report = DomainReport(
        domain=domain,
        organizational_domain=organizational_domain(domain),
        analyzed_at=datetime.now(tz=timezone.utc),
    )

    with HttpClient(settings) as http:
        rdap = RdapClient(http, settings.cache_dir)

        with ThreadPoolExecutor(max_workers=4) as pool:
            dns_future = pool.submit(collect_dns, resolver, domain)
            caa_future = pool.submit(collect_caa, resolver, domain)
            dkim_future = pool.submit(
                probe_selectors, resolver, domain, deep=deep, extra=extra_selectors
            )
            registration_future = (
                None
                if skip_registration
                else pool.submit(_collect_registration, rdap, domain)
            )

            records = dns_future.result()
            caa_records, caa_inherited = caa_future.result()
            dkim_probe = dkim_future.result()
            if registration_future is not None:
                report.registration = registration_future.result()

    report.dns = dict(records)
    report.dns["CAA"] = caa_records

    txt_values = records["TXT"].values if records["TXT"].ok else []

    # SPF en premier : son arbre d'inclusion alimente l'identification des
    # services, qui conditionne à son tour l'attribution des clés DKIM.
    report.spf = analyze_spf(resolver, domain, txt_values)

    mx_values = records["MX"].values if records["MX"].ok else []
    null_mx = is_null_mx(mx_values)
    mx_hosts = [] if null_mx else resolve_mx_hosts(resolver, mx_values)

    provisional = detect_providers(
        mx_hostnames=[host.hostname for host in mx_hosts],
        spf_includes=report.spf.includes_resolved,
        dkim_selectors=[],
        txt_records=txt_values,
    )

    report.dkim = analyze_dkim(
        dkim_probe.found,
        dkim_probe.owners,
        dkim_probe.probed,
        domain_providers=tuple(match.name for match in provisional),
        wildcard_record=dkim_probe.wildcard_record,
    )

    report.providers = detect_providers(
        mx_hostnames=[host.hostname for host in mx_hosts],
        spf_includes=report.spf.includes_resolved,
        dkim_selectors=list(dkim_probe.found),
        txt_records=txt_values,
    )

    report.mx = analyze_mx(
        mx_hosts,
        null_mx=null_mx,
        spf_includes=report.spf.includes_resolved,
    )

    dmarc_values = records["DMARC"].values if records["DMARC"].ok else []
    report.dmarc = analyze_dmarc(resolver, domain, dmarc_values, apex_txt=txt_values)

    report.caa = analyze_caa(caa_records, caa_inherited)

    dnssec = report.registration.dnssec_signed
    if dnssec is None:
        dnssec = bool(records["DS"].ok and records["DS"].values) or resolver.is_dnssec_signed(
            domain
        )
    report.posture = analyze_posture(records, dnssec=bool(dnssec))

    report.findings = sort_findings(rules.evaluate(report))
    report.score = compute_score(report.findings)
    report.verdict = compute_verdict(report.dmarc, report.spf)

    _add_warnings(report, resolver)
    return report


def _collect_registration(rdap: RdapClient, domain: str) -> RegistrationInfo:
    """RDAP en priorité, WHOIS textuel en repli.

    RDAP couvre la quasi-totalité des gTLD mais reste absent de plusieurs
    ccTLD. Le repli n'est donc pas défensif : il est nécessaire.
    """
    info = rdap.domain(domain)
    if info.source == "rdap" and (info.created or info.registrar):
        return info

    fallback = query_whois(domain)
    if fallback.source == "whois" and (fallback.created or fallback.registrar):
        return fallback
    return info if info.source != "none" else fallback


def _add_warnings(report: DomainReport, resolver: DnsResolver) -> None:
    """Signale ce qui a limité l'audit, pour ne pas laisser croire à l'exhaustivité."""
    if resolver.doh_used:
        report.warnings.append(
            "Le port 53 sortant semble filtré : une partie des requêtes est passée "
            "par DNS-over-HTTPS."
        )

    failed = [
        key
        for key, record in report.dns.items()
        if getattr(record, "error", None) not in (None, "NXDOMAIN")
    ]
    if failed:
        report.warnings.append(
            "Requêtes DNS en échec (résultat potentiellement incomplet) : "
            + ", ".join(sorted(failed))
        )

    if report.registration.error:
        report.warnings.append(
            f"Données d'enregistrement indisponibles : {report.registration.error}"
        )

    if report.dkim.wildcard_record is not None:
        report.warnings.append(
            "Un joker « *._domainkey » répond pour tout sélecteur : l'inventaire des "
            "clés DKIM réellement en service n'a pas pu être établi."
        )
    elif not report.dkim.keys:
        report.warnings.append(
            f"{report.dkim.selectors_probed} sélecteurs DKIM testés sans résultat ; "
            "un sélecteur non conventionnel resterait invisible au sondage."
        )
