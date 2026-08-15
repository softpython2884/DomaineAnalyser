"""Types du domaine métier.

Ce module ne fait aucune entrée/sortie et ne dépend d'aucun autre module du
projet. C'est le contrat partagé entre les trois couches : la collecte le
remplit, l'analyse le lit et produit des `Finding`, la restitution le rend.

Un choix structurant : `Finding` exige `impact` et `remediation`. Une règle qui
ne sait pas dire ce qu'un attaquant peut en faire, ni quoi corriger, n'a pas sa
place dans le rapport. Cette contrainte est portée par le typage, pas par la
discipline du contributeur.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Sévérité et catégories
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Gravité d'un constat, du plus grave au plus anodin."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Ordre de tri décroissant (0 = le plus grave)."""
        return _SEVERITY_RANK[self]

    @property
    def label_fr(self) -> str:
        return _SEVERITY_LABEL_FR[self]

    @property
    def penalty_ratio(self) -> float:
        """Fraction du poids de la catégorie retirée par ce constat.

        Exprimer la pénalité en proportion — et non en points absolus — permet
        d'utiliser la même échelle de gravité pour toutes les catégories, quel
        que soit leur poids respectif dans le score.
        """
        return _SEVERITY_PENALTY[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_LABEL_FR: dict[Severity, str] = {
    Severity.CRITICAL: "Critique",
    Severity.HIGH: "Élevé",
    Severity.MEDIUM: "Moyen",
    Severity.LOW: "Faible",
    Severity.INFO: "Information",
}

_SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 1.00,  # annule la catégorie
    Severity.HIGH: 0.50,
    Severity.MEDIUM: 0.25,
    Severity.LOW: 0.10,
    Severity.INFO: 0.00,
}


class Category(str, Enum):
    """Domaine de contrôle auquel se rattache un constat."""

    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    MX = "mx"
    HYGIENE = "hygiene"

    @property
    def label_fr(self) -> str:
        return _CATEGORY_LABEL_FR[self]

    @property
    def weight(self) -> int:
        """Poids dans le score sur 100."""
        return _CATEGORY_WEIGHT[self]


_CATEGORY_LABEL_FR: dict[Category, str] = {
    Category.SPF: "SPF",
    Category.DKIM: "DKIM",
    Category.DMARC: "DMARC",
    Category.MX: "Transport / MX",
    Category.HYGIENE: "Hygiène DNS",
}

# DMARC pèse le plus lourd : c'est le seul mécanisme qui protège réellement
# l'adresse visible par l'utilisateur (le From:), donc le seul qui bloque
# effectivement l'usurpation. SPF et DKIM ne font que l'alimenter.
_CATEGORY_WEIGHT: dict[Category, int] = {
    Category.DMARC: 30,
    Category.SPF: 25,
    Category.DKIM: 20,
    Category.MX: 15,
    Category.HYGIENE: 10,
}


# ---------------------------------------------------------------------------
# Constat
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """Un constat unitaire, factuel et actionnable.

    Attributes:
        code: identifiant stable et documentable (ex. « DA-SPF-004 »). Stable
            d'une version à l'autre pour permettre le suivi et les exclusions.
        detail: ce qui a été observé, sans interprétation.
        impact: ce que cela permet concrètement à un attaquant.
        remediation: l'action à mener, formulée pour être appliquée telle quelle.
        evidence: extraits bruts justifiant le constat (enregistrement DNS…).
        refs: références normatives (RFC, documentation éditeur).
    """

    code: str
    severity: Severity
    category: Category
    title: str
    detail: str
    impact: str
    remediation: str
    evidence: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "detail": self.detail,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": list(self.evidence),
            "refs": list(self.refs),
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Trie par gravité décroissante, puis par code pour un ordre déterministe."""
    return sorted(findings, key=lambda f: (f.severity.rank, f.code))


# ---------------------------------------------------------------------------
# Enregistrements DNS
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DnsRecordSet:
    """Résultat d'une requête DNS, succès comme échec.

    Un échec est une donnée à part entière : « pas de DMARC » et « le serveur
    DNS n'a pas répondu » mènent à des conclusions opposées, et les confondre
    produirait de faux constats.
    """

    name: str
    rtype: str
    values: list[str] = field(default_factory=list)
    ttl: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def empty(self) -> bool:
        """Vrai si la requête a abouti mais qu'aucun enregistrement n'existe."""
        return self.error is None and not self.values

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.rtype,
            "values": list(self.values),
            "ttl": self.ttl,
            "error": self.error,
        }


@dataclass(slots=True)
class MxHost:
    """Un hôte MX et sa résolution."""

    preference: int
    hostname: str
    addresses: list[str] = field(default_factory=list)
    resolves: bool = True
    is_cname: bool = False
    provider: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "preference": self.preference,
            "hostname": self.hostname,
            "addresses": list(self.addresses),
            "resolves": self.resolves,
            "is_cname": self.is_cname,
            "provider": self.provider,
        }


# ---------------------------------------------------------------------------
# Résultats d'analyse par mécanisme
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class MalformedRecord:
    """Enregistrement publié au bon endroit mais que les serveurs ignoreront.

    Ce cas est plus dangereux qu'une absence pure : la configuration existe,
    elle est visible dans l'interface de l'hébergeur, et son auteur la croit
    active. Nommer la corruption exacte permet de la corriger en une minute
    plutôt que de repartir de zéro.
    """

    value: str
    reason: str
    likely_cause: str

    def to_dict(self) -> dict[str, Any]:
        return {"value": self.value, "reason": self.reason, "likely_cause": self.likely_cause}


@dataclass(slots=True)
class SpfMechanism:
    """Un mécanisme SPF, replacé dans l'arbre d'inclusion."""

    qualifier: str  # '+', '-', '~', '?'
    kind: str  # all, ip4, ip6, a, mx, ptr, exists, include, redirect
    value: str | None
    depth: int = 0
    source_domain: str = ""
    costs_lookup: bool = False


@dataclass(slots=True)
class SpfAnalysis:
    """Analyse statique de posture SPF.

    Complète — sans la remplacer — l'évaluation `pyspf`, qui répond à « cette IP
    passe-t-elle ? ». Ici on répond à « qui peut en abuser, et ce SPF est-il
    seulement évaluable ? ».
    """

    present: bool = False
    raw: str | None = None
    multiple_records: bool = False
    all_records: list[str] = field(default_factory=list)
    valid_syntax: bool = True
    syntax_errors: list[str] = field(default_factory=list)
    #: TXT ressemblant à un SPF mais que les serveurs n'identifieront pas.
    malformed: list[MalformedRecord] = field(default_factory=list)
    mechanisms: list[SpfMechanism] = field(default_factory=list)
    all_qualifier: str | None = None
    lookup_count: int = 0
    void_lookup_count: int = 0
    exceeds_lookup_limit: bool = False
    include_tree: dict[str, Any] = field(default_factory=dict)
    includes_resolved: list[str] = field(default_factory=list)
    circular_includes: list[str] = field(default_factory=list)
    unresolvable_includes: list[str] = field(default_factory=list)
    ipv4_space: int = 0
    ipv6_space: int = 0
    uses_ptr: bool = False
    shared_pools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "raw": self.raw,
            "multiple_records": self.multiple_records,
            "valid_syntax": self.valid_syntax,
            "syntax_errors": list(self.syntax_errors),
            "malformed": [item.to_dict() for item in self.malformed],
            "all_qualifier": self.all_qualifier,
            "lookup_count": self.lookup_count,
            "void_lookup_count": self.void_lookup_count,
            "exceeds_lookup_limit": self.exceeds_lookup_limit,
            "includes_resolved": list(self.includes_resolved),
            "circular_includes": list(self.circular_includes),
            "unresolvable_includes": list(self.unresolvable_includes),
            "ipv4_space": self.ipv4_space,
            "ipv6_space": self.ipv6_space,
            "uses_ptr": self.uses_ptr,
            "shared_pools": list(self.shared_pools),
        }


@dataclass(slots=True)
class DkimKey:
    """Une clé publique DKIM découverte pour un sélecteur."""

    selector: str
    raw: str
    key_type: str = "rsa"
    key_bits: int | None = None
    revoked: bool = False
    testing: bool = False
    strict_subdomain: bool = False
    valid: bool = True
    parse_error: str | None = None
    provider: str | None = None
    discovered_via: str = "probe"  # probe | rua | manual

    def to_dict(self) -> dict[str, Any]:
        return {
            "selector": self.selector,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "revoked": self.revoked,
            "testing": self.testing,
            "strict_subdomain": self.strict_subdomain,
            "valid": self.valid,
            "parse_error": self.parse_error,
            "provider": self.provider,
            "discovered_via": self.discovered_via,
        }


@dataclass(slots=True)
class DkimAnalysis:
    keys: list[DkimKey] = field(default_factory=list)
    selectors_probed: int = 0
    external_signers: list[str] = field(default_factory=list)
    #: Valeur d'un joker `*._domainkey`, s'il existe. Sa présence rend le
    #: sondage de sélecteurs inopérant : tout nom interrogé répond.
    wildcard_record: str | None = None

    @property
    def present(self) -> bool:
        return bool(self.keys)

    @property
    def wildcard_revokes_all(self) -> bool:
        """Vrai si le joker déclare qu'aucune clé n'est valide (`p=` vide).

        C'est une déclaration volontaire, équivalente au « null MX » : elle
        indique que le domaine ne signe rien et ne doit rien signer.
        """
        if self.wildcard_record is None:
            return False
        tags = {
            part.split("=", 1)[0].strip().lower(): part.split("=", 1)[-1].strip()
            for part in self.wildcard_record.split(";")
            if "=" in part
        }
        return not tags.get("p", "").strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "selectors_probed": self.selectors_probed,
            "external_signers": list(self.external_signers),
            "wildcard_record": self.wildcard_record,
            "wildcard_revokes_all": self.wildcard_revokes_all,
            "keys": [k.to_dict() for k in self.keys],
        }


@dataclass(slots=True)
class DmarcReportTarget:
    """Destination `rua`/`ruf`, avec l'autorisation externe RFC 7489 §7.1."""

    uri: str
    domain: str
    is_external: bool = False
    authorized: bool | None = None  # None = vérification non applicable
    authorization_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "domain": self.domain,
            "is_external": self.is_external,
            "authorized": self.authorized,
            "authorization_error": self.authorization_error,
        }


@dataclass(slots=True)
class DmarcAnalysis:
    present: bool = False
    raw: str | None = None
    multiple_records: bool = False
    all_records: list[str] = field(default_factory=list)
    valid_syntax: bool = True
    syntax_errors: list[str] = field(default_factory=list)
    #: Enregistrements présents sur `_dmarc` mais non reconnus comme DMARC.
    #: Distinguer « rien de publié » de « publié mais illisible » est
    #: essentiel : le second cas donne au propriétaire la certitude trompeuse
    #: d'être protégé.
    malformed: list[MalformedRecord] = field(default_factory=list)
    #: Enregistrement DMARC publié à tort sur le domaine lui-même.
    misplaced_at_apex: list[str] = field(default_factory=list)
    inherited_from: str | None = None  # domaine organisationnel si héritage
    policy: str | None = None  # none | quarantine | reject
    subdomain_policy: str | None = None
    percentage: int = 100
    adkim: str = "r"
    aspf: str = "r"
    failure_options: str | None = None
    report_interval: int | None = None
    rua: list[DmarcReportTarget] = field(default_factory=list)
    ruf: list[DmarcReportTarget] = field(default_factory=list)

    @property
    def effective_subdomain_policy(self) -> str | None:
        """Politique réellement appliquée aux sous-domaines (`sp` sinon `p`)."""
        return self.subdomain_policy or self.policy

    @property
    def enforcing(self) -> bool:
        return self.policy in ("quarantine", "reject")

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "raw": self.raw,
            "multiple_records": self.multiple_records,
            "valid_syntax": self.valid_syntax,
            "syntax_errors": list(self.syntax_errors),
            "malformed": [item.to_dict() for item in self.malformed],
            "misplaced_at_apex": list(self.misplaced_at_apex),
            "inherited_from": self.inherited_from,
            "policy": self.policy,
            "subdomain_policy": self.subdomain_policy,
            "effective_subdomain_policy": self.effective_subdomain_policy,
            "percentage": self.percentage,
            "adkim": self.adkim,
            "aspf": self.aspf,
            "failure_options": self.failure_options,
            "report_interval": self.report_interval,
            "rua": [t.to_dict() for t in self.rua],
            "ruf": [t.to_dict() for t in self.ruf],
        }


@dataclass(slots=True)
class MxAnalysis:
    hosts: list[MxHost] = field(default_factory=list)
    null_mx: bool = False
    providers: list[str] = field(default_factory=list)
    inconsistent_with_spf: list[str] = field(default_factory=list)

    @property
    def present(self) -> bool:
        return bool(self.hosts) or self.null_mx

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "null_mx": self.null_mx,
            "providers": list(self.providers),
            "inconsistent_with_spf": list(self.inconsistent_with_spf),
            "hosts": [h.to_dict() for h in self.hosts],
        }


@dataclass(slots=True)
class CaaAnalysis:
    present: bool = False
    records: list[str] = field(default_factory=list)
    issuers: list[str] = field(default_factory=list)
    wildcard_issuers: list[str] = field(default_factory=list)
    has_iodef: bool = False
    inherited_from: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "present": self.present,
            "records": list(self.records),
            "issuers": list(self.issuers),
            "wildcard_issuers": list(self.wildcard_issuers),
            "has_iodef": self.has_iodef,
            "inherited_from": self.inherited_from,
        }


@dataclass(slots=True)
class PostureAnalysis:
    """Mécanismes complémentaires de durcissement."""

    dnssec: bool = False
    mta_sts: bool = False
    mta_sts_mode: str | None = None  # none | testing | enforce
    tls_rpt: bool = False
    bimi: bool = False
    bimi_has_vmc: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "dnssec": self.dnssec,
            "mta_sts": self.mta_sts,
            "mta_sts_mode": self.mta_sts_mode,
            "tls_rpt": self.tls_rpt,
            "bimi": self.bimi,
            "bimi_has_vmc": self.bimi_has_vmc,
        }


# ---------------------------------------------------------------------------
# Fournisseurs et enregistrement du domaine
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class ProviderMatch:
    """Service tiers détecté et signaux qui l'ont trahi."""

    name: str
    kind: str  # mailbox | esp | security_gateway | dns | other
    signals: list[str] = field(default_factory=list)
    can_send_as_domain: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "signals": list(self.signals),
            "can_send_as_domain": self.can_send_as_domain,
        }


@dataclass(slots=True)
class IpProfile:
    """Ce que l'on sait d'une adresse IP à partir de sources publiques.

    Sert autant à qualifier un hôte MX qu'à profiler une IP surprise en train
    d'émettre au nom du domaine dans les rapports DMARC.
    """

    address: str
    rdns: str | None = None
    forward_confirmed: bool = False
    asn: int | None = None
    as_name: str | None = None
    bgp_prefix: str | None = None
    country: str | None = None
    registry: str | None = None
    netname: str | None = None
    organization: str | None = None
    abuse_email: str | None = None
    error: str | None = None

    @property
    def as_label(self) -> str:
        if self.asn is None:
            return "ASN inconnu"
        return f"AS{self.asn}" + (f" ({self.as_name})" if self.as_name else "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "rdns": self.rdns,
            "forward_confirmed": self.forward_confirmed,
            "asn": self.asn,
            "as_name": self.as_name,
            "bgp_prefix": self.bgp_prefix,
            "country": self.country,
            "registry": self.registry,
            "netname": self.netname,
            "organization": self.organization,
            "abuse_email": self.abuse_email,
            "error": self.error,
        }


@dataclass(slots=True)
class RegistrationInfo:
    """Données d'enregistrement, issues de RDAP en priorité, WHOIS en repli."""

    source: str = "none"  # rdap | whois | none
    registrar: str | None = None
    registrant: str | None = None
    registrant_country: str | None = None
    created: datetime | None = None
    updated: datetime | None = None
    expires: datetime | None = None
    nameservers: list[str] = field(default_factory=list)
    statuses: list[str] = field(default_factory=list)
    dnssec_signed: bool | None = None
    abuse_email: str | None = None
    raw: str | None = None
    error: str | None = None

    @property
    def age_days(self) -> int | None:
        if self.created is None:
            return None
        created = self.created
        now = datetime.now(tz=created.tzinfo) if created.tzinfo else datetime.now()
        return (now - created).days

    def to_dict(self) -> dict[str, Any]:
        def iso(value: datetime | None) -> str | None:
            return value.isoformat() if value else None

        return {
            "source": self.source,
            "registrar": self.registrar,
            "registrant": self.registrant,
            "registrant_country": self.registrant_country,
            "created": iso(self.created),
            "updated": iso(self.updated),
            "expires": iso(self.expires),
            "age_days": self.age_days,
            "nameservers": list(self.nameservers),
            "statuses": list(self.statuses),
            "dnssec_signed": self.dnssec_signed,
            "abuse_email": self.abuse_email,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Score et rapport
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class CategoryScore:
    category: Category
    weight: int
    earned: float

    @property
    def lost(self) -> float:
        return self.weight - self.earned

    @property
    def ratio(self) -> float:
        return self.earned / self.weight if self.weight else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "weight": self.weight,
            "earned": round(self.earned, 1),
            "lost": round(self.lost, 1),
        }


@dataclass(slots=True)
class SecurityScore:
    total: int
    categories: list[CategoryScore] = field(default_factory=list)

    @property
    def grade(self) -> str:
        if self.total >= 90:
            return "A"
        if self.total >= 75:
            return "B"
        if self.total >= 60:
            return "C"
        if self.total >= 40:
            return "D"
        if self.total >= 20:
            return "E"
        return "F"

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "grade": self.grade,
            "categories": [c.to_dict() for c in self.categories],
        }


@dataclass(slots=True)
class SpoofingVerdict:
    """Réponse à la seule question qui compte vraiment pour l'utilisateur.

    Un tiers quelconque peut-il envoyer un message affichant ce domaine en
    expéditeur, et le voir arriver en boîte de réception ?
    """

    spoofable: bool
    subdomains_spoofable: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spoofable": self.spoofable,
            "subdomains_spoofable": self.subdomains_spoofable,
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class DomainReport:
    """Rapport complet d'audit d'un domaine."""

    domain: str
    organizational_domain: str
    analyzed_at: datetime
    dns: dict[str, DnsRecordSet] = field(default_factory=dict)
    registration: RegistrationInfo = field(default_factory=RegistrationInfo)
    spf: SpfAnalysis = field(default_factory=SpfAnalysis)
    dkim: DkimAnalysis = field(default_factory=DkimAnalysis)
    dmarc: DmarcAnalysis = field(default_factory=DmarcAnalysis)
    mx: MxAnalysis = field(default_factory=MxAnalysis)
    caa: CaaAnalysis = field(default_factory=CaaAnalysis)
    posture: PostureAnalysis = field(default_factory=PostureAnalysis)
    providers: list[ProviderMatch] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: SecurityScore = field(default_factory=lambda: SecurityScore(total=0))
    verdict: SpoofingVerdict = field(
        default_factory=lambda: SpoofingVerdict(spoofable=False, subdomains_spoofable=False)
    )
    # Bloc d'enrichissement externe, volontairement typé en texte libre :
    # il est produit hors du moteur déterministe et ne peut rien y injecter.
    ai_enrichment: str | None = None
    warnings: list[str] = field(default_factory=list)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity is severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "organizational_domain": self.organizational_domain,
            "analyzed_at": self.analyzed_at.isoformat(),
            "score": self.score.to_dict(),
            "verdict": self.verdict.to_dict(),
            "registration": self.registration.to_dict(),
            "dns": {k: v.to_dict() for k, v in self.dns.items()},
            "spf": self.spf.to_dict(),
            "dkim": self.dkim.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "mx": self.mx.to_dict(),
            "caa": self.caa.to_dict(),
            "posture": self.posture.to_dict(),
            "providers": [p.to_dict() for p in self.providers],
            "findings": [f.to_dict() for f in sort_findings(self.findings)],
            "warnings": list(self.warnings),
            "ai_enrichment": self.ai_enrichment,
        }
