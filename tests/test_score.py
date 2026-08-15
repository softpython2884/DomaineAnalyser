"""Tests du scoring et du verdict d'usurpation."""

from __future__ import annotations

import pytest

from domaine_analyser.models import (
    Category,
    DmarcAnalysis,
    Finding,
    MalformedRecord,
    Severity,
    SpfAnalysis,
)
from domaine_analyser.score import compute_score, compute_verdict, severity_counts


def finding(severity: Severity, category: Category, code: str = "DA-TEST-001") -> Finding:
    return Finding(
        code=code,
        severity=severity,
        category=category,
        title="t",
        detail="d",
        impact="i",
        remediation="r",
    )


# --- score -------------------------------------------------------------------


def test_score_parfait_sans_constat():
    score = compute_score([])
    assert score.total == 100
    assert score.grade == "A"


def test_constat_critique_annule_sa_categorie():
    score = compute_score([finding(Severity.CRITICAL, Category.DMARC)])
    assert score.total == 70
    dmarc = next(c for c in score.categories if c.category is Category.DMARC)
    assert dmarc.earned == 0


def test_les_constats_dinformation_ne_coutent_rien():
    score = compute_score([finding(Severity.INFO, Category.HYGIENE)])
    assert score.total == 100


def test_penalite_proportionnelle_au_poids_de_la_categorie():
    # Une même gravité doit coûter proportionnellement autant dans une
    # catégorie légère que dans une catégorie lourde.
    dmarc = compute_score([finding(Severity.HIGH, Category.DMARC)])
    hygiene = compute_score([finding(Severity.HIGH, Category.HYGIENE)])
    assert dmarc.total == 100 - 15  # 50 % de 30
    assert hygiene.total == 100 - 5  # 50 % de 10


def test_une_categorie_ne_descend_jamais_sous_zero():
    findings = [
        finding(Severity.CRITICAL, Category.SPF, "DA-SPF-001"),
        finding(Severity.CRITICAL, Category.SPF, "DA-SPF-002"),
        finding(Severity.HIGH, Category.SPF, "DA-SPF-003"),
    ]
    score = compute_score(findings)
    spf = next(c for c in score.categories if c.category is Category.SPF)
    assert spf.earned == 0
    # Les autres catégories restent intactes : un problème SPF ne doit pas
    # déborder sur le score DMARC.
    assert score.total == 75


@pytest.mark.parametrize(
    ("total", "grade"),
    [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"), (45, "D"), (25, "E"), (10, "F")],
)
def test_bareme_des_notes(total: int, grade: str):
    from domaine_analyser.models import SecurityScore

    assert SecurityScore(total=total).grade == grade


def test_comptage_par_gravite():
    findings = [
        finding(Severity.CRITICAL, Category.DMARC, "a"),
        finding(Severity.HIGH, Category.SPF, "b"),
        finding(Severity.HIGH, Category.SPF, "c"),
    ]
    counts = severity_counts(findings)
    assert counts[Severity.CRITICAL] == 1
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.LOW] == 0


# --- verdict -----------------------------------------------------------------


def test_absence_de_dmarc_rend_usurpable():
    verdict = compute_verdict(DmarcAnalysis(), SpfAnalysis())
    assert verdict.spoofable
    assert verdict.subdomains_spoofable


def test_politique_none_rend_usurpable():
    dmarc = DmarcAnalysis(present=True, policy="none")
    verdict = compute_verdict(dmarc, SpfAnalysis())
    assert verdict.spoofable
    assert any("p=none" in reason for reason in verdict.reasons)


def test_politique_reject_protege():
    dmarc = DmarcAnalysis(present=True, policy="reject")
    verdict = compute_verdict(dmarc, SpfAnalysis(present=True, all_qualifier="-"))
    assert not verdict.spoofable
    assert not verdict.subdomains_spoofable


def test_sp_none_laisse_les_sous_domaines_usurpables():
    dmarc = DmarcAnalysis(present=True, policy="reject", subdomain_policy="none")
    verdict = compute_verdict(dmarc, SpfAnalysis(present=True, all_qualifier="-"))
    assert not verdict.spoofable
    assert verdict.subdomains_spoofable


def test_plus_all_contourne_une_politique_en_application():
    # DMARC est satisfait dès que SPF rend « pass » et que l'alignement tient.
    # Un « +all » fait donc passer n'importe quel message, malgré p=reject.
    dmarc = DmarcAnalysis(present=True, policy="reject")
    spf = SpfAnalysis(present=True, all_qualifier="+")
    verdict = compute_verdict(dmarc, spf)
    assert verdict.spoofable
    assert any("+all" in reason for reason in verdict.reasons)


def test_enregistrements_dmarc_multiples_rendent_usurpable():
    dmarc = DmarcAnalysis(present=True, multiple_records=True, policy="reject")
    verdict = compute_verdict(dmarc, SpfAnalysis())
    assert verdict.spoofable


def test_application_partielle_rend_usurpable():
    dmarc = DmarcAnalysis(present=True, policy="reject", percentage=50)
    verdict = compute_verdict(dmarc, SpfAnalysis(present=True, all_qualifier="-"))
    assert verdict.spoofable
    assert any("50 %" in reason for reason in verdict.reasons)


def test_dmarc_corrompu_donne_une_raison_specifique():
    # « publié mais illisible » et « absent » produisent le même comportement
    # côté serveurs, mais pas la même action corrective.
    dmarc = DmarcAnalysis(
        present=False,
        malformed=[MalformedRecord(value="&quot;v=DMARC1", reason="r", likely_cause="c")],
    )
    verdict = compute_verdict(dmarc, SpfAnalysis())
    assert verdict.spoofable
    assert any("illisible" in reason for reason in verdict.reasons)
