"""Moteur de règles : transforme les analyses en constats actionnables.

Toutes les règles sont regroupées ici plutôt que dispersées dans les
analyseurs. Deux raisons : les niveaux de gravité restent comparables entre
eux parce qu'ils sont décidés au même endroit, et l'ensemble des constats
possibles se lit d'un seul fichier — ce qui rend l'outil auditable par qui
doit s'en servir comme référence.

Chaque règle porte un code stable (`DA-SPF-005`), cité tel quel dans les
rapports. Il permet de suivre un constat dans le temps et de l'exclure sans
ambiguïté quand un risque est accepté en connaissance de cause.
"""

from __future__ import annotations

from ..models import Category, DomainReport, Finding, Severity
from .caa import blocks_all_issuance
from .dkim import MIN_SAFE_KEY_BITS
from .malformed import repaired_preview
from .spf import MAX_LOOKUPS, MAX_VOID_LOOKUPS, format_address_space

#: Seuil au-delà duquel l'espace autorisé cesse d'être maîtrisable.
_LARGE_ADDRESS_SPACE = 1_000_000

#: En dessous, un domaine récemment enregistré mérite d'être signalé : c'est
#: un marqueur commun aux infrastructures d'usurpation, qui sont jetables.
_YOUNG_DOMAIN_DAYS = 90


def evaluate(report: DomainReport) -> list[Finding]:
    """Applique toutes les règles au rapport et retourne les constats."""
    findings: list[Finding] = []
    findings.extend(_spf_rules(report))
    findings.extend(_dkim_rules(report))
    findings.extend(_dmarc_rules(report))
    findings.extend(_mx_rules(report))
    findings.extend(_hygiene_rules(report))
    return findings


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------


def _spf_rules(report: DomainReport) -> list[Finding]:
    spf = report.spf
    out: list[Finding] = []

    for item in spf.malformed:
        out.append(
            Finding(
                code="DA-SPF-016",
                severity=Severity.HIGH,
                category=Category.SPF,
                title="Un enregistrement SPF est publié mais illisible",
                detail=f"{item.reason.capitalize()}. Cause probable : {item.likely_cause}.",
                impact=(
                    "La valeur n'est reconnue par aucun serveur : le domaine se comporte "
                    "comme s'il ne publiait aucun SPF, alors que l'enregistrement est "
                    "bien visible dans l'interface de l'hébergeur."
                ),
                remediation=(
                    "Republier la valeur sans les caractères parasites : "
                    f"« {repaired_preview(item.value)} »."
                ),
                evidence=(item.value,),
                refs=("RFC 7208 §3.1",),
            )
        )

    if not spf.present:
        if spf.malformed:
            return out
        return [
            *out,
            Finding(
                code="DA-SPF-001",
                severity=Severity.HIGH,
                category=Category.SPF,
                title="Aucun enregistrement SPF publié",
                detail=f"Le domaine {report.domain} ne publie aucun enregistrement TXT « v=spf1 ».",
                impact=(
                    "Aucun serveur d'envoi n'est déclaré légitime. Les destinataires ne "
                    "disposent d'aucun moyen de distinguer vos serveurs de ceux d'un tiers, "
                    "et DMARC ne peut pas s'appuyer sur SPF pour valider vos messages."
                ),
                remediation=(
                    "Publier un enregistrement TXT recensant vos serveurs d'envoi et se "
                    "terminant par « -all ». Commencer par « ~all » le temps de vérifier "
                    "qu'aucun flux légitime n'a été oublié."
                ),
                refs=("RFC 7208",),
            )
        ]

    if spf.multiple_records:
        out.append(
            Finding(
                code="DA-SPF-002",
                severity=Severity.CRITICAL,
                category=Category.SPF,
                title="Plusieurs enregistrements SPF publiés",
                detail=f"{len(spf.all_records)} enregistrements « v=spf1 » coexistent sur le domaine.",
                impact=(
                    "L'évaluation rend « permerror » et SPF est intégralement ignoré. "
                    "La protection est nulle, alors que la configuration paraît en place."
                ),
                remediation=(
                    "Ne conserver qu'un seul enregistrement, en fusionnant les mécanismes "
                    "des autres dans celui-ci."
                ),
                evidence=tuple(spf.all_records),
                refs=("RFC 7208 §4.5",),
            )
        )
        return out

    if spf.all_qualifier == "+":
        out.append(
            Finding(
                code="DA-SPF-003",
                severity=Severity.CRITICAL,
                category=Category.SPF,
                title="Le SPF autorise tout Internet (« +all »)",
                detail="L'enregistrement se termine par « +all ».",
                impact=(
                    "Toute adresse IP de la planète est déclarée légitime pour envoyer "
                    "au nom du domaine. SPF valide alors n'importe quel message, y compris "
                    "celui d'un usurpateur, et alimente DMARC en résultat « pass »."
                ),
                remediation="Remplacer « +all » par « -all ».",
                evidence=(spf.raw or "",),
                refs=("RFC 7208 §5.1",),
            )
        )
    elif spf.all_qualifier == "?":
        out.append(
            Finding(
                code="DA-SPF-004",
                severity=Severity.HIGH,
                category=Category.SPF,
                title="Le SPF se termine par « ?all » (neutre)",
                detail="Le qualificateur terminal est « ? », qui n'exprime aucune position.",
                impact=(
                    "Un message provenant d'une adresse non listée obtient « neutral », "
                    "traité comme une absence de SPF. La politique n'apporte aucune "
                    "protection contre l'usurpation."
                ),
                remediation="Remplacer « ?all » par « -all », ou « ~all » en phase de transition.",
                evidence=(spf.raw or "",),
            )
        )
    elif spf.all_qualifier is None:
        out.append(
            Finding(
                code="DA-SPF-014",
                severity=Severity.MEDIUM,
                category=Category.SPF,
                title="Le SPF ne comporte pas de mécanisme terminal « all »",
                detail="Aucun terme « all » n'a été trouvé dans l'enregistrement.",
                impact=(
                    "Une adresse non listée obtient « neutral » par défaut : le SPF "
                    "n'exclut personne explicitement."
                ),
                remediation="Ajouter « -all » en fin d'enregistrement.",
                evidence=(spf.raw or "",),
            )
        )

    if spf.exceeds_lookup_limit:
        out.append(
            Finding(
                code="DA-SPF-005",
                severity=Severity.HIGH,
                category=Category.SPF,
                title=f"Le SPF dépasse la limite de {MAX_LOOKUPS} résolutions DNS",
                detail=(
                    f"L'évaluation complète nécessite {spf.lookup_count} résolutions, "
                    f"pour un maximum autorisé de {MAX_LOOKUPS}."
                ),
                impact=(
                    "Les destinataires conformes rendent « permerror » et ignorent le SPF. "
                    "La panne est silencieuse : rien dans le DNS ne la signale, et elle "
                    "survient en général à l'ajout d'un prestataire dont l'include: "
                    "consomme lui-même plusieurs résolutions."
                ),
                remediation=(
                    "Retirer les « include: » inutilisés, regrouper les prestataires, ou "
                    "remplacer les include: les plus coûteux par les plages « ip4: » "
                    "correspondantes — en acceptant de devoir les maintenir."
                ),
                evidence=(spf.raw or "", f"include: résolus : {', '.join(spf.includes_resolved)}"),
                refs=("RFC 7208 §4.6.4",),
            )
        )
    elif spf.lookup_count >= MAX_LOOKUPS - 1:
        out.append(
            Finding(
                code="DA-SPF-015",
                severity=Severity.LOW,
                category=Category.SPF,
                title="Le SPF est proche de la limite de résolutions DNS",
                detail=f"{spf.lookup_count} résolutions sur {MAX_LOOKUPS} autorisées.",
                impact=(
                    "L'ajout d'un seul prestataire fera basculer l'évaluation en "
                    "« permerror », ce qui désactivera SPF sans avertissement."
                ),
                remediation="Faire le ménage dès maintenant dans les « include: » devenus inutiles.",
            )
        )

    if spf.void_lookup_count > MAX_VOID_LOOKUPS:
        out.append(
            Finding(
                code="DA-SPF-006",
                severity=Severity.MEDIUM,
                category=Category.SPF,
                title="Trop de résolutions DNS sans réponse",
                detail=(
                    f"{spf.void_lookup_count} résolutions ne renvoient aucun enregistrement, "
                    f"pour un maximum de {MAX_VOID_LOOKUPS}."
                ),
                impact="L'évaluation rend « permerror » et le SPF est ignoré.",
                remediation="Retirer les mécanismes pointant vers des noms qui n'existent plus.",
                refs=("RFC 7208 §4.6.4",),
            )
        )

    if spf.uses_ptr:
        out.append(
            Finding(
                code="DA-SPF-007",
                severity=Severity.LOW,
                category=Category.SPF,
                title="Le SPF utilise le mécanisme « ptr », déconseillé",
                detail="Un mécanisme « ptr » figure dans l'arbre SPF.",
                impact=(
                    "Le mécanisme est coûteux et peu fiable ; la RFC en déconseille "
                    "formellement l'usage et certains destinataires l'ignorent, ce qui "
                    "rend le résultat imprévisible."
                ),
                remediation="Remplacer « ptr » par les plages « ip4: »/« ip6: » correspondantes.",
                refs=("RFC 7208 §5.5",),
            )
        )

    for target in spf.unresolvable_includes:
        out.append(
            Finding(
                code="DA-SPF-009",
                severity=Severity.MEDIUM,
                category=Category.SPF,
                title=f"« include:{target} » ne renvoie aucun SPF",
                detail=f"Le domaine {target} ne publie pas d'enregistrement « v=spf1 ».",
                impact=(
                    "L'évaluation rend « permerror ». Il s'agit souvent d'un prestataire "
                    "dont le contrat a pris fin : le nom peut être réenregistré par un "
                    "tiers, qui héritera alors d'une autorisation d'envoi en votre nom."
                ),
                remediation=f"Retirer « include:{target} » de l'enregistrement.",
            )
        )

    for target in spf.circular_includes:
        out.append(
            Finding(
                code="DA-SPF-010",
                severity=Severity.MEDIUM,
                category=Category.SPF,
                title="Inclusion SPF circulaire",
                detail=f"Le domaine {target} est inclus de façon récursive.",
                impact="L'évaluation rend « permerror » et le SPF est ignoré.",
                remediation="Rompre le cycle en retirant l'un des « include: » en cause.",
            )
        )

    if spf.ipv4_space >= _LARGE_ADDRESS_SPACE and spf.all_qualifier != "+":
        out.append(
            Finding(
                code="DA-SPF-011",
                severity=Severity.MEDIUM,
                category=Category.SPF,
                title="Le SPF autorise un espace d'adressage très large",
                detail=(
                    f"{format_address_space(spf.ipv4_space)} IPv4 sont autorisées à "
                    "émettre au nom du domaine."
                ),
                impact=(
                    "Chacune de ces adresses produit un résultat SPF « pass ». La "
                    "compromission d'un seul hôte dans l'une de ces plages suffit à "
                    "émettre du courrier authentifié en votre nom."
                ),
                remediation=(
                    "Restreindre aux plages réellement utilisées et retirer les "
                    "prestataires qui ne servent plus."
                ),
            )
        )

    if spf.shared_pools:
        out.append(
            Finding(
                code="DA-SPF-012",
                severity=Severity.LOW,
                category=Category.SPF,
                title="Le SPF autorise des plateformes à adresses mutualisées",
                detail="Plateformes concernées : " + ", ".join(spf.shared_pools) + ".",
                impact=(
                    "Les adresses d'envoi de ces services sont partagées entre tous "
                    "leurs clients. Le SPF ne distingue donc pas vos envois de ceux "
                    "d'un autre client de la même plateforme."
                ),
                remediation=(
                    "S'appuyer sur DKIM plutôt que sur SPF pour ces flux, en exigeant "
                    "une signature au nom de votre domaine, et activer une adresse IP "
                    "dédiée si le service le permet."
                ),
            )
        )

    if spf.syntax_errors and not spf.multiple_records:
        out.append(
            Finding(
                code="DA-SPF-008",
                severity=Severity.MEDIUM,
                category=Category.SPF,
                title="L'enregistrement SPF comporte des anomalies de syntaxe",
                detail="; ".join(spf.syntax_errors[:5]),
                impact=(
                    "Selon l'anomalie, le terme fautif est ignoré ou l'évaluation "
                    "entière rend « permerror »."
                ),
                remediation="Corriger les termes signalés.",
                evidence=tuple(spf.syntax_errors),
            )
        )

    return out


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------


def _dkim_rules(report: DomainReport) -> list[Finding]:
    dkim = report.dkim
    out: list[Finding] = []

    if dkim.wildcard_record is not None:
        if dkim.wildcard_revokes_all:
            return [
                Finding(
                    code="DA-DKIM-007",
                    severity=Severity.INFO,
                    category=Category.DKIM,
                    title="Le domaine déclare explicitement ne publier aucune clé DKIM",
                    detail=(
                        f"« *._domainkey.{report.domain} » renvoie une clé vide, ce qui "
                        "révoque tout sélecteur."
                    ),
                    impact=(
                        "Déclaration volontaire et conforme, équivalente au « null MX » : "
                        "toute signature se réclamant de ce domaine est invalide, quel "
                        "que soit le sélecteur employé. C'est la configuration attendue "
                        "d'un domaine qui n'envoie pas de courrier."
                    ),
                    remediation=(
                        "Aucune action si le domaine n'émet pas. Retirer le joker avant "
                        "de mettre en service une signature DKIM."
                    ),
                    evidence=(dkim.wildcard_record,),
                    refs=("RFC 6376 §3.6.1",),
                )
            ]

        return [
            Finding(
                code="DA-DKIM-008",
                severity=Severity.MEDIUM,
                category=Category.DKIM,
                title="Un joker DKIM répond pour n'importe quel sélecteur",
                detail=(
                    f"« *._domainkey.{report.domain} » publie une clé active : tout nom "
                    "de sélecteur interrogé renvoie cette même clé."
                ),
                impact=(
                    "Quiconque détient la clé privée correspondante peut signer en "
                    "choisissant librement son sélecteur, ce qui rend impossible toute "
                    "révocation ciblée et tout suivi de l'origine des signatures. "
                    "L'inventaire des sélecteurs réellement utilisés devient par "
                    "ailleurs impraticable."
                ),
                remediation=(
                    "Remplacer le joker par des enregistrements nominatifs, un par "
                    "sélecteur effectivement en service."
                ),
                evidence=(dkim.wildcard_record,),
                refs=("RFC 6376 §3.6.1",),
            )
        ]

    if not dkim.keys:
        return [
            Finding(
                code="DA-DKIM-001",
                severity=Severity.MEDIUM,
                category=Category.DKIM,
                title="Aucune clé DKIM découverte",
                detail=(
                    f"{dkim.selectors_probed} sélecteurs courants ont été testés sans "
                    "résultat. Un sélecteur non conventionnel resterait indétectable "
                    "par sondage : seuls les rapports DMARC permettent de lever ce doute."
                ),
                impact=(
                    "Sans signature, vos messages ne survivent pas à une redirection : "
                    "SPF échoue au deuxième saut et DMARC n'a aucun second mécanisme sur "
                    "lequel se rabattre. Les messages légitimes redirigés sont rejetés."
                ),
                remediation=(
                    "Activer la signature DKIM chez votre hébergeur de messagerie et "
                    "publier la clé publique."
                ),
                refs=("RFC 6376",),
            )
        ]

    for key in dkim.keys:
        label = f"{key.selector}._domainkey.{report.domain}"

        if key.revoked:
            out.append(
                Finding(
                    code="DA-DKIM-003",
                    severity=Severity.MEDIUM,
                    category=Category.DKIM,
                    title=f"Clé DKIM révoquée sur le sélecteur « {key.selector} »",
                    detail=f"{label} publie une valeur « p= » vide.",
                    impact=(
                        "Toute signature référençant ce sélecteur est rejetée. Si le "
                        "sélecteur est encore utilisé à l'envoi, l'intégralité du "
                        "courrier signé échoue en DKIM."
                    ),
                    remediation=(
                        "Retirer l'enregistrement s'il n'est plus utilisé, ou republier "
                        "la clé publique s'il l'est encore."
                    ),
                    evidence=(key.raw,),
                    refs=("RFC 6376 §3.6.1",),
                )
            )
            continue

        if key.testing:
            out.append(
                Finding(
                    code="DA-DKIM-004",
                    severity=Severity.HIGH,
                    category=Category.DKIM,
                    title=f"Sélecteur « {key.selector} » en mode test (« t=y »)",
                    detail=f"{label} porte le drapeau de test.",
                    impact=(
                        "La RFC demande aux destinataires de traiter le message comme "
                        "s'il n'était pas signé. DKIM est donc publié, valide, et sans "
                        "aucun effet — un oubli fréquent après une phase de déploiement."
                    ),
                    remediation="Retirer « t=y » de l'enregistrement.",
                    evidence=(key.raw,),
                    refs=("RFC 6376 §3.6.1",),
                )
            )

        if not key.valid and key.parse_error:
            out.append(
                Finding(
                    code="DA-DKIM-005",
                    severity=Severity.MEDIUM,
                    category=Category.DKIM,
                    title=f"Clé DKIM illisible sur le sélecteur « {key.selector} »",
                    detail=f"{label} : {key.parse_error}.",
                    impact="Aucune signature ne peut être vérifiée avec ce sélecteur.",
                    remediation="Republier la clé publique à partir de la clé privée en service.",
                    evidence=(key.raw,),
                )
            )
        elif key.key_bits is not None and key.key_type == "rsa" and key.key_bits < MIN_SAFE_KEY_BITS:
            out.append(
                Finding(
                    code="DA-DKIM-002",
                    severity=Severity.MEDIUM if key.key_bits >= 1024 else Severity.HIGH,
                    category=Category.DKIM,
                    title=f"Clé DKIM de {key.key_bits} bits sur « {key.selector} »",
                    detail=f"{label} publie une clé RSA de {key.key_bits} bits.",
                    impact=(
                        "Une clé de cette taille n'offre plus la marge de sécurité "
                        "attendue. Sa factorisation permettrait de signer des messages "
                        "au nom du domaine, qui passeraient DKIM et DMARC."
                    ),
                    remediation=(
                        f"Générer une clé d'au moins {MIN_SAFE_KEY_BITS} bits et la "
                        "publier sur un nouveau sélecteur avant de retirer l'ancien."
                    ),
                    evidence=(key.raw[:120],),
                )
            )

    if dkim.external_signers:
        out.append(
            Finding(
                code="DA-DKIM-006",
                severity=Severity.MEDIUM,
                category=Category.DKIM,
                title="Des tiers peuvent signer en votre nom",
                detail="Signataires identifiés : " + ", ".join(dkim.external_signers) + ".",
                impact=(
                    "Ces services disposent d'une clé permettant de produire une "
                    "signature valide pour votre domaine. Une signature DKIM valide "
                    "suffit à faire passer DMARC, y compris si le SPF échoue."
                ),
                remediation=(
                    "Confirmer que chaque service est toujours en usage. Retirer le "
                    "sélecteur de tout prestataire dont le contrat a pris fin — la clé "
                    "reste sinon exploitable indéfiniment."
                ),
            )
        )

    return out


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------


def _dmarc_rules(report: DomainReport) -> list[Finding]:
    dmarc = report.dmarc
    out: list[Finding] = []

    # Signalés quelle que soit la suite : un enregistrement corrompu ou mal
    # placé coexiste souvent avec une politique valide, et les deux se
    # contredisent alors sans que personne ne s'en aperçoive.
    out.extend(_malformed_dmarc_findings(report))

    if not dmarc.present:
        if dmarc.malformed:
            # Le constat « rien de publié » serait faux et surtout trompeur :
            # l'auteur voit bien un enregistrement dans son interface.
            return out
        return [
            *out,
            Finding(
                code="DA-DMARC-001",
                severity=Severity.CRITICAL,
                category=Category.DMARC,
                title="Aucune politique DMARC publiée",
                detail=f"Aucun enregistrement TXT sur « _dmarc.{report.domain} ».",
                impact=(
                    "N'importe qui peut envoyer un message affichant votre domaine en "
                    "expéditeur, sans qu'aucune instruction ne soit donnée aux "
                    "destinataires. SPF et DKIM valident l'enveloppe et la signature, "
                    "jamais l'adresse que voit l'utilisateur. Vous ne recevez par "
                    "ailleurs aucun rapport, donc aucune visibilité sur les usurpations."
                ),
                remediation=(
                    "Publier « v=DMARC1; p=none; rua=mailto:dmarc@votre-domaine » pour "
                    "commencer à collecter des rapports, puis durcir vers « quarantine » "
                    "et « reject » une fois les flux légitimes identifiés."
                ),
                refs=("RFC 7489",),
            )
        ]

    if dmarc.multiple_records:
        out.append(
            Finding(
                code="DA-DMARC-002",
                severity=Severity.CRITICAL,
                category=Category.DMARC,
                title="Plusieurs enregistrements DMARC publiés",
                detail=f"{len(dmarc.all_records)} enregistrements « v=DMARC1 » coexistent.",
                impact=(
                    "La RFC impose aux destinataires de tous les ignorer : le domaine se "
                    "comporte exactement comme s'il n'avait aucune politique, tout en "
                    "paraissant protégé."
                ),
                remediation="Ne conserver qu'un seul enregistrement TXT sur « _dmarc ».",
                evidence=tuple(dmarc.all_records),
                refs=("RFC 7489 §6.6.3",),
            )
        )
        return out

    if dmarc.policy == "none":
        out.append(
            Finding(
                code="DA-DMARC-003",
                severity=Severity.HIGH,
                category=Category.DMARC,
                title="La politique DMARC est en observation seule (« p=none »)",
                detail="Le tag « p » vaut « none ».",
                impact=(
                    "Aucune action n'est demandée aux destinataires. Les messages "
                    "usurpant votre domaine sont délivrés normalement. La politique "
                    "sert uniquement à recevoir des rapports."
                ),
                remediation=(
                    "Exploiter les rapports pour recenser vos émetteurs légitimes, puis "
                    "passer à « p=quarantine » et enfin « p=reject »."
                ),
                evidence=(dmarc.raw or "",),
            )
        )
    elif dmarc.policy == "quarantine":
        out.append(
            Finding(
                code="DA-DMARC-010",
                severity=Severity.LOW,
                category=Category.DMARC,
                title="La politique DMARC est en quarantaine, pas en rejet",
                detail="Le tag « p » vaut « quarantine ».",
                impact=(
                    "Les messages usurpant le domaine sont classés en indésirables mais "
                    "restent accessibles au destinataire, qui peut les consulter."
                ),
                remediation="Passer à « p=reject » une fois les flux légitimes stabilisés.",
            )
        )

    if dmarc.percentage < 100:
        out.append(
            Finding(
                code="DA-DMARC-004",
                severity=Severity.MEDIUM,
                category=Category.DMARC,
                title=f"La politique ne s'applique qu'à {dmarc.percentage} % des messages",
                detail=f"Le tag « pct » vaut {dmarc.percentage}.",
                impact=(
                    f"{100 - dmarc.percentage} % des messages usurpant le domaine "
                    "échappent à la politique. Un attaquant n'a qu'à répéter ses envois "
                    "pour tomber dans cette proportion."
                ),
                remediation="Porter « pct » à 100 une fois la phase de déploiement terminée.",
            )
        )

    effective = dmarc.effective_subdomain_policy
    if dmarc.enforcing and effective == "none":
        out.append(
            Finding(
                code="DA-DMARC-005",
                severity=Severity.HIGH,
                category=Category.DMARC,
                title="Les sous-domaines sont exclus de la politique (« sp=none »)",
                detail=f"« p={dmarc.policy} » mais « sp=none ».",
                impact=(
                    "Le domaine principal est protégé, mais n'importe quel sous-domaine "
                    "— y compris inexistant, comme « facturation.votre-domaine » — reste "
                    "librement usurpable. Les destinataires y accordent la même "
                    "confiance qu'au domaine principal."
                ),
                remediation="Retirer « sp=none » ou l'aligner sur la politique principale.",
                evidence=(dmarc.raw or "",),
            )
        )

    if not dmarc.rua:
        out.append(
            Finding(
                code="DA-DMARC-006",
                severity=Severity.MEDIUM,
                category=Category.DMARC,
                title="Aucune destination de rapports agrégés (« rua »)",
                detail="Le tag « rua » est absent de l'enregistrement.",
                impact=(
                    "Vous ne recevez aucun rapport : ni la liste des serveurs qui "
                    "émettent en votre nom, ni la détection des usurpations. Durcir la "
                    "politique à l'aveugle risque de bloquer des flux légitimes."
                ),
                remediation="Ajouter « rua=mailto:dmarc@votre-domaine » à l'enregistrement.",
            )
        )

    for target in dmarc.rua + dmarc.ruf:
        if target.authorized is False:
            out.append(
                Finding(
                    code="DA-DMARC-007",
                    severity=Severity.HIGH,
                    category=Category.DMARC,
                    title=f"Destination de rapports non autorisée : {target.domain}",
                    detail=target.authorization_error or "",
                    impact=(
                        "Les serveurs conformes n'envoient aucun rapport vers cette "
                        "destination. Le symptôme est indiscernable d'une absence de "
                        "trafic : la configuration paraît correcte et aucun rapport "
                        "n'arrive jamais."
                    ),
                    remediation=(
                        f"Demander à {target.domain} de publier l'enregistrement TXT "
                        f"« {report.domain}._report._dmarc.{target.domain} » avec la "
                        "valeur « v=DMARC1 »."
                    ),
                    evidence=(target.uri,),
                    refs=("RFC 7489 §7.1",),
                )
            )

    if dmarc.inherited_from:
        out.append(
            Finding(
                code="DA-DMARC-009",
                severity=Severity.INFO,
                category=Category.DMARC,
                title="Politique DMARC héritée du domaine organisationnel",
                detail=(
                    f"Aucun enregistrement propre à {report.domain} ; la politique de "
                    f"{dmarc.inherited_from} s'applique."
                ),
                impact=(
                    "Comportement conforme à la norme. À noter : toute modification sur "
                    "le domaine parent s'appliquera immédiatement ici."
                ),
                remediation=(
                    "Publier une politique dédiée si ce sous-domaine doit être traité "
                    "différemment."
                ),
            )
        )

    if dmarc.syntax_errors:
        out.append(
            Finding(
                code="DA-DMARC-008",
                severity=Severity.MEDIUM,
                category=Category.DMARC,
                title="L'enregistrement DMARC comporte des anomalies",
                detail="; ".join(dmarc.syntax_errors[:5]),
                impact="Selon l'anomalie, un tag est ignoré ou la politique entière est invalide.",
                remediation="Corriger les tags signalés.",
                evidence=(dmarc.raw or "",),
            )
        )

    return out


def _malformed_dmarc_findings(report: DomainReport) -> list[Finding]:
    """Enregistrements DMARC publiés mais inopérants."""
    dmarc = report.dmarc
    out: list[Finding] = []

    for item in dmarc.malformed:
        out.append(
            Finding(
                code="DA-DMARC-011",
                severity=Severity.CRITICAL,
                category=Category.DMARC,
                title="Un enregistrement DMARC est publié mais illisible",
                detail=(
                    f"Sur « _dmarc.{report.domain} », {item.reason}. "
                    f"Cause probable : {item.likely_cause}."
                ),
                impact=(
                    "Aucun serveur de messagerie ne reconnaît cette valeur : le domaine "
                    "se comporte exactement comme s'il n'avait aucune politique DMARC. "
                    "C'est plus dangereux qu'une absence, car l'enregistrement est "
                    "visible dans l'interface de l'hébergeur et paraît donc actif."
                ),
                remediation=(
                    "Republier la valeur sans les caractères parasites : "
                    f"« {repaired_preview(item.value)} ». Si l'interface de l'hébergeur "
                    "ajoute elle-même les guillemets, ne pas les saisir."
                ),
                evidence=(item.value,),
                refs=("RFC 7489 §6.3",),
            )
        )

    for record in dmarc.misplaced_at_apex:
        out.append(
            Finding(
                code="DA-DMARC-012",
                severity=Severity.MEDIUM,
                category=Category.DMARC,
                title="Une politique DMARC est publiée au mauvais endroit",
                detail=(
                    f"Un enregistrement « v=DMARC1 » figure sur « {report.domain} » "
                    f"au lieu de « _dmarc.{report.domain} »."
                ),
                impact=(
                    "Les serveurs interrogent exclusivement le sous-domaine « _dmarc ». "
                    "Cette valeur n'est donc jamais consultée. Elle entretient en outre "
                    "la confusion : deux politiques différentes peuvent coexister sans "
                    "que la contradiction soit visible."
                ),
                remediation=(
                    f"Déplacer cet enregistrement vers « _dmarc.{report.domain} », ou le "
                    "supprimer s'il fait doublon avec une politique déjà en place."
                ),
                evidence=(record,),
                refs=("RFC 7489 §6.1",),
            )
        )

    return out


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


def _mx_rules(report: DomainReport) -> list[Finding]:
    mx = report.mx
    out: list[Finding] = []

    if mx.null_mx:
        return [
            Finding(
                code="DA-MX-007",
                severity=Severity.INFO,
                category=Category.MX,
                title="Le domaine déclare ne pas recevoir de courrier (« null MX »)",
                detail="Un enregistrement MX « 0 . » est publié.",
                impact=(
                    "Déclaration explicite et conforme. Les émetteurs sont informés "
                    "immédiatement plutôt qu'après expiration d'une file d'attente."
                ),
                remediation=(
                    "Vérifier qu'une politique DMARC en rejet accompagne cette "
                    "déclaration : un domaine sans messagerie ne doit jamais émettre."
                ),
                refs=("RFC 7505",),
            )
        ]

    if not mx.hosts:
        return [
            Finding(
                code="DA-MX-001",
                severity=Severity.MEDIUM,
                category=Category.MX,
                title="Aucun enregistrement MX",
                detail=f"Le domaine {report.domain} ne publie aucun MX.",
                impact=(
                    "Le domaine ne peut pas recevoir de courrier. Les émetteurs se "
                    "rabattront sur l'enregistrement A, comportement hérité et peu fiable."
                ),
                remediation=(
                    "Publier des MX, ou déclarer explicitement l'absence de messagerie "
                    "avec un « null MX » (« 0 . ») accompagné de « p=reject »."
                ),
            )
        ]

    unresolvable = [host for host in mx.hosts if not host.resolves]
    if unresolvable:
        out.append(
            Finding(
                code="DA-MX-003",
                severity=Severity.HIGH,
                category=Category.MX,
                title="Des hôtes MX ne résolvent vers aucune adresse",
                detail="Hôtes concernés : " + ", ".join(h.hostname for h in unresolvable) + ".",
                impact=(
                    "Le courrier destiné au domaine ne peut pas être remis via ces "
                    "hôtes. Selon leur préférence, une partie ou la totalité du flux "
                    "entrant est perdue."
                ),
                remediation="Corriger les enregistrements A/AAAA, ou retirer les MX obsolètes.",
                evidence=tuple(h.hostname for h in unresolvable),
            )
        )

    cnames = [host for host in mx.hosts if host.is_cname]
    if cnames:
        out.append(
            Finding(
                code="DA-MX-004",
                severity=Severity.LOW,
                category=Category.MX,
                title="Des MX pointent vers un alias CNAME",
                detail="Hôtes concernés : " + ", ".join(h.hostname for h in cnames) + ".",
                impact=(
                    "La RFC 2181 interdit cette construction. Certains serveurs "
                    "l'acceptent, d'autres refusent la remise : le comportement varie "
                    "selon l'émetteur."
                ),
                remediation="Faire pointer les MX vers un nom portant directement un A/AAAA.",
                refs=("RFC 2181 §10.3",),
            )
        )

    if len(mx.hosts) == 1:
        out.append(
            Finding(
                code="DA-MX-005",
                severity=Severity.LOW,
                category=Category.MX,
                title="Un seul hôte MX déclaré",
                detail=f"L'unique MX est {mx.hosts[0].hostname}.",
                impact=(
                    "Aucune redondance à la réception. Son indisponibilité provoque le "
                    "rejet ou la mise en attente de tout le courrier entrant."
                ),
                remediation="Déclarer au moins un MX secondaire de préférence supérieure.",
            )
        )

    if mx.inconsistent_with_spf:
        out.append(
            Finding(
                code="DA-MX-006",
                severity=Severity.MEDIUM,
                category=Category.MX,
                title="Incohérence entre les MX et le SPF",
                detail=(
                    "Services présents dans les MX mais absents du SPF : "
                    + ", ".join(mx.inconsistent_with_spf)
                    + "."
                ),
                impact=(
                    "Le courrier est reçu par un service que le SPF n'autorise pas à "
                    "émettre. C'est la signature d'une migration inachevée : deux "
                    "configurations coexistent et l'une des deux ne fonctionne plus."
                ),
                remediation=(
                    "Aligner le SPF sur les services réellement utilisés, et retirer "
                    "ceux qui ne servent plus."
                ),
            )
        )

    return out


# ---------------------------------------------------------------------------
# Hygiène
# ---------------------------------------------------------------------------


def _hygiene_rules(report: DomainReport) -> list[Finding]:
    out: list[Finding] = []
    caa = report.caa
    posture = report.posture

    if not caa.present:
        out.append(
            Finding(
                code="DA-HYG-001",
                severity=Severity.LOW,
                category=Category.HYGIENE,
                title="Aucun enregistrement CAA",
                detail=f"Ni {report.domain} ni ses parents ne publient de CAA.",
                impact=(
                    "N'importe quelle autorité de certification publique peut émettre "
                    "un certificat pour ce domaine. Un certificat frauduleux permet "
                    "d'usurper le site et les services de messagerie associés."
                ),
                remediation=(
                    "Publier un CAA restreignant l'émission à vos autorités, et ajouter "
                    "un tag « iodef » pour être averti des demandes refusées."
                ),
                refs=("RFC 8659",),
            )
        )
    elif not caa.has_iodef and not blocks_all_issuance(caa):
        out.append(
            Finding(
                code="DA-HYG-005",
                severity=Severity.INFO,
                category=Category.HYGIENE,
                title="Le CAA ne comporte pas de tag « iodef »",
                detail="Aucune adresse de notification n'est publiée.",
                impact=(
                    "Une tentative d'émission de certificat par une autorité non "
                    "autorisée est refusée, mais vous n'en êtes pas informé — alors "
                    "que c'est précisément le signal d'une attaque en préparation."
                ),
                remediation="Ajouter « 0 iodef \"mailto:securite@votre-domaine\" ».",
            )
        )

    if not posture.dnssec:
        out.append(
            Finding(
                code="DA-HYG-002",
                severity=Severity.LOW,
                category=Category.HYGIENE,
                title="La zone n'est pas signée par DNSSEC",
                detail="Le résolveur ne renvoie pas de réponse authentifiée pour ce domaine.",
                impact=(
                    "Les réponses DNS peuvent être falsifiées en transit. Tous les "
                    "enregistrements examinés dans ce rapport — SPF, DKIM, DMARC, MX — "
                    "reposent sur un socle non authentifié."
                ),
                remediation="Activer DNSSEC chez l'hébergeur DNS et publier le DS au registre.",
            )
        )

    if not posture.mta_sts:
        out.append(
            Finding(
                code="DA-HYG-003",
                severity=Severity.LOW,
                category=Category.HYGIENE,
                title="Aucune politique MTA-STS",
                detail=f"Aucun enregistrement sur « _mta-sts.{report.domain} ».",
                impact=(
                    "Le chiffrement du transport entrant n'est pas exigé. SMTP se "
                    "rabat silencieusement sur du texte clair si la négociation TLS "
                    "échoue, ce qu'un attaquant en interception peut provoquer."
                ),
                remediation=(
                    "Publier une politique MTA-STS et la servir sur "
                    f"« https://mta-sts.{report.domain}/.well-known/mta-sts.txt »."
                ),
                refs=("RFC 8461",),
            )
        )

    if not posture.tls_rpt:
        out.append(
            Finding(
                code="DA-HYG-004",
                severity=Severity.INFO,
                category=Category.HYGIENE,
                title="Aucun rapport TLS (« TLS-RPT »)",
                detail=f"Aucun enregistrement sur « _smtp._tls.{report.domain} ».",
                impact=(
                    "Les échecs de négociation TLS à la réception ne sont pas remontés. "
                    "Une interception active ne laisse aucune trace exploitable."
                ),
                remediation="Publier « v=TLSRPTv1; rua=mailto:tlsrpt@votre-domaine ».",
                refs=("RFC 8460",),
            )
        )

    age = report.registration.age_days
    if age is not None and age < _YOUNG_DOMAIN_DAYS:
        out.append(
            Finding(
                code="DA-HYG-006",
                severity=Severity.INFO,
                category=Category.HYGIENE,
                title=f"Domaine enregistré il y a {age} jours",
                detail=f"Date d'enregistrement : {report.registration.created}.",
                impact=(
                    "Information de contexte. Les infrastructures d'usurpation "
                    "s'appuient massivement sur des domaines récents, jetables ; "
                    "plusieurs filtres accordent d'ailleurs une confiance réduite aux "
                    "domaines de moins de trois mois."
                ),
                remediation="Aucune action si l'enregistrement est légitime.",
            )
        )

    return out
