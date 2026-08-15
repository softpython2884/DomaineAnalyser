# Audit de sécurité email — solutions-corp.org

**Score : 74/100 (note C)** — Configuration perfectible : plusieurs contrôles manquent.

Analysé le 15/08/2026 à 15:06 UTC. Domaine organisationnel : `solutions-corp.org`.

## Verdict

> ### ⚠️ Le domaine `solutions-corp.org` est usurpable
>
> Un tiers peut envoyer un message affichant ce domaine en expéditeur et atteindre la boîte de réception du destinataire.
>
> **Les sous-domaines restent usurpables.** Un message émis depuis `facturation.solutions-corp.org`, nom qui n'a même pas besoin d'exister, ne se heurte à aucune politique.

Éléments retenus :

- La politique DMARC est en « p=none » : aucune action n'est demandée aux destinataires, les messages usurpés sont délivrés normalement.

## Répartition du score

| Domaine de contrôle | Obtenu | Maximum |
| --- | ---: | ---: |
| SPF | 25 | 25 |
| DKIM | 20 | 20 |
| DMARC | 8 | 30 |
| Transport / MX | 15 | 15 |
| Hygiène DNS | 7 | 10 |
| **Total** | **74** | **100** |

_DMARC porte le poids le plus élevé : c'est le seul mécanisme qui protège l'adresse réellement affichée au destinataire. SPF et DKIM ne font que l'alimenter._

## Risques détectés

7 constats : 1 élevé, 1 moyen, 3 faible, 2 information.

### 🟠 Élevé

#### `DA-DMARC-003` La politique DMARC est en observation seule (« p=none »)

**Constat.** Le tag « p » vaut « none ».

**Impact.** Aucune action n'est demandée aux destinataires. Les messages usurpant votre domaine sont délivrés normalement. La politique sert uniquement à recevoir des rapports.

**Correction.** Exploiter les rapports pour recenser vos émetteurs légitimes, puis passer à « p=quarantine » et enfin « p=reject ».

<details><summary>Relevé</summary>

```
v=DMARC1; p=none;
```

</details>

### 🟡 Moyen

#### `DA-DMARC-006` Aucune destination de rapports agrégés (« rua »)

**Constat.** Le tag « rua » est absent de l'enregistrement.

**Impact.** Vous ne recevez aucun rapport : ni la liste des serveurs qui émettent en votre nom, ni la détection des usurpations. Durcir la politique à l'aveugle risque de bloquer des flux légitimes.

**Correction.** Ajouter « rua=mailto:dmarc@votre-domaine » à l'enregistrement.

### 🔵 Faible

#### `DA-HYG-001` Aucun enregistrement CAA

**Constat.** Ni solutions-corp.org ni ses parents ne publient de CAA.

**Impact.** N'importe quelle autorité de certification publique peut émettre un certificat pour ce domaine. Un certificat frauduleux permet d'usurper le site et les services de messagerie associés.

**Correction.** Publier un CAA restreignant l'émission à vos autorités, et ajouter un tag « iodef » pour être averti des demandes refusées.

_Référence : RFC 8659._

#### `DA-HYG-002` La zone n'est pas signée par DNSSEC

**Constat.** Le résolveur ne renvoie pas de réponse authentifiée pour ce domaine.

**Impact.** Les réponses DNS peuvent être falsifiées en transit. Tous les enregistrements examinés dans ce rapport — SPF, DKIM, DMARC, MX — reposent sur un socle non authentifié.

**Correction.** Activer DNSSEC chez l'hébergeur DNS et publier le DS au registre.

#### `DA-HYG-003` Aucune politique MTA-STS

**Constat.** Aucun enregistrement sur « _mta-sts.solutions-corp.org ».

**Impact.** Le chiffrement du transport entrant n'est pas exigé. SMTP se rabat silencieusement sur du texte clair si la négociation TLS échoue, ce qu'un attaquant en interception peut provoquer.

**Correction.** Publier une politique MTA-STS et la servir sur « https://mta-sts.solutions-corp.org/.well-known/mta-sts.txt ».

_Référence : RFC 8461._

### ⚪ Information

#### `DA-HYG-004` Aucun rapport TLS (« TLS-RPT »)

**Constat.** Aucun enregistrement sur « _smtp._tls.solutions-corp.org ».

**Impact.** Les échecs de négociation TLS à la réception ne sont pas remontés. Une interception active ne laisse aucune trace exploitable.

**Correction.** Publier « v=TLSRPTv1; rua=mailto:tlsrpt@votre-domaine ».

_Référence : RFC 8460._

#### `DA-HYG-006` Domaine enregistré il y a 86 jours

**Constat.** Date d'enregistrement : 2026-05-20 18:50:50.452000+00:00.

**Impact.** Information de contexte. Les infrastructures d'usurpation s'appuient massivement sur des domaines récents, jetables ; plusieurs filtres accordent d'ailleurs une confiance réduite aux domaines de moins de trois mois.

**Correction.** Aucune action si l'enregistrement est légitime.


## Plan d'action

Par ordre de priorité décroissante.

| # | Priorité | Action | Réf. |
| ---: | --- | --- | --- |
| 1 | Élevé | Exploiter les rapports pour recenser vos émetteurs légitimes, puis passer à « p=quarantine » et enfin « p=reject ». | `DA-DMARC-003` |
| 2 | Moyen | Ajouter « rua=mailto:dmarc@votre-domaine » à l'enregistrement. | `DA-DMARC-006` |
| 3 | Faible | Publier un CAA restreignant l'émission à vos autorités, et ajouter un tag « iodef » pour être averti des demandes refusées. | `DA-HYG-001` |
| 4 | Faible | Activer DNSSEC chez l'hébergeur DNS et publier le DS au registre. | `DA-HYG-002` |
| 5 | Faible | Publier une politique MTA-STS et la servir sur « https://mta-sts.solutions-corp.org/.well-known/mta-sts.txt ». | `DA-HYG-003` |

## Authentification

### SPF

| Élément | Valeur |
| --- | --- |
| Enregistrement | `v=spf1 include:_spf.mx.cloudflare.net ~all` |
| Qualificateur terminal | `~all` |
| Résolutions DNS | 1 / 10 |
| Résolutions sans réponse | 0 / 2 |
| Espace IPv4 autorisé | 8 192 adresses |
| Espace IPv6 autorisé | 1.24e+27 adresses |
| Inclusions résolues | `_spf.mx.cloudflare.net` |

### DKIM

| Sélecteur | Type | Taille | État | Service |
| --- | --- | ---: | --- | --- |
| `cf2024-1` | rsa | 2048 bits | active | Cloudflare Email |

### DMARC

| Élément | Valeur |
| --- | --- |
| Enregistrement | `v=DMARC1; p=none;` |
| Politique (`p`) | `none` |
| Sous-domaines (`sp`) | `none` _(héritée de `p`)_ |
| Application (`pct`) | 100 % |
| Alignement DKIM / SPF | `r` / `r` |

### Durcissement

| Mécanisme | État |
| --- | --- |
| DNSSEC | **absent** |
| MTA-STS | **absent** |
| TLS-RPT | **absent** |
| BIMI | **absent** |
| CAA | **absent** |

## Services identifiés

| Service | Type | Peut émettre au nom du domaine | Signaux |
| --- | --- | :---: | --- |
| Cloudflare Email | esp | **oui** | MX route2.mx.cloudflare.net, SPF include:_spf.mx.cloudflare.net, sélecteur DKIM cf2024-1 |

_1 service(s) peuvent techniquement émettre en affichant ce domaine. Chacun constitue un chemin d'envoi légitime, donc un point de compromission possible : la fin d'un contrat ne révoque ni une clé DKIM ni un `include:` SPF._

## Enregistrement du domaine

| Élément | Valeur |
| --- | --- |
| Source | RDAP |
| Bureau d'enregistrement | Cloudflare, Inc. |
| Créé le | 20/05/2026 |
| Âge | 86 jours |
| Expire le | 20/05/2027 |
| Contact abuse | registry-abuse@cloudflare.com |
| Statuts | `client transfer prohibited` |
| Serveurs de noms | `duke.ns.cloudflare.com`, `fiona.ns.cloudflare.com` |

## Relevé DNS

| Type | Nom | TTL | Valeur |
| --- | --- | ---: | --- |
| A | `solutions-corp.org` | — | _absent_ |
| AAAA | `solutions-corp.org` | — | _absent_ |
| MX | `solutions-corp.org` | 300 | `13 route2.mx.cloudflare.net` |
|  |  |  | `40 route3.mx.cloudflare.net` |
|  |  |  | `97 route1.mx.cloudflare.net` |
| NS | `solutions-corp.org` | 86400 | `duke.ns.cloudflare.com` |
|  |  |  | `fiona.ns.cloudflare.com` |
| TXT | `solutions-corp.org` | 300 | `v=spf1 include:_spf.mx.cloudflare.net ~all` |
| CNAME | `solutions-corp.org` | — | _absent_ |
| SOA | `solutions-corp.org` | 1800 | `duke.ns.cloudflare.com dns.cloudflare.com 2409893682 10000 2400 604800 1800` |
| CAA | `solutions-corp.org` | — | _absent_ |
| DS | `solutions-corp.org` | — | _absent_ |
| DMARC | `_dmarc.solutions-corp.org` | 300 | `v=DMARC1; p=none;` |
| MTA_STS | `_mta-sts.solutions-corp.org` | — | _absent_ |
| TLS_RPT | `_smtp._tls.solutions-corp.org` | — | _absent_ |
| BIMI | `default._bimi.solutions-corp.org` | — | _absent_ |

---

_Rapport produit par DomaineAnalyser. Collecte strictement passive : DNS, RDAP et WHOIS publics uniquement, sans aucune connexion vers l'infrastructure analysée._
