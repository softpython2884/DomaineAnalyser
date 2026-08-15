# Audit de sécurité email — nationquest.fr

**Score : 73/100 (note C)** — Configuration perfectible : plusieurs contrôles manquent.

Analysé le 15/08/2026 à 15:09 UTC. Domaine organisationnel : `nationquest.fr`.

## Verdict

> ### ✅ Le domaine `nationquest.fr` est protégé contre l'usurpation directe
>
> Une politique DMARC en application demande aux destinataires de traiter les messages non alignés.

Éléments retenus :

- La politique DMARC « p=reject » demande aux destinataires de traiter les messages non alignés.

## Répartition du score

| Domaine de contrôle | Obtenu | Maximum |
| --- | ---: | ---: |
| SPF | 25 | 25 |
| DKIM | 20 | 20 |
| DMARC | 8 | 30 |
| Transport / MX | 14 | 15 |
| Hygiène DNS | 7 | 10 |
| **Total** | **73** | **100** |

_DMARC porte le poids le plus élevé : c'est le seul mécanisme qui protège l'adresse réellement affichée au destinataire. SPF et DKIM ne font que l'alimenter._

## Risques détectés

7 constats : 1 élevé, 1 moyen, 4 faible, 1 information.

### 🟠 Élevé

#### `DA-DMARC-007` Destination de rapports non autorisée : forgenet.fr&quot

**Constat.** « nationquest.fr._report._dmarc.forgenet.fr&quot » est absent : les serveurs conformes n'enverront aucun rapport vers forgenet.fr&quot

**Impact.** Les serveurs conformes n'envoient aucun rapport vers cette destination. Le symptôme est indiscernable d'une absence de trafic : la configuration paraît correcte et aucun rapport n'arrive jamais.

**Correction.** Demander à forgenet.fr&quot de publier l'enregistrement TXT « nationquest.fr._report._dmarc.forgenet.fr&quot » avec la valeur « v=DMARC1 ».

<details><summary>Relevé</summary>

```
mailto:contact@forgenet.fr&quot
```

</details>

_Référence : RFC 7489 §7.1._

### 🟡 Moyen

#### `DA-DMARC-012` Une politique DMARC est publiée au mauvais endroit

**Constat.** Un enregistrement « v=DMARC1 » figure sur « nationquest.fr » au lieu de « _dmarc.nationquest.fr ».

**Impact.** Les serveurs interrogent exclusivement le sous-domaine « _dmarc ». Cette valeur n'est donc jamais consultée. Elle entretient en outre la confusion : deux politiques différentes peuvent coexister sans que la contradiction soit visible.

**Correction.** Déplacer cet enregistrement vers « _dmarc.nationquest.fr », ou le supprimer s'il fait doublon avec une politique déjà en place.

<details><summary>Relevé</summary>

```
v=DMARC1; p=quarantine; rua=mailto:nightfury@nationquest.fr
```

</details>

_Référence : RFC 7489 §6.1._

### 🔵 Faible

#### `DA-HYG-001` Aucun enregistrement CAA

**Constat.** Ni nationquest.fr ni ses parents ne publient de CAA.

**Impact.** N'importe quelle autorité de certification publique peut émettre un certificat pour ce domaine. Un certificat frauduleux permet d'usurper le site et les services de messagerie associés.

**Correction.** Publier un CAA restreignant l'émission à vos autorités, et ajouter un tag « iodef » pour être averti des demandes refusées.

_Référence : RFC 8659._

#### `DA-HYG-002` La zone n'est pas signée par DNSSEC

**Constat.** Le résolveur ne renvoie pas de réponse authentifiée pour ce domaine.

**Impact.** Les réponses DNS peuvent être falsifiées en transit. Tous les enregistrements examinés dans ce rapport — SPF, DKIM, DMARC, MX — reposent sur un socle non authentifié.

**Correction.** Activer DNSSEC chez l'hébergeur DNS et publier le DS au registre.

#### `DA-HYG-003` Aucune politique MTA-STS

**Constat.** Aucun enregistrement sur « _mta-sts.nationquest.fr ».

**Impact.** Le chiffrement du transport entrant n'est pas exigé. SMTP se rabat silencieusement sur du texte clair si la négociation TLS échoue, ce qu'un attaquant en interception peut provoquer.

**Correction.** Publier une politique MTA-STS et la servir sur « https://mta-sts.nationquest.fr/.well-known/mta-sts.txt ».

_Référence : RFC 8461._

#### `DA-MX-005` Un seul hôte MX déclaré

**Constat.** L'unique MX est nationquest.fr.

**Impact.** Aucune redondance à la réception. Son indisponibilité provoque le rejet ou la mise en attente de tout le courrier entrant.

**Correction.** Déclarer au moins un MX secondaire de préférence supérieure.

### ⚪ Information

#### `DA-HYG-004` Aucun rapport TLS (« TLS-RPT »)

**Constat.** Aucun enregistrement sur « _smtp._tls.nationquest.fr ».

**Impact.** Les échecs de négociation TLS à la réception ne sont pas remontés. Une interception active ne laisse aucune trace exploitable.

**Correction.** Publier « v=TLSRPTv1; rua=mailto:tlsrpt@votre-domaine ».

_Référence : RFC 8460._


## Plan d'action

Par ordre de priorité décroissante.

| # | Priorité | Action | Réf. |
| ---: | --- | --- | --- |
| 1 | Élevé | Demander à forgenet.fr&quot de publier l'enregistrement TXT « nationquest.fr._report._dmarc.forgenet.fr&quot » avec la valeur « v=DMARC1 ». | `DA-DMARC-007` |
| 2 | Moyen | Déplacer cet enregistrement vers « _dmarc.nationquest.fr », ou le supprimer s'il fait doublon avec une politique déjà en place. | `DA-DMARC-012` |
| 3 | Faible | Publier un CAA restreignant l'émission à vos autorités, et ajouter un tag « iodef » pour être averti des demandes refusées. | `DA-HYG-001` |
| 4 | Faible | Activer DNSSEC chez l'hébergeur DNS et publier le DS au registre. | `DA-HYG-002` |
| 5 | Faible | Publier une politique MTA-STS et la servir sur « https://mta-sts.nationquest.fr/.well-known/mta-sts.txt ». | `DA-HYG-003` |
| 6 | Faible | Déclarer au moins un MX secondaire de préférence supérieure. | `DA-MX-005` |

## Authentification

### SPF

| Élément | Valeur |
| --- | --- |
| Enregistrement | `v=spf1 a mx ip4:185.207.226.9 ip4:109.238.10.182 -all` |
| Qualificateur terminal | `-all` |
| Résolutions DNS | 2 / 10 |
| Résolutions sans réponse | 0 / 2 |
| Espace IPv4 autorisé | 2 adresses |
| Espace IPv6 autorisé | aucune |

### DKIM

| Sélecteur | Type | Taille | État | Service |
| --- | --- | ---: | --- | --- |
| `default` | rsa | 2048 bits | active | — |

### DMARC

| Élément | Valeur |
| --- | --- |
| Enregistrement | `v=DMARC1; p=reject; rua=mailto:contact@forgenet.fr&quot;; fo=1` |
| Politique (`p`) | `reject` |
| Sous-domaines (`sp`) | `reject` _(héritée de `p`)_ |
| Application (`pct`) | 100 % |
| Alignement DKIM / SPF | `r` / `r` |

| Destination | Type | Externe | Autorisée |
| --- | --- | --- | --- |
| `mailto:contact@forgenet.fr&quot` | rua | oui | **non** |

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
| Google Workspace | mailbox | **oui** | jeton TXT google-site-verification |

_1 service(s) peuvent techniquement émettre en affichant ce domaine. Chacun constitue un chemin d'envoi légitime, donc un point de compromission possible : la fin d'un contrat ne révoque ni une clé DKIM ni un `include:` SPF._

## Enregistrement du domaine

| Élément | Valeur |
| --- | --- |
| Source | RDAP |
| Bureau d'enregistrement | OVH |
| Titulaire | Ano Nymous |
| Créé le | 01/06/2025 |
| Âge | 439 jours |
| Expire le | 01/06/2027 |
| Contact abuse | abuse@ovh.net |
| Statuts | `client transfer prohibited`, `client delete prohibited` |
| Serveurs de noms | `ns1.webstrator.com`, `ns2.webstrator.com` |

## Relevé DNS

| Type | Nom | TTL | Valeur |
| --- | --- | ---: | --- |
| A | `nationquest.fr` | 60 | `185.207.226.9` |
| AAAA | `nationquest.fr` | — | _absent_ |
| MX | `nationquest.fr` | 60 | `1 nationquest.fr` |
| NS | `nationquest.fr` | 60 | `ns1.webstrator.com` |
|  |  |  | `ns2.webstrator.com` |
| TXT | `nationquest.fr` | 60 | `v=DMARC1; p=quarantine; rua=mailto:nightfury@nationquest.fr` |
|  |  |  | `google-site-verification=zYwoHfzR6vQnNplm4OlfsBPYayhSFCRM2c1gkpEY-SQ` |
|  |  |  | `v=spf1 a mx ip4:185.207.226.9 ip4:109.238.10.182 -all` |
| CNAME | `nationquest.fr` | — | _absent_ |
| SOA | `nationquest.fr` | 60 | `ns1.webstrator.com tech.octogency.com 2026081503 3600 1800 1209600 3600` |
| CAA | `nationquest.fr` | — | _absent_ |
| DS | `nationquest.fr` | — | _absent_ |
| DMARC | `_dmarc.nationquest.fr` | 60 | `v=DMARC1; p=reject; rua=mailto:contact@forgenet.fr&quot;; fo=1` |
| MTA_STS | `_mta-sts.nationquest.fr` | — | _absent_ |
| TLS_RPT | `_smtp._tls.nationquest.fr` | — | _absent_ |
| BIMI | `default._bimi.nationquest.fr` | — | _absent_ |

---

_Rapport produit par DomaineAnalyser. Collecte strictement passive : DNS, RDAP et WHOIS publics uniquement, sans aucune connexion vers l'infrastructure analysée._
