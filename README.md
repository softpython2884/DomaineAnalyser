# DomaineAnalyser

Audit de sécurité email et forensic d'usurpation, en ligne de commande.

Analyse un domaine en profondeur (DNS, WHOIS/RDAP, SPF, DKIM, DMARC, CAA),
identifie les services tiers capables d'écrire en son nom, exploite les
rapports agrégés DMARC pour remonter jusqu'aux infrastructures qui l'usurpent,
et produit un rapport d'audit exploitable.

> **Portée.** L'outil est **passif** : il n'interroge que des sources publiques
> (DNS, RDAP, Certificate Transparency) et n'établit aucune connexion vers
> l'infrastructure analysée. Il est conçu pour auditer vos propres domaines et
> pour analyser les messages que vous recevez.

## Pourquoi

La plupart des vérificateurs en ligne répondent à « le SPF est-il présent ? ».
C'est rarement la bonne question. Celles qui comptent sont :

- **Un tiers peut-il envoyer un message affichant mon domaine en expéditeur ?**
  L'outil rend un verdict binaire explicite, pas seulement un score.
- **Combien d'adresses IP sont réellement autorisées à écrire en mon nom ?**
  Un SPF de trois lignes en autorise couramment plusieurs millions.
- **Mon SPF est-il seulement évaluable ?** Au-delà de dix résolutions DNS, il
  bascule en `permerror` et cesse silencieusement de protéger quoi que ce soit.
- **Quels tiers peuvent signer en mon nom ?** Un prestataire résilié laisse en
  général sa clé DKIM active.
- **Mes rapports DMARC arrivent-ils vraiment ?** S'ils partent vers un domaine
  externe non autorisé (RFC 7489 §7.1), ils sont jetés sans avertissement.

## Installation

```bash
git clone https://github.com/OWNER/DomaineAnalyser.git
cd DomaineAnalyser
```

Puis, selon la plateforme :

```bash
./install.sh
```

```bat
install.cmd
```

Le script crée un environnement virtuel, installe les dépendances, amorce le
cache de la Public Suffix List et vérifie l'installation. Il est idempotent :
le relancer ne casse rien.

Installation manuelle, si vous préférez :

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e .
```

Vérifiez ensuite l'état de l'environnement :

```bash
da doctor
```

## Utilisation

Audit complet d'un domaine :

```bash
da domain example.com
```

Écrire le rapport dans un fichier, au format JSON pour l'outillage :

```bash
da domain example.com --output rapport.md --json rapport.json
```

Sonder davantage de sélecteurs DKIM, ou des sélecteurs connus :

```bash
da domain example.com --deep --selector monselecteur
```

En intégration continue, `--fail-on` renvoie le code de sortie 2 dès qu'un
constat atteint la gravité indiquée :

```bash
da domain example.com --fail-on high
```

### Aperçu de la sortie

```
example.com — 34/100 (E)

USURPABLE : un tiers peut envoyer un message affichant example.com
en expéditeur et atteindre la boîte de réception.
  · DMARC en p=none : aucune action n'est demandée aux destinataires
  · Le SPF se termine par ~all, non contraignant sans DMARC

Constats : 2 critiques, 3 élevés, 4 moyens
```

## Ce qui est analysé

| Domaine | Points de contrôle |
| --- | --- |
| **DNS** | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, DS |
| **Enregistrement** | RDAP en priorité, WHOIS en repli, âge du domaine, bureau d'enregistrement, statuts, contact abuse |
| **SPF** | Syntaxe, enregistrements multiples, arbre `include` récursif, **comptage des 10 résolutions DNS**, résolutions à vide, qualificateur terminal, mécanisme `ptr`, **taille de l'espace IP autorisé**, pools mutualisés |
| **DKIM** | Sondage de sélecteurs par fournisseur, longueur et type de clé, clé révoquée, mode test, **signataires tiers** |
| **DMARC** | Politique et politique de sous-domaine, `pct`, alignement, enregistrements multiples, héritage organisationnel, **autorisation des destinations externes de rapport** |
| **MX** | Fournisseur, cohérence avec le SPF, null MX, MX en CNAME, hôtes non résolvables, point de défaillance unique |
| **Hygiène** | CAA, DNSSEC, MTA-STS, TLS-RPT, BIMI |

### Score

Sur 100, pondéré par domaine de contrôle : DMARC 30, SPF 25, DKIM 20,
transport 15, hygiène 10. DMARC pèse le plus lourd parce que c'est le seul
mécanisme qui protège l'adresse réellement visible par le destinataire.

Le score est **entièrement déterministe** : mêmes enregistrements DNS, même
score. Il ne dépend d'aucun service externe ni d'aucun modèle.

## Enrichissement optionnel

Une clé Google Gemini (`GEMINI_API_KEY`) active l'option `--ai`, qui recherche
du contexte public sur les infrastructures identifiées : réputation d'un
opérateur, campagnes signalées, identité d'une organisation.

Cet enrichissement est délibérément cloisonné :

- il ne reçoit que des faits déjà établis par le moteur, et ne collecte rien ;
- toute affirmation dépourvue d'URL source est écartée ;
- sa sortie occupe une section distincte, marquée comme non vérifiée ;
- **il ne peut ni créer, ni modifier, ni supprimer un constat, ni influencer le
  score.**

L'outil est pleinement fonctionnel sans clé d'API.

## Tests actifs d'usurpation

Au-delà de l'audit passif, l'outil peut **vérifier concrètement** si un domaine
est usurpable, en forgeant des messages et en observant ce que ton serveur de
réception en fait.

> **Sûr par construction.** Ces tests ne livrent qu'à **une** boîte : celle dont
> tu prouves le contrôle en y donnant un accès IMAP. Il est donc impossible de
> s'en servir pour envoyer du courrier forgé à un tiers. Chaque message porte un
> marqueur visible et un jeton unique. N'utilise ces tests que sur une
> infrastructure que tu possèdes ou pour laquelle tu as une autorisation.

Configuration (dans `.env`, voir `.env.example`) : accès IMAP à la boîte de
vérification et `DA_TEST_ACK=true`. Vérifie le tout :

```bash
da mail-doctor
```

Prévisualiser les messages sans rien envoyer :

```bash
da test-spoof exemple.com --dry-run
```

Lancer la campagne (forge l'expéditeur, livre à ta boîte, relit le verdict) :

```bash
da test-spoof exemple.com
```

L'outil rejoue plusieurs scénarios — usurpation directe, en-tête `From`
désaligné, sous-domaine, domaine sosie, nom d'affichage trompeur — puis pour
chacun indique s'il a été **rejeté**, **mis en quarantaine** ou **délivré en
boîte de réception**, avec le verdict SPF/DKIM/DMARC que le récepteur a calculé.

> **Port 25.** L'envoi direct au MX suppose le port 25 sortant ouvert, que
> beaucoup de FAI filtrent. Lance les tests depuis un serveur où il est ouvert,
> ou passe par un relais authentifié (`--mode relay`).

Sonder le transport d'un MX (STARTTLS, certificat, AUTH) **sans envoyer de mail** :

```bash
da probe-mx exemple.com
```

## Feuille de route

- [x] Audit de domaine, score et rapport
- [x] Tests actifs d'usurpation (envoi contrôlé + vérification IMAP), sonde MX
- [ ] Interface terminal (TUI)
- [ ] Ingestion des rapports agrégés DMARC (RUA) et base d'historique
- [ ] Pivot automatique : IP en échec d'alignement → profilage de l'émetteur
- [ ] Analyse de messages `.eml` : chaîne `Received`, re-vérification
      cryptographique DKIM, domaines sosies, indicateurs
- [ ] Enrichissement Gemini

## Développement

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy
```

Les tests s'exécutent hors ligne : la résolution DNS est remplacée par un
résolveur alimenté par des réponses enregistrées. Aucun test du jeu par défaut
n'accède au réseau.

## Licence

MIT. Voir [LICENSE](LICENSE).
