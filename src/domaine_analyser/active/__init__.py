"""Tests actifs de sécurité email.

Contrairement au reste de l'outil, strictement passif, ce sous-système émet
réellement des messages. Il le fait sous une contrainte non négociable, câblée
dans `safety` et vérifiée à chaque campagne :

    L'outil ne livre qu'à une boîte dont le contrôle est PROUVÉ par une
    connexion IMAP réussie à cette même boîte.

Conséquence directe : on ne peut pas s'en servir pour envoyer du courrier forgé
vers un tiers, puisqu'il faudrait pouvoir lire sa boîte. C'est un dispositif
d'auto-test d'usurpation — on forge un expéditeur, on se l'envoie à soi-même, et
on observe ce que le serveur récepteur en fait (accepté, quarantaine, rejeté) et
le verdict SPF/DKIM/DMARC qu'il a calculé.
"""

from __future__ import annotations
