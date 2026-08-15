"""Analyse des faits collectés.

Les modules de cette couche ne connaissent ni `httpx`, ni `dnspython`. Lorsque
l'analyse a besoin de résoudre un nom — c'est le cas de SPF, dont l'arbre
`include:` n'est connaissable qu'en interrogeant le DNS — elle reçoit un objet
conforme au protocole `lookup.DnsLookup`. En production c'est le résolveur
réel, dans les tests un dictionnaire figé. Le comportement est donc
reproductible et vérifiable hors ligne.
"""

from __future__ import annotations
