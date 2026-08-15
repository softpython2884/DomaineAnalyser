"""Couche d'accès réseau : DNS, HTTP, RDAP, WHOIS.

Seule couche autorisée à faire des entrées/sorties. Les modules d'analyse ne
l'importent jamais directement : ils reçoivent des données déjà collectées, ce
qui les rend purs et testables hors ligne.
"""

from __future__ import annotations
