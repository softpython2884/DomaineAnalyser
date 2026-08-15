"""Collecte des faits bruts.

Cette couche interroge le réseau et remplit les structures de `models`. Elle
n'émet aucun jugement : c'est le rôle de `analyze`. La séparation permet de
rejouer une analyse hors ligne à partir de données enregistrées.
"""

from __future__ import annotations
