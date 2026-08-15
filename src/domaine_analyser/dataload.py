"""Chargement des fichiers de données embarqués.

Passe par `importlib.resources` plutôt que par des chemins relatifs : c'est la
seule façon fiable de lire ces fichiers aussi bien depuis les sources que
depuis un paquet installé ou une archive zip.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Any

import yaml


@lru_cache(maxsize=8)
def load_data_file(name: str) -> dict[str, Any]:
    """Charge et met en cache un fichier YAML de `domaine_analyser.data`."""
    handle = resources.files("domaine_analyser.data").joinpath(name)
    payload = yaml.safe_load(handle.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{name} : le contenu attendu est un dictionnaire YAML")
    return payload


def load_providers() -> list[dict[str, Any]]:
    """Retourne la base de reconnaissance des services tiers."""
    entries = load_data_file("providers.yaml").get("providers", [])
    return [entry for entry in entries if isinstance(entry, dict) and entry.get("name")]


def load_selectors() -> dict[str, Any]:
    """Retourne le dictionnaire de sélecteurs DKIM."""
    return load_data_file("dkim_selectors.yaml")
