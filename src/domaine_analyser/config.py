"""Configuration de l'outil.

Ordre de priorité, du plus fort au plus faible : arguments de la ligne de
commande, variables d'environnement, fichier `.env` du répertoire courant,
puis valeurs par défaut. Aucune valeur n'est requise : l'outil doit fonctionner
sur une machine vierge, sans fichier de configuration ni clé d'API.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from platformdirs import user_cache_dir, user_data_dir

APP_NAME = "domaine-analyser"

#: Résolveurs publics utilisés par défaut. Fixer les résolveurs plutôt que
#: d'utiliser ceux du système rend un audit reproductible d'une machine à
#: l'autre, ce qui compte quand le rapport sert de pièce justificative.
DEFAULT_RESOLVERS = ("1.1.1.1", "8.8.8.8")

#: Résolveurs DNS-over-HTTPS, utilisés lorsque le port 53 sortant est filtré.
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
)

USER_AGENT = "DomaineAnalyser/0.1 (+https://github.com/OWNER/DomaineAnalyser)"


def _env_str(key: str, default: str = "") -> str:
    return (os.environ.get(key) or "").strip() or default


def _env_float(key: str, default: float) -> float:
    raw = _env_str(key)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = _env_str(key).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on", "oui")


def _env_list(key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = _env_str(key)
    if not raw:
        return default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(slots=True)
class Settings:
    """Réglages effectifs de l'exécution en cours."""

    resolvers: tuple[str, ...] = DEFAULT_RESOLVERS
    dns_timeout: float = 5.0
    dns_lifetime: float = 10.0
    doh_enabled: bool = True
    http_timeout: float = 15.0
    max_concurrency: int = 16
    db_path: Path = field(default_factory=Path)
    cache_dir: Path = field(default_factory=Path)
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"

    @property
    def ai_available(self) -> bool:
        return bool(self.gemini_api_key)

    def with_overrides(
        self,
        *,
        resolvers: tuple[str, ...] | None = None,
        dns_timeout: float | None = None,
        http_timeout: float | None = None,
    ) -> Settings:
        """Retourne une copie surchargée par les options de la ligne de commande."""
        return Settings(
            resolvers=resolvers or self.resolvers,
            dns_timeout=dns_timeout or self.dns_timeout,
            dns_lifetime=self.dns_lifetime,
            doh_enabled=self.doh_enabled,
            http_timeout=http_timeout or self.http_timeout,
            max_concurrency=self.max_concurrency,
            db_path=self.db_path,
            cache_dir=self.cache_dir,
            gemini_api_key=self.gemini_api_key,
            gemini_model=self.gemini_model,
        )


@lru_cache(maxsize=1)
def load_settings() -> Settings:
    """Charge la configuration une seule fois par processus."""
    # `override=False` : une variable déjà présente dans l'environnement prime
    # sur le fichier .env, ce qui permet de surcharger ponctuellement un run.
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)

    cache_dir = Path(user_cache_dir(APP_NAME, appauthor=False))

    db_raw = _env_str("DA_DB_PATH")
    db_path = (
        Path(db_raw).expanduser()
        if db_raw
        else Path(user_data_dir(APP_NAME, appauthor=False)) / "dmarc.sqlite"
    )

    return Settings(
        resolvers=_env_list("DA_DNS_RESOLVERS", DEFAULT_RESOLVERS),
        dns_timeout=_env_float("DA_DNS_TIMEOUT", 5.0),
        dns_lifetime=_env_float("DA_DNS_LIFETIME", 10.0),
        doh_enabled=_env_bool("DA_DOH_ENABLED", True),
        http_timeout=_env_float("DA_HTTP_TIMEOUT", 15.0),
        max_concurrency=int(_env_float("DA_MAX_CONCURRENCY", 16)),
        db_path=db_path,
        cache_dir=cache_dir,
        gemini_api_key=_env_str("GEMINI_API_KEY"),
        gemini_model=_env_str("DA_GEMINI_MODEL", "gemini-2.5-flash"),
    )
