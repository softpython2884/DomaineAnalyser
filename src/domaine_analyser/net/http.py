"""Client HTTP partagé (RDAP, Certificate Transparency, enrichissement).

Un client unique et réutilisé, pour trois raisons : le maintien des connexions
(RDAP enchaîne plusieurs appels vers le même hôte), un `User-Agent`
identifiable — courtoisie élémentaire envers des services publics gratuits
comme crt.sh —, et un comportement de reprise homogène.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx

from ..config import USER_AGENT, Settings

_RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3


class HttpClient:
    """Client HTTP synchrone avec reprise sur erreur transitoire."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.Client(
            timeout=httpx.Timeout(settings.http_timeout),
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )
        self._lock = threading.Lock()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get_json(self, url: str, *, accept: str = "application/json") -> Any | None:
        """Retourne le JSON, ou None si la ressource est absente ou illisible.

        Un 404 n'est pas une anomalie : en RDAP, il signifie simplement que
        l'objet n'est pas enregistré. Il ne déclenche donc aucune reprise.
        """
        response = self._request(url, accept=accept)
        if response is None or response.status_code != 200:
            return None
        try:
            return response.json()
        except ValueError:
            return None

    def get_text(self, url: str, *, accept: str = "text/plain") -> str | None:
        response = self._request(url, accept=accept)
        if response is None or response.status_code != 200:
            return None
        return response.text

    def _request(self, url: str, *, accept: str) -> httpx.Response | None:
        delay = 1.0
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                with self._lock:
                    response = self._client.get(url, headers={"Accept": accept})
            except httpx.HTTPError:
                if attempt == _MAX_ATTEMPTS:
                    return None
                time.sleep(delay)
                delay *= 2
                continue

            if response.status_code in _RETRY_STATUS and attempt < _MAX_ATTEMPTS:
                # Respecte Retry-After quand le service l'indique : crt.sh et
                # certains serveurs RDAP limitent activement le débit.
                retry_after = response.headers.get("Retry-After")
                wait = delay
                if retry_after and retry_after.isdigit():
                    wait = min(float(retry_after), 30.0)
                time.sleep(wait)
                delay *= 2
                continue

            return response

        return None
