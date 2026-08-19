"""
redis_client.py
----------------
Redis caching layer (ThreatLens AI blueprint, Section 9: "Use Redis for
low-latency access to recent alerts, active threats, current risk scores,
session state and dashboard caching").

Design choice: wraps redis-py behind a small class that FALLS BACK to a
simple in-memory dict if no Redis server is reachable. Why: this lets the
FastAPI app (and this project's tests) run and be evaluated on a machine
that doesn't have Redis running yet, without silently pretending caching
doesn't matter -- the interface is identical either way, so swapping in
real Redis later (via docker-compose, already provided) requires zero
code changes elsewhere in the app.
"""

import json
import os
import time
from typing import Any, Optional

try:
    import redis as redis_lib
    REDIS_LIB_AVAILABLE = True
except ImportError:
    REDIS_LIB_AVAILABLE = False


class _InMemoryFallbackCache:
    """
    Minimal drop-in replacement for the subset of redis-py's API this
    project uses, with the same TTL behavior. Used automatically when a
    real Redis server can't be reached, so development/testing never hard-
    depends on infrastructure being up.
    """

    def __init__(self):
        self._store: dict[str, tuple[Any, Optional[float]]] = {}

    def set(self, key: str, value: str, ex: Optional[int] = None):
        expires_at = time.time() + ex if ex else None
        self._store[key] = (value, expires_at)
        return True

    def get(self, key: str) -> Optional[str]:
        item = self._store.get(key)
        if item is None:
            return None
        value, expires_at = item
        if expires_at is not None and time.time() > expires_at:
            del self._store[key]
            return None
        return value

    def delete(self, key: str):
        self._store.pop(key, None)
        return True

    def ping(self):
        return True


class CacheClient:
    """
    Thin, JSON-aware wrapper used throughout the API layer:
        cache.set_json("threats:active", data, ttl_seconds=30)
        cache.get_json("threats:active")

    Connects to REDIS_URL (default localhost:6379, matching the
    docker-compose service) on first use; if the connection fails, silently
    switches to the in-memory fallback above and logs a one-time warning
    rather than crashing every request that touches the cache.
    """

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client = self._connect()

    def _connect(self):
        if REDIS_LIB_AVAILABLE:
            try:
                client = redis_lib.Redis.from_url(self.redis_url, decode_responses=True, socket_connect_timeout=1)
                client.ping()
                return client
            except Exception:
                print(f"[cache] Could not reach Redis at {self.redis_url} -- "
                      f"using in-memory fallback cache instead.")
        return _InMemoryFallbackCache()

    def set_json(self, key: str, value: Any, ttl_seconds: int = 60) -> None:
        self._client.set(key, json.dumps(value), ex=ttl_seconds)

    def get_json(self, key: str) -> Optional[Any]:
        raw = self._client.get(key)
        if raw is None:
            return None
        return json.loads(raw)

    def invalidate(self, key: str) -> None:
        self._client.delete(key)


# Module-level singleton — the same pattern FastAPI routes will `import` and reuse.
cache = CacheClient()
