import random
import threading
from typing import List, Optional, Set
from pathlib import Path

from aiohttp_socks import ProxyConnector


class ProxyPool:
    def __init__(self):
        self._proxies: List[str] = []
        self._dead: Set[str] = set()
        self._lock = threading.Lock()

    def load_file(self, path: str) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        raw = p.read_text(encoding="utf-8", errors="ignore")
        with self._lock:
            self._proxies = [
                line.strip() for line in raw.splitlines()
                if line.strip() and not line.startswith("#")
            ]
            random.shuffle(self._proxies)
            self._dead.clear()
        return len(self._proxies)

    @property
    def count(self) -> int:
        return len(self._proxies)

    @property
    def alive_count(self) -> int:
        return len(self._proxies) - len(self._dead)

    @property
    def dead_count(self) -> int:
        return len(self._dead)

    def random(self) -> Optional[str]:
        if not self._proxies:
            return None
        alive = [p for p in self._proxies if p not in self._dead]
        if not alive:
            # all dead — reset and retry
            self._dead.clear()
            alive = self._proxies
        return random.choice(alive)

    def mark_dead(self, proxy: str):
        self._dead.add(proxy)

    def mark_alive(self, proxy: str):
        self._dead.discard(proxy)

    def get_connector(self, rotate: bool = True) -> Optional[ProxyConnector]:
        proxy_url = self.random()
        if not proxy_url:
            return None
        return ProxyConnector.from_url(proxy_url, ssl=False)


proxy_pool = ProxyPool()
