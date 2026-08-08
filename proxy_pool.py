import random
from typing import List, Optional
from pathlib import Path

from aiohttp_socks import ProxyConnector


class ProxyPool:
    def __init__(self):
        self._proxies: List[str] = []
        self._index: int = 0

    def load_file(self, path: str) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        raw = p.read_text(encoding="utf-8", errors="ignore")
        self._proxies = [
            line.strip() for line in raw.splitlines()
            if line.strip() and not line.startswith("#")
        ]
        random.shuffle(self._proxies)
        self._index = 0
        return len(self._proxies)

    @property
    def count(self) -> int:
        return len(self._proxies)

    def next(self) -> Optional[str]:
        if not self._proxies:
            return None
        proxy = self._proxies[self._index % len(self._proxies)]
        self._index += 1
        return proxy

    def random(self) -> Optional[str]:
        if not self._proxies:
            return None
        return random.choice(self._proxies)

    def get_connector(self, rotate: bool = True) -> Optional[ProxyConnector]:
        proxy_url = self.random() if rotate else self.next()
        if not proxy_url:
            return None
        return ProxyConnector.from_url(proxy_url)


proxy_pool = ProxyPool()
