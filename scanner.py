"""
Port scanner — finds open ports on target, tests which ones serve HTTP.
"""

import asyncio
from typing import Dict, List, Tuple

import aiohttp


COMMON_PORTS = [
    80, 443, 8080, 8443, 8888, 3000, 3443,
    5000, 5443, 8000, 8001, 8008, 8081, 8082,
    8083, 8084, 8085, 8086, 8087, 8088, 8090,
    8181, 8444, 8880, 9000, 9090, 9443,
    2053, 2083, 2087, 2096, 4443, 10443,
    2222, 2086, 2095, 8880, 8843, 4433,
    18080, 18443, 28080, 38080, 48080,
]


async def tcp_check(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def http_check(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, int, float]:
    """Returns (reachable, status_code, response_time_ms)."""
    scheme = "https" if port in (443, 8443, 4443, 3443, 5443, 9443, 10443, 18443) else "http"
    url = f"{scheme}://{host}:{port}/"
    t0 = asyncio.get_event_loop().time()
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=timeout, connect=2),
        ) as session:
            async with session.get(url, headers={"User-Agent": "Mozilla/5.0"}, ssl=False) as resp:
                elapsed = (asyncio.get_event_loop().time() - t0) * 1000
                return True, resp.status, round(elapsed, 1)
    except Exception:
        # try opposite scheme
        scheme2 = "http" if scheme == "https" else "https"
        url2 = f"{scheme2}://{host}:{port}/"
        t0 = asyncio.get_event_loop().time()
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=timeout, connect=2),
            ) as session:
                async with session.get(url2, headers={"User-Agent": "Mozilla/5.0"}, ssl=False) as resp:
                    elapsed = (asyncio.get_event_loop().time() - t0) * 1000
                    return True, resp.status, round(elapsed, 1)
        except Exception:
            return False, 0, 0


async def scan_ports(host: str, ports: List[int] = None, concurrency: int = 50) -> List[Dict]:
    """Scan ports, return list of dicts with port info sorted by response time."""
    if ports is None:
        ports = COMMON_PORTS

    sem = asyncio.Semaphore(concurrency)
    results = []

    async def check(port):
        async with sem:
            tcp_open = await tcp_check(host, port)
            if not tcp_open:
                return
            http_ok, status, latency = await http_check(host, port)
            results.append({
                "port": port,
                "tcp_open": tcp_open,
                "http_ok": http_ok,
                "status": status,
                "latency_ms": latency,
                "scheme": "https" if port in (443, 8443, 4443, 3443, 5443, 9443, 10443, 18443) else "http",
            })

    tasks = [asyncio.create_task(check(p)) for p in ports]
    await asyncio.gather(*tasks)

    # HTTP-responsive ports first, sorted by latency
    results.sort(key=lambda r: (not r["http_ok"], r["latency_ms"]))
    return results
