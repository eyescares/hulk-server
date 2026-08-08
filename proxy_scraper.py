#!/usr/bin/env python3

"""
Auto-scrape free proxies from public APIs.
Saves working proxies to a file for the attack engine.
"""

import asyncio
import time
from typing import List, Set

import aiohttp

PROXY_SOURCES = [
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=5000&country=all&ssl=all&anonymity=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
]

PROTOCOL_HINTS = {
    "socks5": "socks5://",
    "socks4": "socks4://",
    "http": "http://",
}


def _guess_protocol(source_url: str) -> str:
    url_lower = source_url.lower()
    if "socks5" in url_lower:
        return "socks5://"
    if "socks4" in url_lower:
        return "socks4://"
    return "http://"


async def _fetch_source(session: aiohttp.ClientSession, url: str) -> List[str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                return []
            text = await resp.text()
            prefix = _guess_protocol(url)
            proxies = []
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    continue
                if line.startswith(("http://", "https://", "socks4://", "socks5://")):
                    proxies.append(line)
                else:
                    proxies.append(prefix + line)
            return proxies
    except Exception:
        return []


async def _check_proxy(proxy: str, test_url: str = "http://httpbin.org/ip", timeout: int = 8) -> bool:
    try:
        from aiohttp_socks import ProxyConnector
        connector = ProxyConnector.from_url(proxy)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                return resp.status == 200
    except Exception:
        return False


async def scrape_proxies(check: bool = False, max_check: int = 300) -> List[str]:
    all_proxies: Set[str] = set()

    async with aiohttp.ClientSession() as session:
        tasks = [_fetch_source(session, url) for url in PROXY_SOURCES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            all_proxies.update(result)

    proxies = list(all_proxies)

    if not check or not proxies:
        return proxies

    # проверяем подвыборку
    subset = proxies[:max_check]
    check_tasks = [_check_proxy(p) for p in subset]
    results = await asyncio.gather(*check_tasks)
    working = [p for p, ok in zip(subset, results) if ok]

    unchecked = proxies[max_check:]
    return working + unchecked


def save_proxies(proxies: List[str], path: str = "proxies.txt") -> int:
    with open(path, "w", encoding="utf-8") as f:
        for p in proxies:
            f.write(p + "\n")
    return len(proxies)


async def auto_scrape_and_save(path: str = "proxies.txt", check: bool = False) -> int:
    proxies = await scrape_proxies(check=check)
    return save_proxies(proxies, path)


if __name__ == "__main__":
    import sys
    out = "proxies.txt"
    do_check = "--check" in sys.argv
    count = asyncio.run(auto_scrape_and_save(out, check=do_check))
    print(f"Saved {count} proxies to {out}")
