"""
Real-time target health monitor — ping, HTTP latency, availability.
Runs alongside the attack to show how the target is doing.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Optional

import aiohttp


@dataclass
class TargetHealth:
    ping_ms: float = 0.0
    http_latency_ms: float = 0.0
    available: bool = True
    last_status: int = 0
    last_check: float = 0.0
    history: List[float] = field(default_factory=list)  # last N latencies
    avg_latency_ms: float = 0.0
    peak_latency_ms: float = 0.0
    downtime_start: float = 0.0
    total_downtime: float = 0.0
    checks_total: int = 0
    checks_failed: int = 0
    degraded: bool = False  # latency > 2x baseline


class TargetMonitor:
    def __init__(self):
        self.health = TargetHealth()
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._baseline: float = 0.0

    @property
    def is_running(self):
        return self._task is not None and not self._task.done()

    def start(self, host: str, port: int = 443):
        if self.is_running:
            self.stop_sync()
        self._stop.clear()
        self.health = TargetHealth()
        scheme = "https" if port in (443, 8443, 4443, 3443, 5443, 9443) else "http"
        url = f"{scheme}://{host}:{port}/"
        self._task = asyncio.create_task(self._loop(host, url))

    def stop_sync(self):
        self._stop.set()
        if self._task:
            self._task.cancel()

    async def _ping(self, host: str) -> float:
        """TCP connect as ping substitute (ICMP needs root + raw sockets)."""
        t0 = time.monotonic()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443), timeout=3,
            )
            elapsed = (time.monotonic() - t0) * 1000
            writer.close()
            await writer.wait_closed()
            return round(elapsed, 1)
        except Exception:
            return -1

    async def _http_probe(self, url: str) -> tuple:
        """Single HTTP probe, returns (status, latency_ms) or (0, -1) on failure."""
        t0 = time.monotonic()
        try:
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=False),
                timeout=aiohttp.ClientTimeout(total=5, connect=3),
            ) as s:
                async with s.get(url, headers={"User-Agent": "Mozilla/5.0 HealthCheck"}, ssl=False) as r:
                    elapsed = (time.monotonic() - t0) * 1000
                    return r.status, round(elapsed, 1)
        except Exception:
            return 0, -1

    async def _loop(self, host: str, url: str):
        # initial baseline (3 probes before attack impact)
        baselines = []
        for _ in range(3):
            _, lat = await self._http_probe(url)
            if lat > 0:
                baselines.append(lat)
            await asyncio.sleep(0.3)
        self._baseline = sum(baselines) / len(baselines) if baselines else 100.0

        while not self._stop.is_set():
            h = self.health
            h.checks_total += 1

            # TCP ping
            h.ping_ms = await self._ping(host)

            # HTTP probe
            status, latency = await self._http_probe(url)
            h.last_check = time.time()

            if latency > 0:
                h.http_latency_ms = latency
                h.last_status = status
                h.available = True
                h.history.append(latency)
                if len(h.history) > 30:
                    h.history.pop(0)
                h.avg_latency_ms = round(sum(h.history) / len(h.history), 1)
                h.peak_latency_ms = round(max(h.history), 1)
                h.degraded = h.avg_latency_ms > self._baseline * 2

                if h.downtime_start > 0:
                    h.total_downtime += time.time() - h.downtime_start
                    h.downtime_start = 0
            else:
                h.available = False
                h.checks_failed += 1
                h.http_latency_ms = -1
                if h.downtime_start == 0:
                    h.downtime_start = time.time()

            await asyncio.sleep(2)


monitor = TargetMonitor()
