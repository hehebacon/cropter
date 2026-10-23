"""Interactive terminal UI for CROPTer; standard-library only."""

from __future__ import annotations

import os
import platform
import sys
import time
import traceback
from pathlib import Path
from urllib.parse import urlsplit

from cropter import __version__
from cropter.scope import Scope, load_scope
from cropter.scanner import scan_url

RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
MAGENTA = "\033[95m"
DIM = "\033[2m"
BOLD = "\033[1m"
DELAY = 0.0001


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def pause() -> None:
    try:
        input(f"\n{DIM}Press Enter to return to menu...{RESET}")
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt


def banner() -> None:
    print(f"""{CYAN}{BOLD}
   ____ ____   ___  ____ _____ _____ ____
  / ___|  _ \\ / _ \\|  _ \\_   _| ____|  _ \\
 | |   | |_) | | | | |_) || | |  _| | |_) |
 | |___|  _ <| |_| |  __/ | | | |___|  _ <
  \\____|_| \\_\\___/|_|    |_| |_____|_| \\_\\
{RESET}{MAGENTA}       authorized security research console{RESET}
{DIM}       CROPTer {__version__}  |  {platform.system()} {platform.release()}{RESET}
""")


def boot_animation() -> None:
    clear()
    banner()
    print(f"{CYAN}[BOOT]{RESET} Initializing local interface", end="", flush=True)
    for _ in range(18):
        print(f"{CYAN}.{RESET}", end="", flush=True)
        time.sleep(DELAY)
    print(f" {GREEN}OK{RESET}")
    print(f"{CYAN}[MODE]{RESET} Offline-first / explicit-scope checks")
    print(f"{CYAN}[NET ]{RESET} No network scan is started by this interface")
    time.sleep(0.08)


def heading(title: str) -> None:
    clear()
    banner()
    print(f"{BOLD}{title}{RESET}")
    print("─" * 58)


def read_required(prompt: str) -> str:
    while True:
        value = input(f"{CYAN}{prompt}{RESET} ").strip()
        if value:
            return value
        print(f"{RED}Input cannot be empty.{RESET}")


def scope_check() -> None:
    heading("SCOPE CHECK")
    print("Checks a URL against a local allow/deny file. It sends no request.")
    scope_path = input(f"Scope file [scope.example.txt]: ").strip() or "scope.example.txt"
    url = read_required("URL to check:")
    print(f"\n{DIM}No network request will be made.{RESET}")
    if input("Run check? [Y/n]: ").strip().lower() not in {"", "y", "yes"}:
        print("Cancelled.")
        return
    scope = load_scope(scope_path)
    allowed = scope.allows_url(url)
    print("\n" + "─" * 58)
    print(f"URL: {url}")
    print(f"IN SCOPE: {GREEN if allowed else RED}{str(allowed).upper()}{RESET}")
    if not allowed:
        print("Do not test this URL unless you have verified authorization and scope.")
    print("─" * 58)


def scope_show() -> None:
    heading("SCOPE CONFIGURATION")
    path = input("Scope file [scope.example.txt]: ").strip() or "scope.example.txt"
    scope = load_scope(path)
    print(f"\n{GREEN}ALLOW LIST{RESET}")
    for host in scope.allowed_hosts:
        print(f"  + {host}")
    print(f"\n{RED}DENY LIST{RESET}")
    for host in scope.denied_hosts:
        print(f"  - {host}")
    print(f"\nLoaded from: {Path(path).resolve()}")


def scan_target() -> None:
    heading("AUTO-SCOPE PASSIVE WEB REVIEW")
    print("Enter one URL; CROPTer derives a narrow scope automatically.")
    print("Low-impact same-origin review: ordinary GET requests only.")
    print("No subdomain enumeration, form submission, brute force, or exploit payloads.")
    url = read_required("Target URL (https://example.com):")
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not accepted.")
    host = parsed.hostname.rstrip(".").lower()
    scope = Scope((host,))
    print(f"\nTarget: {url}")
    print(f"Auto-scope host: {host}")
    print("CROPTer will review only this origin, up to 15 pages. It will not discover or scan other hosts.")
    confirmation = input("I confirm I own this target or have permission to test it. Start? [y/N]: ").strip().lower()
    if confirmation not in {"y", "yes"}:
        print("Cancelled; no requests sent.")
        return
    report_path = input("Report path [cropter-report.json]: ").strip() or "cropter-report.json"
    print(f"\n{CYAN}[SCAN]{RESET} Reviewing the auto-scoped origin...")
    report = scan_url(url, scope, report_path)
    print(f"{GREEN}[DONE]{RESET} Checked {report['page_count']} page(s).")
    print(f"Findings: {len(report['findings'])}")
    print(f"Report: {Path(report_path).resolve()}")
    for item in report["findings"][:12]:
        color = RED if item["severity"] in {"high", "critical"} else MAGENTA
        print(f"  {color}[{item['severity'].upper()}]{RESET} {item['title']}")
    if not report["findings"]:
        print("No findings from these limited checks. This does not mean the site is secure.")

def diagnostics() -> None:
    heading("SYSTEM DIAGNOSTICS")
    print(f"Python:      {sys.version.split()[0]}")
    print(f"Executable:  {sys.executable}")
    print(f"Platform:    {platform.platform()}")
    print(f"Project dir: {Path.cwd()}")
    print(f"Virtual env: {GREEN if sys.prefix != getattr(sys, 'base_prefix', sys.prefix) else RED}"
          f"{'active' if sys.prefix != getattr(sys, 'base_prefix', sys.prefix) else 'not active'}{RESET}")
    print("Network mode: low-impact passive review; URL-derived same-origin scope")


def main() -> int:
    try:
        boot_animation()
        while True:
            print(f"""
{CYAN}{BOLD}┌─ CROPTer TOOLKIT ───────────────────────────────────┐{RESET}
{CYAN}│{RESET}  {GREEN}1{RESET}  Scope check       {DIM}Check URL against local scope{RESET}
{CYAN}│{RESET}  {GREEN}2{RESET}  Show scope        {DIM}Display allow/deny rules{RESET}
{CYAN}│{RESET}  {GREEN}3{RESET}  Auto-scope web scan {DIM}Enter one URL; scope is derived automatically{RESET}
{CYAN}│{RESET}  {GREEN}4{RESET}  Diagnostics       {DIM}Python and environment info{RESET}
{CYAN}│{RESET}  {GREEN}5{RESET}  Exit
{CYAN}{BOLD}└─────────────────────────────────────────────────────┘{RESET}""")
            choice = input(f"{MAGENTA}cropter>{RESET} ").strip().lower()
            if choice in {"5", "q", "quit", "exit"}:
                print(f"{GREEN}CROPTer session closed.{RESET}")
                return 0
            try:
                if choice == "1":
                    scope_check()
                elif choice == "2":
                    scope_show()
                elif choice == "3":
                    scan_target()
                elif choice == "4":
                    diagnostics()
                else:
                    print(f"{RED}Unknown option. Choose 1–5.{RESET}")
                    time.sleep(0.5)
                    continue
                pause()
            except (OSError, ValueError) as exc:
                print(f"\n{RED}{BOLD}[ERROR]{RESET} {exc}")
                print(f"{DIM}Check the file path and configuration, then try again.{RESET}")
                pause()
    except KeyboardInterrupt:
        print(f"\n{MAGENTA}Interrupted — CROPTer closed cleanly.{RESET}")
        return 130
    except Exception as exc:
        print(f"\n{RED}{BOLD}[FATAL ERROR]{RESET} {exc}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
