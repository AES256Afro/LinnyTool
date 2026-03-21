#!/usr/bin/env python3
"""LinnyTool — Linux Security Hardening, Auditing & Grading.

Terminal-first security platform with optional GUI.
Run without arguments for interactive TUI, or use CLI flags.
"""

import argparse
import curses
import logging
import os
import platform
import socket
import sys
import time
from pathlib import Path
from typing import Optional

# Ensure the project root is on the path
sys.path.insert(0, str(Path(__file__).parent))

from core import __version__, logger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linnytool",
        description="LinnyTool — Linux Security Hardening, Auditing & Grading",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  sudo python3 linnytool.py                    Interactive TUI
  sudo python3 linnytool.py --scan             Full security scan
  sudo python3 linnytool.py --harden basic     Apply basic hardening
  sudo python3 linnytool.py --harden moderate --dry-run
  sudo python3 linnytool.py --restore          Restore from latest backup
  sudo python3 linnytool.py --report           Generate HTML report
  sudo python3 linnytool.py --install-deps     Install security tools
  sudo python3 linnytool.py --gui              Launch tkinter GUI
""",
    )
    parser.add_argument("--scan", action="store_true", help="Run full security scan")
    parser.add_argument("--harden", choices=["basic", "moderate", "aggressive"],
                        metavar="TIER", help="Apply hardening tier (basic|moderate|aggressive)")
    parser.add_argument("--restore", nargs="?", const="latest", metavar="SNAPSHOT",
                        help="Restore from backup (latest or specific snapshot path)")
    parser.add_argument("--report", action="store_true", help="Generate HTML report from last scan")
    parser.add_argument("--install-deps", action="store_true", help="Install security tool dependencies")
    parser.add_argument("--install-gui", action="store_true", help="Install GUI dependencies (tkinter)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without applying")
    parser.add_argument("--gui", action="store_true", help="Launch tkinter GUI")
    parser.add_argument("--history", action="store_true", help="Show scan history")
    parser.add_argument("--resources", action="store_true", help="Show security resource links")
    parser.add_argument("--sysinfo", action="store_true", help="Show system information")
    parser.add_argument("--version", action="version", version=f"LinnyTool {__version__}")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return parser


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "\033[2m%(asctime)s\033[0m %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.setLevel(level)
    logger.addHandler(handler)


def check_root() -> None:
    if os.geteuid() != 0:
        print("\033[91mLinnyTool requires root privileges. Run with: sudo python3 linnytool.py\033[0m")
        sys.exit(1)


# ============================================================================
# CLI COMMAND HANDLERS
# ============================================================================

def cmd_scan() -> None:
    """Run full security scan with grading."""
    from core.distro_detect import detect
    from core.sysinfo import collect
    from core.grading import calculate_grade
    from core.reporter import generate_terminal_report, generate_html_report
    from core.history import HistoryDB

    print("\n\033[96m\033[1m  LinnyTool Full Security Scan\033[0m")
    print("  " + "=" * 40)
    start_time = time.time()

    profile = detect()
    sysinfo = collect(profile)
    all_findings = []

    # 1. Hardening audit
    print("\n  \033[1m[1/4]\033[0m Running hardening checks...")
    from core.hardening import audit as hardening_audit, Tier, get_findings_as_dicts as h_findings
    audit_results = hardening_audit(Tier.AGGRESSIVE, profile)
    all_findings.extend(h_findings(audit_results))
    passed = sum(1 for r in audit_results if r["passes"])
    print(f"        {passed}/{len(audit_results)} checks passing")

    # 2. Network audit
    print("  \033[1m[2/4]\033[0m Running network audit...")
    from core.network_audit import audit as net_audit, get_findings_as_dicts as n_findings
    net_result = net_audit(profile)
    all_findings.extend(n_findings(net_result))
    net_fails = sum(1 for f in net_result.findings if f.status == "Fail")
    print(f"        {net_result.open_port_count} ports, {net_fails} issues")

    # 3. CVE scan
    print("  \033[1m[3/4]\033[0m Scanning for CVEs...")
    from core.cve_scanner import scan as cve_scan, get_findings_as_dicts as c_findings
    cve_result = cve_scan(profile, check_kev=True)
    all_findings.extend(c_findings(cve_result))
    print(f"        {cve_result.total_cves} CVEs found ({cve_result.kev_matches} in CISA KEV)")

    # 4. OpenSCAP / Lynis (if available)
    print("  \033[1m[4/4]\033[0m Running security auditors...")
    from core.scanner_lynis import is_available as lynis_avail, scan as lynis_scan, get_findings_as_dicts as l_findings
    from core.scanner_openscap import is_available as scap_avail, scan as scap_scan

    if lynis_avail():
        lynis_result = lynis_scan(quick=True)
        if lynis_result:
            all_findings.extend(l_findings(lynis_result))
            print(f"        Lynis: hardening index {lynis_result.hardening_index}/100")
    else:
        print("        Lynis: not installed (run --install-deps)")

    scap_result = None
    if scap_avail() and profile.scap_content_file:
        scap_result = scap_scan(profile)
        if scap_result:
            print(f"        OpenSCAP: {scap_result.passed}/{scap_result.total_rules} rules passed ({scap_result.score:.1f}%)")
    else:
        print("        OpenSCAP: not available")

    # Grade
    duration = time.time() - start_time
    grade_result = calculate_grade(all_findings)

    # Terminal report
    report = generate_terminal_report(grade_result, all_findings, sysinfo)
    print(report)

    # HTML report
    report_path = generate_html_report(sysinfo, grade_result, all_findings)
    print(f"  HTML report: {report_path}")

    # Save to history
    try:
        with HistoryDB() as db:
            scan_id = db.save_scan(
                scan_type="full",
                grade=grade_result.overall_grade,
                score=grade_result.overall_score,
                duration=duration,
                distro=profile.display_name,
                kernel=platform.release(),
                hostname=socket.gethostname(),
            )
            db.save_findings_batch(scan_id, all_findings)
            print(f"  Scan saved to history (ID: {scan_id})")
    except Exception as e:
        logger.error("Failed to save scan history: %s", e)

    print(f"\n  Completed in {duration:.1f}s\n")


def cmd_harden(tier_name: str, dry_run: bool) -> None:
    """Apply hardening at the specified tier."""
    from core.distro_detect import detect
    from core.hardening import Tier, apply

    tier = Tier(tier_name)
    profile = detect()

    action = "DRY RUN" if dry_run else "APPLYING"
    print(f"\n\033[96m\033[1m  LinnyTool Hardening — {tier.value.upper()} ({action})\033[0m")
    print("  " + "=" * 50)

    results = apply(tier, profile, dry_run=dry_run)

    for r in results:
        if r["was_passing"]:
            icon = "\033[92m  PASS\033[0m"
        elif r["success"]:
            icon = "\033[93m FIXED\033[0m" if not dry_run else "\033[94m WOULD\033[0m"
        else:
            icon = "\033[91m  FAIL\033[0m"

        print(f"  [{icon}] {r['name']:<35s} {r['detail'][:50]}")

    passed = sum(1 for r in results if r["was_passing"])
    fixed = sum(1 for r in results if not r["was_passing"] and r["success"])
    failed = sum(1 for r in results if not r["was_passing"] and not r["success"])

    print(f"\n  Summary: {passed} already passing, {fixed} {'would fix' if dry_run else 'fixed'}, {failed} failed")

    if not dry_run and fixed > 0:
        from core.backup_manager import get_latest_snapshot
        snap = get_latest_snapshot()
        if snap:
            print(f"  Backup:  {snap}")
            print(f"  Restore: sudo python3 linnytool.py --restore")
    print()


def cmd_restore(snapshot: str) -> None:
    """Restore from backup."""
    from core.backup_manager import restore_all, get_latest_snapshot, list_snapshots

    if snapshot == "latest":
        snap_path = get_latest_snapshot()
        if not snap_path:
            print("\033[91m  No backup snapshots found.\033[0m")
            return
    else:
        snap_path = Path(snapshot)
        if not snap_path.exists():
            print(f"\033[91m  Snapshot not found: {snapshot}\033[0m")
            return

    print(f"\n\033[96m\033[1m  Restoring from: {snap_path}\033[0m")
    restored = restore_all(snap_path)
    if restored:
        print(f"  Restored {len(restored)} files:")
        for f in restored:
            print(f"    \033[92m+ {f}\033[0m")
        # Restart sshd if SSH configs were restored
        if any("ssh" in f for f in restored):
            from core import run_command
            run_command(["systemctl", "restart", "sshd"], timeout=30)
            print("  SSH daemon restarted")
    else:
        print("  \033[91mNo files were restored.\033[0m")
    print()


def cmd_install_deps(include_gui: bool = False) -> None:
    """Install security tool dependencies."""
    from core.distro_detect import detect
    from core.dependency_installer import install_all, install_gui_deps

    profile = detect()
    print(f"\n\033[96m\033[1m  Installing Dependencies ({profile.display_name})\033[0m")
    print("  " + "=" * 50)

    def callback(name, msg, success):
        icon = "\033[92m OK\033[0m" if success else "\033[91m!!\033[0m"
        print(f"  [{icon}] {name:<25s} {msg}")

    results = install_all(profile, callback=callback, include_optional=include_gui)

    installed = sum(1 for v in results.values() if v)
    print(f"\n  {installed}/{len(results)} packages available\n")


def cmd_history() -> None:
    """Show scan history."""
    from core.history import HistoryDB

    with HistoryDB() as db:
        scans = db.get_scans(limit=20)

    if not scans:
        print("\n  No scan history found. Run --scan first.\n")
        return

    print(f"\n\033[96m\033[1m  Scan History\033[0m")
    print(f"  {'Date':<22s} {'Type':<8s} {'Grade':<6s} {'Score':<8s} {'Findings'}")
    print(f"  {'-' * 60}")
    for s in scans:
        print(f"  {s['timestamp']:<22s} {s['scan_type']:<8s} {s.get('overall_grade', '-'):<6s} "
              f"{s.get('overall_score', 0):>5.1f}   {s.get('total_findings', 0)} "
              f"(C:{s.get('critical_count', 0)} H:{s.get('high_count', 0)})")
    print()


def cmd_sysinfo() -> None:
    """Show system information."""
    from core.distro_detect import detect
    from core.sysinfo import collect, format_uptime

    profile = detect()
    info = collect(profile)

    print(f"\n\033[96m\033[1m  System Information\033[0m")
    print(f"  {'=' * 50}")
    print(f"  Hostname:       {info.hostname}")
    print(f"  Distribution:   {info.distro.display_name}")
    print(f"  Family:         {info.distro.family.value.upper()}")
    print(f"  Pkg Manager:    {info.distro.pkg_manager.value}")
    print(f"  Container:      {info.distro.container.value}")
    print(f"  Init System:    {info.distro.init_system}")
    print(f"  Server Mode:    {'Yes' if info.distro.is_server else 'No (desktop detected)'}")
    print(f"  Kernel:         {info.kernel_version}")
    print(f"  Architecture:   {info.architecture}")
    print(f"  CPU:            {info.cpu_model}")
    print(f"  CPU Cores:      {info.cpu_cores}")
    print(f"  RAM:            {info.ram_total_mb} MB total, {info.ram_available_mb} MB available")
    print(f"  Uptime:         {format_uptime(info.uptime_seconds)}")
    print(f"  Last Boot:      {info.last_boot}")

    if info.mac_status:
        print(f"  MAC Framework:  {info.mac_status.framework} ({info.mac_status.mode})")
    if info.firewall_status:
        fw = info.firewall_status
        print(f"  Firewall:       {fw.tool} ({'active' if fw.active else 'inactive'})")

    print(f"\n  \033[1mSecurity Tools:\033[0m")
    for name, installed in info.security_tools.items():
        icon = "\033[92m+\033[0m" if installed else "\033[91m-\033[0m"
        print(f"    [{icon}] {name}")

    if info.distro.scap_content_file:
        print(f"\n  SCAP Content:   {Path(info.distro.scap_content_file).name}")
    else:
        print(f"\n  SCAP Content:   Not found (run --install-deps)")

    print()


# ============================================================================
# CURSES TUI
# ============================================================================

class LinnyToolTUI:
    """Curses-based terminal user interface."""

    MENU_ITEMS = [
        ("Full Security Scan", "scan"),
        ("Hardening", "harden"),
        ("Backup / Restore", "backup"),
        ("Scan History", "history"),
        ("System Information", "sysinfo"),
        ("Install Dependencies", "deps"),
        ("Security Resources", "resources"),
        ("Exit", "exit"),
    ]

    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.current_row = 0
        self.status_msg = ""
        self._init_colors()
        curses.curs_set(0)
        self.stdscr.timeout(-1)

    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_CYAN, -1)      # header
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)  # selected
        curses.init_pair(3, curses.COLOR_WHITE, -1)      # normal
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)  # status bar
        curses.init_pair(5, curses.COLOR_RED, -1)        # critical
        curses.init_pair(6, curses.COLOR_YELLOW, -1)     # warning
        curses.init_pair(7, curses.COLOR_GREEN, -1)      # pass/good

    def run(self):
        while True:
            self.stdscr.clear()
            self._draw_header()
            self._draw_menu()
            self._draw_status_bar()
            self.stdscr.refresh()

            key = self.stdscr.getch()
            if key == curses.KEY_UP and self.current_row > 0:
                self.current_row -= 1
            elif key == curses.KEY_DOWN and self.current_row < len(self.MENU_ITEMS) - 1:
                self.current_row += 1
            elif key in (curses.KEY_ENTER, 10, 13):
                action = self.MENU_ITEMS[self.current_row][1]
                if action == "exit":
                    break
                self._handle_action(action)
            elif key == ord("q") or key == ord("Q"):
                break

    def _draw_header(self):
        h, w = self.stdscr.getmaxyx()
        title = f"LinnyTool v{__version__}"
        subtitle = "Linux Security Hardening, Auditing & Grading"

        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(1, max(0, (w - len(title)) // 2), title)
        self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(2, max(0, (w - len(subtitle)) // 2), subtitle)

        # ASCII art banner
        banner = "[ SECURITY SUITE ]"
        self.stdscr.attron(curses.color_pair(1))
        self.stdscr.addstr(3, max(0, (w - len(banner)) // 2), banner)
        self.stdscr.attroff(curses.color_pair(1))

        self.stdscr.addstr(4, 2, "-" * min(w - 4, 70))

    def _draw_menu(self):
        h, w = self.stdscr.getmaxyx()
        start_y = 6

        for idx, (label, _) in enumerate(self.MENU_ITEMS):
            x = max(0, (w - 40) // 2)
            y = start_y + idx * 2

            if y >= h - 2:
                break

            if idx == self.current_row:
                self.stdscr.attron(curses.color_pair(2) | curses.A_BOLD)
                self.stdscr.addstr(y, x, f"  > {label:<35s}")
                self.stdscr.attroff(curses.color_pair(2) | curses.A_BOLD)
            else:
                self.stdscr.attron(curses.color_pair(3))
                self.stdscr.addstr(y, x, f"    {label:<35s}")
                self.stdscr.attroff(curses.color_pair(3))

    def _draw_status_bar(self):
        h, w = self.stdscr.getmaxyx()
        status = f" {self.status_msg}" if self.status_msg else " Use arrow keys to navigate, Enter to select, Q to quit"
        status = status[:w - 1]

        self.stdscr.attron(curses.color_pair(4))
        try:
            self.stdscr.addstr(h - 1, 0, status.ljust(w - 1))
        except curses.error:
            pass
        self.stdscr.attroff(curses.color_pair(4))

    def _handle_action(self, action: str):
        """Handle menu selection by dropping out of curses temporarily."""
        curses.endwin()

        try:
            if action == "scan":
                cmd_scan()
            elif action == "harden":
                self._harden_submenu()
            elif action == "backup":
                self._backup_submenu()
            elif action == "history":
                cmd_history()
            elif action == "sysinfo":
                cmd_sysinfo()
            elif action == "deps":
                cmd_install_deps()
            elif action == "resources":
                from core.resources import print_resources
                print_resources()
        except Exception as e:
            print(f"\n\033[91mError: {e}\033[0m")

        print("\nPress Enter to return to menu...")
        input()

        # Re-init curses
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)
        self._init_colors()
        curses.curs_set(0)

    def _harden_submenu(self):
        """Interactive hardening tier selection."""
        print("\n\033[96m\033[1m  Select Hardening Tier:\033[0m")
        print("  1) Basic     — SSH, firewall, passwords, USB storage")
        print("  2) Moderate  — + sysctl, auditd, AppArmor/SELinux, AIDE")
        print("  3) Aggressive — + filesystem/protocol blocking, banners")
        print("  4) Dry Run (Basic)")
        print("  5) Dry Run (Moderate)")
        print("  6) Dry Run (Aggressive)")
        print("  0) Cancel")

        choice = input("\n  Choice: ").strip()
        tier_map = {
            "1": ("basic", False), "2": ("moderate", False), "3": ("aggressive", False),
            "4": ("basic", True), "5": ("moderate", True), "6": ("aggressive", True),
        }
        if choice in tier_map:
            tier, dry = tier_map[choice]
            cmd_harden(tier, dry)

    def _backup_submenu(self):
        """Interactive backup/restore menu."""
        from core.backup_manager import list_snapshots

        print("\n\033[96m\033[1m  Backup / Restore\033[0m")
        snapshots = list_snapshots()
        if snapshots:
            print(f"\n  Available snapshots ({len(snapshots)}):")
            for i, s in enumerate(snapshots[:10], 1):
                print(f"    {i}) {s['timestamp']}  {s['reason']:<30s}  {s['file_count']} files")
            print(f"\n  R) Restore latest")
            print(f"  0) Cancel")
            choice = input("\n  Choice: ").strip().upper()
            if choice == "R":
                cmd_restore("latest")
            elif choice.isdigit() and 1 <= int(choice) <= len(snapshots):
                cmd_restore(snapshots[int(choice) - 1]["path"])
        else:
            print("  No backup snapshots found.")
            print("  Backups are automatically created when hardening is applied.")


# ============================================================================
# GUI LAUNCHER
# ============================================================================

def cmd_gui():
    """Launch the tkinter GUI."""
    try:
        from gui.linnytool_gui import launch_gui
        launch_gui()
    except ImportError as e:
        print(f"\033[91m  GUI not available: {e}\033[0m")
        print("  Install GUI dependencies: sudo python3 linnytool.py --install-gui")
        sys.exit(1)


# ============================================================================
# MAIN
# ============================================================================

def main():
    args = build_parser().parse_args()
    setup_logging(args.verbose)

    # Commands that don't need root
    if args.resources:
        from core.resources import print_resources
        print_resources()
        return
    if args.history:
        cmd_history()
        return

    # Everything else needs root
    check_root()

    if args.gui:
        cmd_gui()
    elif args.scan:
        cmd_scan()
    elif args.harden:
        cmd_harden(args.harden, args.dry_run)
    elif args.restore is not None:
        cmd_restore(args.restore)
    elif args.report:
        cmd_scan()  # Generate fresh scan + report
    elif args.install_deps or args.install_gui:
        cmd_install_deps(include_gui=args.install_gui)
    elif args.sysinfo:
        cmd_sysinfo()
    else:
        # Interactive TUI
        try:
            curses.wrapper(lambda stdscr: LinnyToolTUI(stdscr).run())
        except KeyboardInterrupt:
            print("\n  Exiting LinnyTool.\n")


if __name__ == "__main__":
    main()
