"""LinnyTool Tkinter GUI — Optional graphical interface.

Mirrors WinnyTool's layout: sidebar navigation + dynamic content area.
Dark theme (#1a1a2e). Threaded scan execution for responsive UI.
"""

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
except ImportError:
    print("tkinter not available. Install with: sudo python3 linnytool.py --install-gui")
    sys.exit(1)

from core import __version__, logger
from core.distro_detect import detect
from core.sysinfo import collect, format_uptime


# Theme colors
BG = "#1a1a2e"
BG_LIGHT = "#16213e"
BG_CARD = "#0f3460"
FG = "#e0e0e0"
FG_DIM = "#888888"
ACCENT = "#4fc3f7"
GREEN = "#28a745"
RED = "#dc3545"
ORANGE = "#fd7e14"
YELLOW = "#ffc107"
BLUE = "#17a2b8"

SEVERITY_COLORS = {
    "Critical": RED,
    "High": ORANGE,
    "Medium": YELLOW,
    "Low": BLUE,
    "Info": FG_DIM,
}


class LinnyToolGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"LinnyTool v{__version__} — Linux Security Suite")
        self.root.geometry("1200x800")
        self.root.configure(bg=BG)
        self.root.minsize(900, 600)

        # State
        self.profile = None
        self.sysinfo = None
        self.scan_running = False

        # Apply dark theme
        self._apply_theme()

        # Build layout
        self._build_sidebar()
        self._build_content()
        self._build_status_bar()

        # Load initial data
        self.root.after(100, self._load_initial)

    def _apply_theme(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_LIGHT)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("TButton", background=BG_CARD, foreground=FG, padding=(10, 6))
        style.map("TButton",
                  background=[("active", ACCENT), ("pressed", ACCENT)],
                  foreground=[("active", BG), ("pressed", BG)])
        style.configure("Sidebar.TButton", background=BG_LIGHT, foreground=FG,
                        padding=(15, 10), font=("Segoe UI", 11))
        style.map("Sidebar.TButton",
                  background=[("active", BG_CARD)],
                  foreground=[("active", ACCENT)])
        style.configure("Active.Sidebar.TButton", background=BG_CARD, foreground=ACCENT)
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground=ACCENT)
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10), foreground=FG_DIM)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("Grade.TLabel", font=("Segoe UI", 48, "bold"))

    def _build_sidebar(self):
        sidebar = ttk.Frame(self.root, width=220)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Logo
        logo_frame = ttk.Frame(sidebar)
        logo_frame.pack(fill=tk.X, pady=(20, 10), padx=10)
        ttk.Label(logo_frame, text="LinnyTool", style="Title.TLabel").pack()
        ttk.Label(logo_frame, text="Security Suite", style="Subtitle.TLabel").pack()

        ttk.Separator(sidebar, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=5)

        # Nav buttons
        buttons = [
            ("Full Scan", self._show_scan),
            ("Hardening", self._show_harden),
            ("Backup/Restore", self._show_backup),
            ("Scan History", self._show_history),
            ("System Info", self._show_sysinfo),
            ("Dependencies", self._show_deps),
            ("Resources", self._show_resources),
        ]

        self.nav_buttons = []
        for label, cmd in buttons:
            btn = ttk.Button(sidebar, text=label, style="Sidebar.TButton",
                             command=cmd)
            btn.pack(fill=tk.X, padx=10, pady=2)
            self.nav_buttons.append(btn)

    def _build_content(self):
        self.content_frame = ttk.Frame(self.root)
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                              bg=BG_LIGHT, fg=FG_DIM, anchor=tk.W, padx=10, pady=4,
                              font=("Segoe UI", 9))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _set_status(self, msg: str):
        self.status_var.set(msg)
        self.root.update_idletasks()

    def _load_initial(self):
        self._set_status("Detecting system...")
        try:
            self.profile = detect()
            self.sysinfo = collect(self.profile)
            self._set_status(f"Ready — {self.profile.display_name}")
            self._show_scan()
        except Exception as e:
            self._set_status(f"Error: {e}")

    # =====================================================================
    # PANELS
    # =====================================================================

    def _show_scan(self):
        self._clear_content()
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Full Security Scan", style="Title.TLabel").pack(pady=(0, 10))
        ttk.Label(frame, text="Runs hardening audit, network scan, CVE check, and security auditors.",
                  style="Subtitle.TLabel").pack()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        self.scan_btn = ttk.Button(btn_frame, text="Start Scan", command=self._run_scan)
        self.scan_btn.pack()

        self.scan_output = scrolledtext.ScrolledText(
            frame, bg=BG_LIGHT, fg=FG, insertbackground=FG,
            font=("Consolas", 10), height=25, wrap=tk.WORD,
            borderwidth=0, relief=tk.FLAT,
        )
        self.scan_output.pack(fill=tk.BOTH, expand=True, pady=10)

    def _run_scan(self):
        if self.scan_running:
            return
        self.scan_running = True
        self.scan_btn.configure(state=tk.DISABLED)
        self.scan_output.delete("1.0", tk.END)
        self._set_status("Scanning...")

        def scan_thread():
            try:
                self._scan_log("Starting full security scan...\n")
                start = time.time()

                from core.hardening import audit as h_audit, Tier, get_findings_as_dicts as h_fd
                from core.network_audit import audit as n_audit, get_findings_as_dicts as n_fd
                from core.cve_scanner import scan as c_scan, get_findings_as_dicts as c_fd
                from core.grading import calculate_grade

                all_findings = []

                self._scan_log("[1/3] Running hardening checks...")
                results = h_audit(Tier.AGGRESSIVE, self.profile)
                all_findings.extend(h_fd(results))
                passed = sum(1 for r in results if r["passes"])
                self._scan_log(f"  {passed}/{len(results)} checks passing\n")

                self._scan_log("[2/3] Running network audit...")
                net = n_audit(self.profile)
                all_findings.extend(n_fd(net))
                self._scan_log(f"  {net.open_port_count} ports, {sum(1 for f in net.findings if f.status == 'Fail')} issues\n")

                self._scan_log("[3/3] Scanning for CVEs...")
                cves = c_scan(self.profile, check_kev=True)
                all_findings.extend(c_fd(cves))
                self._scan_log(f"  {cves.total_cves} CVEs found\n")

                grade = calculate_grade(all_findings)
                duration = time.time() - start

                self._scan_log(f"\n{'=' * 50}")
                self._scan_log(f"  Grade: {grade.overall_grade} ({grade.overall_score:.1f}/100)")
                self._scan_log(f"  Passed: {grade.total_pass}  Failed: {grade.total_fail}")
                self._scan_log(f"  Duration: {duration:.1f}s")
                self._scan_log(f"{'=' * 50}\n")

                # Show failed checks
                for f in all_findings:
                    if f.get("status") == "Fail":
                        sev = f.get("severity", "Info")
                        self._scan_log(f"  [{sev:>8s}] {f.get('check_name', '')}: {f.get('description', '')[:60]}")

                from core.reporter import generate_html_report
                report_path = generate_html_report(self.sysinfo, grade, all_findings)
                self._scan_log(f"\nHTML report: {report_path}")

                self.root.after(0, lambda: self._set_status(
                    f"Scan complete — Grade: {grade.overall_grade} ({grade.overall_score:.1f}/100)"))

            except Exception as e:
                self._scan_log(f"\nError: {e}")
                self.root.after(0, lambda: self._set_status(f"Scan error: {e}"))
            finally:
                self.scan_running = False
                self.root.after(0, lambda: self.scan_btn.configure(state=tk.NORMAL))

        threading.Thread(target=scan_thread, daemon=True).start()

    def _scan_log(self, msg: str):
        def _append():
            self.scan_output.insert(tk.END, msg + "\n")
            self.scan_output.see(tk.END)
        self.root.after(0, _append)

    def _show_harden(self):
        self._clear_content()
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="System Hardening", style="Title.TLabel").pack(pady=(0, 10))

        tiers = [
            ("Basic", "SSH, firewall, passwords, USB storage, auto updates"),
            ("Moderate", "+ sysctl, auditd, AppArmor/SELinux, AIDE, core dumps"),
            ("Aggressive", "+ filesystem/protocol blocking, banners, NTP, wireless"),
        ]

        for tier_name, desc in tiers:
            card = tk.Frame(frame, bg=BG_CARD, padx=15, pady=10)
            card.pack(fill=tk.X, pady=5)

            header = tk.Frame(card, bg=BG_CARD)
            header.pack(fill=tk.X)

            tk.Label(header, text=tier_name, bg=BG_CARD, fg=ACCENT,
                     font=("Segoe UI", 13, "bold")).pack(side=tk.LEFT)

            btn_frame = tk.Frame(header, bg=BG_CARD)
            btn_frame.pack(side=tk.RIGHT)

            ttk.Button(btn_frame, text="Dry Run",
                       command=lambda t=tier_name.lower(): self._apply_harden(t, True)).pack(side=tk.LEFT, padx=2)
            ttk.Button(btn_frame, text="Apply",
                       command=lambda t=tier_name.lower(): self._apply_harden(t, False)).pack(side=tk.LEFT, padx=2)

            tk.Label(card, text=desc, bg=BG_CARD, fg=FG_DIM,
                     font=("Segoe UI", 9)).pack(anchor=tk.W, pady=(5, 0))

    def _apply_harden(self, tier: str, dry_run: bool):
        if not dry_run:
            if not messagebox.askyesno("Confirm",
                    f"Apply {tier.upper()} hardening?\n\nA backup will be created automatically."):
                return

        self._clear_content()
        output = scrolledtext.ScrolledText(
            self.content_frame, bg=BG_LIGHT, fg=FG,
            font=("Consolas", 10), wrap=tk.WORD, borderwidth=0,
        )
        output.pack(fill=tk.BOTH, expand=True)

        def run():
            from core.hardening import Tier, apply
            action = "DRY RUN" if dry_run else "APPLYING"
            self.root.after(0, lambda: output.insert(tk.END,
                f"Hardening — {tier.upper()} ({action})\n{'=' * 50}\n\n"))

            results = apply(Tier(tier), self.profile, dry_run=dry_run)
            for r in results:
                if r["was_passing"]:
                    icon = "  PASS"
                elif r["success"]:
                    icon = " FIXED" if not dry_run else " WOULD"
                else:
                    icon = "  FAIL"
                line = f"[{icon}] {r['name']:<35s} {r['detail'][:50]}\n"
                self.root.after(0, lambda l=line: output.insert(tk.END, l))

            self.root.after(0, lambda: self._set_status("Hardening complete"))

        threading.Thread(target=run, daemon=True).start()

    def _show_backup(self):
        self._clear_content()
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Backup / Restore", style="Title.TLabel").pack(pady=(0, 10))

        from core.backup_manager import list_snapshots
        snapshots = list_snapshots()

        if not snapshots:
            ttk.Label(frame, text="No backup snapshots found.",
                      style="Subtitle.TLabel").pack(pady=20)
            ttk.Label(frame, text="Backups are created automatically when hardening is applied.",
                      style="Subtitle.TLabel").pack()
            return

        for s in snapshots[:10]:
            card = tk.Frame(frame, bg=BG_CARD, padx=15, pady=8)
            card.pack(fill=tk.X, pady=3)

            info = tk.Frame(card, bg=BG_CARD)
            info.pack(fill=tk.X)

            tk.Label(info, text=s["timestamp"], bg=BG_CARD, fg=ACCENT,
                     font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
            tk.Label(info, text=f"  {s['reason']}  ({s['file_count']} files)",
                     bg=BG_CARD, fg=FG_DIM).pack(side=tk.LEFT, padx=10)

            ttk.Button(info, text="Restore",
                       command=lambda p=s["path"]: self._do_restore(p)).pack(side=tk.RIGHT)

    def _do_restore(self, path: str):
        if not messagebox.askyesno("Confirm", f"Restore all files from this backup?\n\n{path}"):
            return
        from core.backup_manager import restore_all
        restored = restore_all(Path(path))
        messagebox.showinfo("Restore Complete", f"Restored {len(restored)} files.")
        self._set_status(f"Restored {len(restored)} files from {Path(path).name}")

    def _show_history(self):
        self._clear_content()
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Scan History", style="Title.TLabel").pack(pady=(0, 10))

        from core.history import HistoryDB
        with HistoryDB() as db:
            scans = db.get_scans(20)

        if not scans:
            ttk.Label(frame, text="No scan history. Run a Full Scan first.",
                      style="Subtitle.TLabel").pack(pady=20)
            return

        # Table
        cols = ("Date", "Type", "Grade", "Score", "Findings")
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=15)
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=120)

        for s in scans:
            tree.insert("", tk.END, values=(
                s["timestamp"], s["scan_type"],
                s.get("overall_grade", "-"),
                f"{s.get('overall_score', 0):.1f}",
                s.get("total_findings", 0),
            ))

        tree.pack(fill=tk.BOTH, expand=True)

    def _show_sysinfo(self):
        self._clear_content()
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="System Information", style="Title.TLabel").pack(pady=(0, 10))

        if not self.sysinfo:
            return

        info = self.sysinfo
        rows = [
            ("Hostname", info.hostname),
            ("Distribution", info.distro.display_name if info.distro else "Unknown"),
            ("Kernel", info.kernel_version),
            ("Architecture", info.architecture),
            ("CPU", f"{info.cpu_model} ({info.cpu_cores} cores)"),
            ("RAM", f"{info.ram_total_mb} MB total, {info.ram_available_mb} MB avail"),
            ("Uptime", format_uptime(info.uptime_seconds)),
        ]
        if info.mac_status:
            rows.append(("MAC Framework", f"{info.mac_status.framework} ({info.mac_status.mode})"))
        if info.firewall_status:
            rows.append(("Firewall", f"{info.firewall_status.tool} ({'active' if info.firewall_status.active else 'inactive'})"))

        for label, value in rows:
            row = tk.Frame(frame, bg=BG_CARD, padx=15, pady=6)
            row.pack(fill=tk.X, pady=1)
            tk.Label(row, text=label, bg=BG_CARD, fg=FG_DIM, width=18, anchor=tk.W,
                     font=("Segoe UI", 10)).pack(side=tk.LEFT)
            tk.Label(row, text=str(value), bg=BG_CARD, fg=FG,
                     font=("Segoe UI", 10)).pack(side=tk.LEFT)

        # Security tools
        ttk.Label(frame, text="Security Tools", style="Title.TLabel").pack(pady=(20, 5))
        for name, installed in info.security_tools.items():
            color = GREEN if installed else RED
            icon = "+" if installed else "-"
            tk.Label(frame, text=f"  [{icon}] {name}", bg=BG, fg=color,
                     font=("Consolas", 10), anchor=tk.W).pack(fill=tk.X)

    def _show_deps(self):
        self._clear_content()
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Install Dependencies", style="Title.TLabel").pack(pady=(0, 10))
        ttk.Label(frame, text="Install all security tool packages for your distro.",
                  style="Subtitle.TLabel").pack()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="Install All", command=self._do_install_deps).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Install + GUI", command=lambda: self._do_install_deps(gui=True)).pack(side=tk.LEFT, padx=5)

        self.deps_output = scrolledtext.ScrolledText(
            frame, bg=BG_LIGHT, fg=FG, font=("Consolas", 10),
            height=20, wrap=tk.WORD, borderwidth=0,
        )
        self.deps_output.pack(fill=tk.BOTH, expand=True, pady=10)

    def _do_install_deps(self, gui=False):
        def run():
            from core.dependency_installer import install_all
            def cb(name, msg, success):
                icon = "OK" if success else "!!"
                line = f"[{icon}] {name:<25s} {msg}\n"
                self.root.after(0, lambda l=line: self.deps_output.insert(tk.END, l))
            results = install_all(self.profile, callback=cb, include_optional=gui)
            count = sum(1 for v in results.values() if v)
            self.root.after(0, lambda: self.deps_output.insert(tk.END,
                f"\n{count}/{len(results)} packages available\n"))
            self.root.after(0, lambda: self._set_status(f"Installed {count}/{len(results)} packages"))

        self.deps_output.delete("1.0", tk.END)
        threading.Thread(target=run, daemon=True).start()

    def _show_resources(self):
        self._clear_content()
        frame = ttk.Frame(self.content_frame)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Security Resources", style="Title.TLabel").pack(pady=(0, 10))

        from core.resources import RESOURCES

        canvas = tk.Canvas(frame, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=BG)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)

        for category, links in RESOURCES.items():
            tk.Label(scroll_frame, text=category, bg=BG, fg=ACCENT,
                     font=("Segoe UI", 12, "bold"), anchor=tk.W).pack(fill=tk.X, pady=(15, 5))
            for link in links:
                row = tk.Frame(scroll_frame, bg=BG_CARD, padx=10, pady=5)
                row.pack(fill=tk.X, pady=1)
                tk.Label(row, text=link["name"], bg=BG_CARD, fg=FG,
                         font=("Segoe UI", 10, "bold"), anchor=tk.W).pack(fill=tk.X)
                tk.Label(row, text=link["description"], bg=BG_CARD, fg=FG_DIM,
                         font=("Segoe UI", 9), anchor=tk.W).pack(fill=tk.X)
                tk.Label(row, text=link["url"], bg=BG_CARD, fg=BLUE,
                         font=("Segoe UI", 9), anchor=tk.W, cursor="hand2").pack(fill=tk.X)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def run(self):
        self.root.mainloop()


def launch_gui():
    app = LinnyToolGUI()
    app.run()


if __name__ == "__main__":
    launch_gui()
