import tkinter as tk
from tkinter import ttk, font, filedialog, messagebox
import subprocess
import time
import threading
import math
import psutil
import datetime
import os

# ── Colour palette ──────────────────────────────────────────────────────────
BG        = "#0d1117"
BG_CARD   = "#161b22"
BG_ITEM   = "#1c2333"
BORDER    = "#21262d"
TEAL      = "#79c0ff"
TEAL_DIM  = "#388bfd"
GREEN     = "#56d364"
YELLOW    = "#e3b341"
RED       = "#f85149"
WHITE     = "#e6edf3"
MUTED     = "#484f58"
MUTED2    = "#6e7681"
PURPLE    = "#bc8cff"

FONT_TITLE = ("Segoe UI", 20, "bold")
FONT_SUB   = ("Segoe UI", 10)
FONT_MONO  = ("Consolas", 10)
FONT_BADGE = ("Segoe UI", 9, "bold")
FONT_BTN   = ("Segoe UI", 10, "bold")
FONT_SCORE = ("Segoe UI", 26, "bold")

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode(errors="ignore")
    except:
        return ""

# FEATURE 1 – Security Scan (original + password policy)

def windows_security_scan():
    findings = []

    # Admin accounts
    out = run_cmd("net localgroup administrators")
    users = [l.strip() for l in out.splitlines() if l.strip()]
    if len(users) > 5:
        findings.append(("Too many admin accounts detected", "warn"))
    else:
        findings.append(("Admin account count is normal", "safe"))

    # Test-signing mode
    bcd = run_cmd("bcdedit")
    if "testsigning Yes" in bcd:
        findings.append(("Test signing mode is ENABLED", "danger"))
    else:
        findings.append(("Driver signature enforcement active", "safe"))

    # Windows Defender
    defender = run_cmd("powershell Get-MpComputerStatus")
    if "AMServiceEnabled" in defender and "True" in defender:
        findings.append(("Windows Defender is active", "safe"))
    else:
        findings.append(("Windows Defender appears disabled", "danger"))

    # Suspicious ports
    net = run_cmd("netstat -ano")
    bad_ports = [p for p in ["4444", "5555", "1337", "6667", "31337"] if p in net]
    if bad_ports:
        findings.append((f"Suspicious port(s) open: {', '.join(bad_ports)}", "danger"))
    else:
        findings.append(("No known malicious ports detected", "safe"))

    # Startup entries
    startup = run_cmd('reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')
    if len(startup.splitlines()) > 15:
        findings.append(("Excessive startup entries found", "warn"))
    else:
        findings.append(("Startup entries within normal range", "safe"))

    # System file integrity
    sfc = run_cmd("sfc /verifyonly")
    if "did not find any integrity violations" in sfc.lower():
        findings.append(("System file integrity verified", "safe"))
    else:
        findings.append(("System file anomalies detected", "warn"))

    # ── NEW: Password Policy Check ──────────────────────────────────────────
    pw_policy = run_cmd("net accounts")
    min_len_line = [l for l in pw_policy.splitlines() if "Minimum password length" in l]
    max_age_line = [l for l in pw_policy.splitlines() if "Maximum password age" in l]
    lockout_line = [l for l in pw_policy.splitlines() if "Lockout threshold" in l]

    # Minimum password length
    if min_len_line:
        val = min_len_line[0].split()[-1]
        try:
            if int(val) >= 8:
                findings.append((f"Password min length: {val} chars (Good)", "safe"))
            else:
                findings.append((f"Password min length too short: {val} chars", "warn"))
        except:
            findings.append(("Password minimum length: Not configured", "warn"))
    else:
        findings.append(("Password policy: Unable to retrieve", "warn"))

    # Account lockout
    if lockout_line:
        val = lockout_line[0].split()[-1]
        if val.isdigit() and int(val) > 0:
            findings.append((f"Account lockout enabled after {val} attempts", "safe"))
        else:
            findings.append(("Account lockout NOT configured (Risky)", "danger"))
    else:
        findings.append(("Account lockout policy: Not found", "warn"))

    # Max password age
    if max_age_line:
        val = max_age_line[0].split()[-1]
        try:
            days = int(val)
            if 30 <= days <= 90:
                findings.append((f"Password max age: {days} days (Good)", "safe"))
            elif days > 90:
                findings.append((f"Password max age too long: {days} days", "warn"))
            else:
                findings.append((f"Password max age: {days} days", "safe"))
        except:
            findings.append(("Password max age: Unlimited (Risky)", "warn"))

    return findings

# FEATURE 2 – CPU & RAM Live Monitor

class ResourceMonitor(tk.Frame):
    """Live CPU and RAM usage bars that update every second."""

    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG_CARD, **kw)
        self._running = True
        self._build()
        self._update()

    def _build(self):
        tk.Label(self, text="LIVE RESOURCES", fg=MUTED2, bg=BG_CARD,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=10, pady=(8, 2))

        # CPU bar
        cpu_row = tk.Frame(self, bg=BG_CARD)
        cpu_row.pack(fill="x", padx=10, pady=2)
        tk.Label(cpu_row, text="CPU", fg=MUTED2, bg=BG_CARD,
                 font=("Segoe UI", 8), width=4, anchor="w").pack(side="left")
        self.cpu_bar = ttk.Progressbar(cpu_row, length=120, mode="determinate",
                                        style="CPU.Horizontal.TProgressbar")
        self.cpu_bar.pack(side="left", padx=(4, 6))
        self.cpu_lbl = tk.Label(cpu_row, text="0%", fg=TEAL, bg=BG_CARD,
                                font=("Segoe UI", 8, "bold"), width=5)
        self.cpu_lbl.pack(side="left")

        # RAM bar
        ram_row = tk.Frame(self, bg=BG_CARD)
        ram_row.pack(fill="x", padx=10, pady=(2, 8))
        tk.Label(ram_row, text="RAM", fg=MUTED2, bg=BG_CARD,
                 font=("Segoe UI", 8), width=4, anchor="w").pack(side="left")
        self.ram_bar = ttk.Progressbar(ram_row, length=120, mode="determinate",
                                        style="RAM.Horizontal.TProgressbar")
        self.ram_bar.pack(side="left", padx=(4, 6))
        self.ram_lbl = tk.Label(ram_row, text="0%", fg=PURPLE, bg=BG_CARD,
                                font=("Segoe UI", 8, "bold"), width=5)
        self.ram_lbl.pack(side="left")

        # Style progressbars
        style = ttk.Style()
        style.theme_use("default")
        style.configure("CPU.Horizontal.TProgressbar",
                        background=TEAL_DIM, troughcolor=BG_ITEM, thickness=8)
        style.configure("RAM.Horizontal.TProgressbar",
                        background=PURPLE, troughcolor=BG_ITEM, thickness=8)

    def _update(self):
        if not self._running:
            return
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent

        self.cpu_bar["value"] = cpu
        self.ram_bar["value"] = ram

        cpu_color = GREEN if cpu < 60 else YELLOW if cpu < 85 else RED
        ram_color = GREEN if ram < 70 else YELLOW if ram < 88 else RED

        self.cpu_lbl.config(text=f"{cpu:.0f}%", fg=cpu_color)
        self.ram_lbl.config(text=f"{ram:.0f}%", fg=ram_color)

        self.after(1000, self._update)

    def stop(self):
        self._running = False


# FEATURE 3 – Export Scan Report


def export_report(results, score, verdict):
    """Save a formatted .txt security report to a user-chosen location."""
    if not results:
        messagebox.showwarning("No Data", "Run a scan first before exporting.")
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename  = f"SecurityReport_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    lines = [
        "=" * 60,
        "  WINDOWS SECURITY ANALYZER — SCAN REPORT",
        "=" * 60,
        f"  Generated : {timestamp}",
        f"  Risk Score: {score}",
        f"  Verdict   : {verdict}",
        "=" * 60,
        "",
        "DETAILED FINDINGS:",
        "-" * 60,
    ]
    for label, status in results:
        tag = {"safe": "[SAFE]", "warn": "[WARN]", "danger": "[RISK]"}.get(status, "[INFO]")
        lines.append(f"  {tag:<10} {label}")

    lines += [
        "",
        "-" * 60,
        "  RISK SCORE GUIDE:",
        "  0-2  → SAFE       System appears secure",
        "  3-5  → SUSPICIOUS  Review flagged items",
        "  6+   → HIGH RISK   Immediate action recommended",
        "=" * 60,
        "  Generated by SYSTEM-CHECKER | github.com/AnantRayal2006",
        "=" * 60,
    ]

    path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        initialfile=filename,
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        title="Save Security Report"
    )
    if path:
        with open(path, "w") as f:
            f.write("\n".join(lines))
        messagebox.showinfo("Report Saved", f"Report saved to:\n{path}")


# Animated Ring Canvas

class RingCanvas(tk.Canvas):
    def __init__(self, parent, size=80, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=BG_CARD, bd=0, highlightthickness=0, **kw)
        self.size   = size
        self.angle  = 0
        self._job   = None
        self._spinning = False
        self._draw_ring(self.angle, MUTED)

    def _draw_ring(self, start, color, extent=240):
        self.delete("all")
        pad, s = 8, self.size
        self.create_arc(pad, pad, s-pad, s-pad,
                        start=0, extent=359,
                        style="arc", outline=BG_ITEM, width=6)
        self.create_arc(pad, pad, s-pad, s-pad,
                        start=start, extent=extent,
                        style="arc", outline=color, width=6)

    def spin(self):
        self._spinning = True
        self._animate()

    def _animate(self):
        if not self._spinning:
            return
        self.angle = (self.angle - 6) % 360
        self._draw_ring(self.angle, TEAL_DIM)
        self._job = self.after(30, self._animate)

    def stop(self, score_color=GREEN):
        self._spinning = False
        if self._job:
            self.after_cancel(self._job)
        self._draw_ring(90, score_color, extent=359)

    def idle(self):
        self._spinning = False
        if self._job:
            self.after_cancel(self._job)
        self._draw_ring(90, MUTED, extent=359)


# Flat Button

class _FlatButton(tk.Label):
    def __init__(self, parent, text, normal_bg, hover_bg, fg, font, command, **kw):
        super().__init__(parent, text=text, bg=normal_bg, fg=fg,
                         font=font, pady=8, cursor="hand2", **kw)
        self._nbg, self._hbg, self._fg = normal_bg, hover_bg, fg
        self._cmd = command
        self._on  = False
        self.bind("<Enter>",    self._enter)
        self.bind("<Leave>",    self._leave)
        self.bind("<Button-1>", self._click)

    def _enter(self, _):
        if not self._on: self.config(bg=self._hbg)
    def _leave(self, _):
        if not self._on: self.config(bg=self._nbg)
    def _click(self, _):
        if not self._on: self._cmd()

    def set_state(self, state):
        if state == "disabled":
            self._on = True
            self.config(bg=MUTED, fg=BG, cursor="")
        else:
            self._on = False
            self.config(bg=self._nbg, fg=self._fg, cursor="hand2")


# Helpers


def _sep_h(parent, color=BORDER, height=1):
    tk.Frame(parent, bg=color, height=height).pack(fill="x")

def _rounded_border(widget):
    widget.config(relief="flat", bd=0,
                  highlightthickness=1,
                  highlightbackground=BORDER,
                  highlightcolor=BORDER)



class App:
    def __init__(self, root):
        self.root     = root
        self.root.title("SYSTEM CHECKER — Windows Security Analyzer")
        self.root.geometry("780x680")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)
        self.results  = []
        self._score   = 0
        self._verdict = "—"
        self._build_ui()

    # ── UI Construction ───────────────────────────────────────────────────
    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG_CARD)
        header.pack(fill="x")
        _sep_h(header)
        hinner = tk.Frame(header, bg=BG_CARD)
        hinner.pack(fill="x", padx=24, pady=12)
        tk.Label(hinner, text="🛡  SYSTEM CHECKER",
                 fg=WHITE, bg=BG_CARD, font=FONT_TITLE).pack(side="left")
        self.badge = tk.Label(hinner, text="IDLE",
                              fg=MUTED2, bg=BG_ITEM,
                              font=FONT_BADGE, padx=10, pady=4)
        self.badge.pack(side="right")
        _sep_h(header, color=BORDER)

        # Body
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=20, pady=14)

        # ── Left panel ────────────────────────────────────────────────────
        left = tk.Frame(body, bg=BG, width=170)
        left.pack(side="left", fill="y", padx=(0, 16))
        left.pack_propagate(False)

        self.ring = RingCanvas(left, size=88)
        self.ring.pack(pady=(8, 12))

        # Run Scan button
        self.btn_scan = _FlatButton(left, text="▶  Run Scan",
                                    normal_bg="#1f6feb", hover_bg="#388bfd",
                                    fg=WHITE, font=FONT_BTN,
                                    command=self.start_scan)
        self.btn_scan.pack(fill="x")

        tk.Frame(left, bg=BG, height=6).pack()

        # Export Report button (NEW Feature 3)
        self.btn_export = _FlatButton(left, text="⬇  Export Report",
                                      normal_bg="#238636", hover_bg="#2ea043",
                                      fg=WHITE, font=FONT_BTN,
                                      command=self._do_export)
        self.btn_export.pack(fill="x")

        tk.Frame(left, bg=BG, height=14).pack()

        # Risk score card
        score_card = tk.Frame(left, bg=BG_CARD, padx=12, pady=10)
        score_card.pack(fill="x")
        _rounded_border(score_card)
        tk.Label(score_card, text="RISK SCORE",
                 fg=MUTED2, bg=BG_CARD, font=("Segoe UI", 8)).pack()
        self.score_lbl = tk.Label(score_card, text="—",
                                  fg=MUTED, bg=BG_CARD, font=FONT_SCORE)
        self.score_lbl.pack()
        self.verdict_lbl = tk.Label(score_card, text="",
                                    fg=MUTED, bg=BG_CARD,
                                    font=("Segoe UI", 9, "bold"))
        self.verdict_lbl.pack()

        tk.Frame(left, bg=BG, height=14).pack()

        # CPU / RAM monitor (NEW Feature 2)
        self.monitor = ResourceMonitor(left)
        _rounded_border(self.monitor)
        self.monitor.pack(fill="x")

        # Scan timestamp
        tk.Frame(left, bg=BG, height=10).pack()
        self.time_lbl = tk.Label(left, text="", fg=MUTED, bg=BG,
                                 font=("Segoe UI", 7), wraplength=160)
        self.time_lbl.pack()

        # ── Right panel ───────────────────────────────────────────────────
        right = tk.Frame(body, bg=BG_CARD)
        right.pack(side="left", fill="both", expand=True)

        list_header = tk.Frame(right, bg=BG_CARD, padx=14, pady=8)
        list_header.pack(fill="x")
        tk.Label(list_header, text="Scan Results",
                 fg=MUTED2, bg=BG_CARD,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        self.count_lbl = tk.Label(list_header, text="",
                                  fg=MUTED, bg=BG_CARD, font=("Segoe UI", 9))
        self.count_lbl.pack(side="right")
        _sep_h(right, color=BORDER)

        # Scrollable results list
        canvas = tk.Canvas(right, bg=BG_CARD, highlightthickness=0)
        scrollbar = ttk.Scrollbar(right, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        self.list_frame = tk.Frame(canvas, bg=BG_CARD)
        self._canvas_window = canvas.create_window((0, 0), window=self.list_frame, anchor="nw")

        def _on_frame_configure(e):
            canvas.configure(scrollregion=canvas.bbox("all"))
        def _on_canvas_configure(e):
            canvas.itemconfig(self._canvas_window, width=e.width)

        self.list_frame.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        # Footer
        foot = tk.Frame(self.root, bg=BG_CARD)
        foot.pack(fill="x", side="bottom")
        _sep_h(foot, color=BORDER)
        tk.Label(foot,
                 text="Windows Security Analyzer  ·  v5.0  ·  github.com/AnantRayal2006/SYSTEM-CHECKER",
                 fg=MUTED, bg=BG_CARD, font=("Segoe UI", 8)).pack(pady=5)

    # ── Scan Logic ────────────────────────────────────────────────────────
    def start_scan(self):
        for w in self.list_frame.winfo_children():
            w.destroy()
        self.score_lbl.config(text="—", fg=MUTED)
        self.verdict_lbl.config(text="", fg=MUTED)
        self.count_lbl.config(text="")
        self.badge.config(text="SCANNING…", fg=TEAL)
        self.btn_scan.set_state("disabled")
        self.btn_export.set_state("disabled")
        self.ring.spin()
        self.time_lbl.config(text="")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        self.results = windows_security_scan()
        dangers = 0
        warns   = 0

        for idx, (label, result) in enumerate(self.results):
            time.sleep(0.38)
            if result == "danger":
                dangers += 1
                color, icon, tag = RED,    "✕", "danger"
            elif result == "warn":
                warns += 1
                color, icon, tag = YELLOW, "!", "warn"
            else:
                color, icon, tag = GREEN,  "✓", "safe"
            self.root.after(0, self._add_row, idx, label, icon, color, tag)

        self._score = dangers * 3 + warns
        if self._score >= 6:
            self._verdict, vcolor = "HIGH RISK",   RED
        elif self._score >= 3:
            self._verdict, vcolor = "SUSPICIOUS",  YELLOW
        else:
            self._verdict, vcolor = "SAFE",        GREEN

        self.root.after(0, self._finish, self._score, self._verdict, vcolor, len(self.results))

    def _add_row(self, idx, label, icon, color, tag):
        row_bg = BG_ITEM if idx % 2 == 0 else BG_CARD
        inner  = tk.Frame(self.list_frame, bg=row_bg, padx=12, pady=9)
        inner.pack(fill="x")

        tk.Label(inner, text=icon, fg=color, bg=row_bg,
                 font=("Consolas", 12, "bold"), width=2).pack(side="left")
        tk.Label(inner, text=label, fg=WHITE, bg=row_bg,
                 font=("Segoe UI", 9), anchor="w").pack(side="left", padx=(6, 0), fill="x", expand=True)

        chip_map = {"safe": (GREEN, "SAFE"), "warn": (YELLOW, "WARN"), "danger": (RED, "RISK")}
        c, t = chip_map[tag]
        tk.Label(inner, text=t, fg=c, bg=row_bg,
                 font=("Segoe UI", 8, "bold")).pack(side="right")

        total = len(self.list_frame.winfo_children())
        self.count_lbl.config(text=f"{total} checks")

    def _finish(self, score, verdict, vcolor, total):
        self.ring.stop(score_color=vcolor)
        self.score_lbl.config(text=str(score), fg=vcolor)
        self.verdict_lbl.config(text=verdict, fg=vcolor)
        self.badge.config(text=verdict, fg=vcolor)
        self.btn_scan.set_state("normal")
        self.btn_export.set_state("normal")
        self.count_lbl.config(text=f"{total} / {total} checks")
        ts = datetime.datetime.now().strftime("Last scan: %d %b %Y, %H:%M:%S")
        self.time_lbl.config(text=ts)

    def _do_export(self):
        export_report(self.results, self._score, self._verdict)


if __name__ == "__main__":
    root = tk.Tk()
    app  = App(root)
    root.mainloop()
