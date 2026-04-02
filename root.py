import tkinter as tk
from tkinter import ttk, font
import subprocess
import time
import threading
import math
BG          = "#0d1117"   
BG_CARD     = "#161b22"   
BG_ITEM     = "#1c2333"   
BORDER      = "#21262d"  
TEAL        = "#79c0ff"  
TEAL_DIM    = "#388bfd"  
GREEN       = "#56d364"  
YELLOW      = "#e3b341"  
RED         = "#f85149"  
WHITE       = "#e6edf3"  
MUTED       = "#484f58"   
MUTED2      = "#6e7681"   
FONT_TITLE  = ("Segoe UI", 22, "bold")
FONT_SUB    = ("Segoe UI", 10)
FONT_MONO   = ("Consolas", 10)
FONT_BADGE  = ("Segoe UI", 9, "bold")
FONT_BTN    = ("Segoe UI", 11, "bold")
FONT_SCORE  = ("Segoe UI", 28, "bold")

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode(errors="ignore")
    except:
        return ""

def windows_security_scan():
    findings = []

    out = run_cmd("net localgroup administrators")
    users = [line.strip() for line in out.splitlines() if line.strip()]
    if len(users) > 5:
        findings.append(("Too many admin accounts", "warn"))
    else:
        findings.append(("Admin accounts normal", "safe"))

    bcd = run_cmd("bcdedit")
    if "testsigning Yes" in bcd:
        findings.append(("Test signing mode enabled", "danger"))
    else:
        findings.append(("Driver signature enforcement active", "safe"))

    defender = run_cmd("powershell Get-MpComputerStatus")
    if "AMServiceEnabled : True" in defender:
        findings.append(("Windows Defender active", "safe"))
    else:
        findings.append(("Windows Defender disabled", "danger"))

    net = run_cmd("netstat -ano")
    if any(p in net for p in ["4444", "5555", "1337"]):
        findings.append(("Suspicious ports open", "danger"))
    else:
        findings.append(("No suspicious ports", "safe"))

    startup = run_cmd('reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run')
    if len(startup.splitlines()) > 15:
        findings.append(("Too many startup entries", "warn"))
    else:
        findings.append(("Startup entries normal", "safe"))

    sfc = run_cmd("sfc /verifyonly")
    if "did not find any integrity violations" in sfc.lower():
        findings.append(("System files intact", "safe"))
    else:
        findings.append(("System file anomalies", "warn"))

    return findings

class RingCanvas(tk.Canvas):
    """A smooth animated arc that spins during scanning."""

    def __init__(self, parent, size=64, **kw):
        super().__init__(parent, width=size, height=size,
                         bg=BG_CARD, bd=0, highlightthickness=0, **kw)
        self.size = size
        self.angle = 0
        self._job = None
        self._spinning = False
        self._draw_ring(self.angle, MUTED)

    def _draw_ring(self, start, color, extent=240):
        self.delete("all")
        pad = 8
        s = self.size
        
        self.create_arc(pad, pad, s - pad, s - pad,
                        start=0, extent=359,
                        style="arc", outline=BG_ITEM, width=6)
        
        self.create_arc(pad, pad, s - pad, s - pad,
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

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("SYSTEM CHECKER")
        self.root.geometry("720x620")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)

        self.results = []
        self._build_ui()
    def _build_ui(self):
        header = tk.Frame(self.root, bg=BG_CARD, pady=0)
        header.pack(fill="x")
        _sep_h(header)

        hinner = tk.Frame(header, bg=BG_CARD)
        hinner.pack(fill="x", padx=28, pady=14)

        tk.Label(hinner, text="SYSTEM CHECKER",
                 fg=WHITE, bg=BG_CARD, font=FONT_TITLE).pack(side="left")

        self.badge = tk.Label(hinner, text="IDLE",
                              fg=MUTED2, bg=BG_ITEM,
                              font=FONT_BADGE, padx=10, pady=4)
        self.badge.pack(side="right", padx=(0, 2))

        _sep_h(header, color=BORDER)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=24, pady=18)

        left = tk.Frame(body, bg=BG, width=160)
        left.pack(side="left", fill="y", padx=(0, 20))
        left.pack_propagate(False)

        self.ring = RingCanvas(left, size=96)
        self.ring.pack(pady=(12, 16))

        self.btn = _FlatButton(left, text="  Run Scan  ",
                               normal_bg="#1f6feb", hover_bg="#388bfd",
                               fg=WHITE, font=FONT_BTN,
                               command=self.start_scan)
        self.btn.pack(fill="x")

        tk.Frame(left, bg=BG, height=20).pack()

        score_card = tk.Frame(left, bg=BG_CARD, padx=14, pady=12)
        score_card.pack(fill="x")
        _rounded_border(score_card)

        tk.Label(score_card, text="RISK SCORE",
                 fg=MUTED2, bg=BG_CARD, font=("Segoe UI", 8)).pack()
        self.score_lbl = tk.Label(score_card, text="—",
                                  fg=MUTED, bg=BG_CARD, font=FONT_SCORE)
        self.score_lbl.pack()
        self.verdict_lbl = tk.Label(score_card, text="",
                                    fg=MUTED, bg=BG_CARD, font=("Segoe UI", 10, "bold"))
        self.verdict_lbl.pack()

        right = tk.Frame(body, bg=BG_CARD, padx=0, pady=0)
        right.pack(side="left", fill="both", expand=True)

        list_header = tk.Frame(right, bg=BG_CARD, padx=16, pady=10)
        list_header.pack(fill="x")
        tk.Label(list_header, text="Scan Results",
                 fg=MUTED2, bg=BG_CARD, font=("Segoe UI", 9, "bold")).pack(side="left")
        self.count_lbl = tk.Label(list_header, text="",
                                  fg=MUTED, bg=BG_CARD, font=("Segoe UI", 9))
        self.count_lbl.pack(side="right")

        _sep_h(right, color=BORDER)

        self.list_frame = tk.Frame(right, bg=BG_CARD)
        self.list_frame.pack(fill="both", expand=True, padx=0, pady=0)

        foot = tk.Frame(self.root, bg=BG_CARD, pady=0)
        foot.pack(fill="x", side="bottom")
        _sep_h(foot, color=BORDER)
        tk.Label(foot, text="Windows Security Analyzer  ·  v4",
                 fg=MUTED, bg=BG_CARD, font=("Segoe UI", 8)).pack(pady=6)

    def start_scan(self):
        for w in self.list_frame.winfo_children():
            w.destroy()
        self.score_lbl.config(text="—", fg=MUTED)
        self.verdict_lbl.config(text="", fg=MUTED)
        self.count_lbl.config(text="")
        self.badge.config(text="SCANNING", fg=TEAL)
        self.btn.set_state("disabled")
        self.ring.spin()
        threading.Thread(target=self._scan_worker, daemon=True).start()
    def _scan_worker(self):
        self.results = windows_security_scan()
        dangers = 0
        warns = 0
        for idx, (label, result) in enumerate(self.results):
            time.sleep(0.45)

            if result == "danger":
                dangers += 1
                color, icon, tag = RED, "✕", "danger"
            elif result == "warn":
                warns += 1
                color, icon, tag = YELLOW, "!", "warn"
            else:
                color, icon, tag = GREEN, "✓", "safe"

            self.root.after(0, self._add_row, idx, label, icon, color, tag)

        score = dangers * 3 + warns

        if score >= 6:
            verdict, vcolor = "HIGH RISK", RED
        elif score >= 3:
            verdict, vcolor = "SUSPICIOUS", YELLOW
        else:
            verdict, vcolor = "SAFE", GREEN

        total = len(self.results)
        self.root.after(0, self._finish, score, verdict, vcolor, total)

    def _add_row(self, idx, label, icon, color, tag):
        row = tk.Frame(self.list_frame, bg=BG_CARD, padx=16, pady=0)
        row.pack(fill="x")

        inner = tk.Frame(row, bg=BG_ITEM if idx % 2 == 0 else BG_CARD,
                         padx=12, pady=9)
        inner.pack(fill="x")

        dot = tk.Label(inner, text=icon, fg=color, bg=inner["bg"],
                       font=("Consolas", 12, "bold"), width=2)
        dot.pack(side="left")

        tk.Label(inner, text=label, fg=WHITE, bg=inner["bg"],
                 font=("Segoe UI", 10)).pack(side="left", padx=(6, 0))

        tag_colors = {"safe": GREEN, "warn": YELLOW, "danger": RED}
        badge_txt  = {"safe": "SAFE", "warn": "WARN", "danger": "RISK"}
        chip = tk.Label(inner, text=badge_txt[tag],
                        fg=tag_colors[tag], bg=inner["bg"],
                        font=("Segoe UI", 8, "bold"))
        chip.pack(side="right")
        self.count_lbl.config(text=f"{self.list_frame.winfo_children().__len__()} checks")

    def _finish(self, score, verdict, vcolor, total):
        self.ring.stop(score_color=vcolor)
        self.score_lbl.config(text=str(score), fg=vcolor)
        self.verdict_lbl.config(text=verdict, fg=vcolor)
        self.badge.config(text=verdict, fg=vcolor)
        self.btn.set_state("normal")
        self.count_lbl.config(text=f"{total} / {total} checks")

def _sep_h(parent, color=BORDER, height=1):
    tk.Frame(parent, bg=color, height=height).pack(fill="x")
def _rounded_border(widget):
    """Simulate a subtle border by configuring relief."""
    widget.config(relief="flat", bd=0,
                  highlightthickness=1, highlightbackground=BORDER,
                  highlightcolor=BORDER)
class _FlatButton(tk.Label):
    """Hover-animated flat button built from a Label."""

    def __init__(self, parent, text, normal_bg, hover_bg,
                 fg, font, command, **kw):
        super().__init__(parent, text=text, bg=normal_bg, fg=fg,
                         font=font, pady=10, cursor="hand2", **kw)
        self._nbg  = normal_bg
        self._hbg  = hover_bg
        self._fg   = fg
        self._cmd  = command
        self._on   = False

        self.bind("<Enter>",    self._enter)
        self.bind("<Leave>",    self._leave)
        self.bind("<Button-1>", self._click)

    def _enter(self, _):
        if not self._on:
            self.config(bg=self._hbg)

    def _leave(self, _):
        if not self._on:
            self.config(bg=self._nbg)

    def _click(self, _):
        if not self._on:
            self._cmd()

    def set_state(self, state):
        if state == "disabled":
            self._on = True
            self.config(bg=MUTED, fg=BG, cursor="")
        else:
            self._on = False
            self.config(bg=self._nbg, fg=self._fg, cursor="hand2")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
