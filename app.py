"""
app.py — PhishGuard Phishing Awareness Chatbot v2.0
=====================================================
Explainable Phishing Awareness Chatbot
LLM-Powered System for Cyber Attack Detection and User Education

University of the West of Scotland | MSc IT with Data Analytics
Banner ID : B01821745  (no student name shown in app)
Supervisor: Dr Graeme

UI DESIGN: BrainyNerds-style left sidebar
  ┌──────────────────────────────────────────────────────┐
  │ ■ Sidebar (dark navy, 235px fixed)  │  Main Content  │
  │   Logo + brand                      │  Header bar    │
  │   MAIN MENU label                   │  Page content  │
  │   • Dashboard                       │                │
  │   • Analyse Email                   │                │
  │   • Chatbot                         │                │
  │   • Model Metrics                   │                │
  │   • XAI Charts                      │                │
  │   • Datasets                        │                │
  │   • Settings                        │                │
  │   ─────────────                     │                │
  │   Banner ID badge (bottom)          │                │
  └──────────────────────────────────────────────────────┘

OUTLOOK INTEGRATION:
  When running as standalone .exe the app connects to local
  Outlook via win32com (Windows only) to fetch inbox emails.
  Gmail is handled by the browser extension (extension/ folder).
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading, os, sys, warnings, time, re
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.cm as mcm
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.gridspec import GridSpec
from sklearn.model_selection import train_test_split

from phishing_pipeline import (
    PhishingDetector, PhishingDataLoader,
    preprocess_email, extract_structural_features,
    LABEL_NAMES,
)

# ── Outlook integration (Windows only, optional) ──────────
try:
    import win32com.client
    OUTLOOK_AVAILABLE = True
except ImportError:
    OUTLOOK_AVAILABLE = False

# ─────────────────────────────────────────────────────────
#  IDENTITY  (Banner ID only — no student name)
# ─────────────────────────────────────────────────────────
BANNER_ID   = "B01821745"
PROGRAMME   = "MSc IT with Data Analytics"
UNIVERSITY  = "University of the West of Scotland"
TITLE_SHORT = "PhishGuard AI"
TITLE_LONG  = "Explainable Phishing Awareness Chatbot"

# ─────────────────────────────────────────────────────────
#  COLOUR PALETTE  (BrainyNerds reference)
#
#  Sidebar:  dark navy  #1A2332
#  Accent:   orange     #FF6B2B  (BrainyNerds primary orange)
#  Success:  green      #28C76F
#  Danger:   red        #EA5455
#  Info:     blue       #1E6FD9
#  Warning:  amber      #FF9F43
#  Purple:   #7367F0
#  Teal:     #00B4D8
#  Main bg:  #F5F6FA
# ─────────────────────────────────────────────────────────
C = {
    # ── Sidebar ──
    "sb":           "#1A2332",
    "sb_hover":     "#243447",
    "sb_active":    "#2A3F5A",
    "sb_text":      "#8B9BB4",
    "sb_active_txt":"#FFFFFF",
    "sb_section":   "#4A5568",

    # ── Main ──
    "bg":           "#F5F6FA",
    "white":        "#FFFFFF",
    "border":       "#E2E8F0",
    "border2":      "#CBD5E0",

    # ── Accents ──
    "orange":       "#FF6B2B",
    "orange_lt":    "#FFF0E8",
    "blue":         "#1E6FD9",
    "blue_lt":      "#EBF4FF",
    "green":        "#28C76F",
    "green_lt":     "#EAFAF1",
    "red":          "#EA5455",
    "red_lt":       "#FFF0F0",
    "amber":        "#FF9F43",
    "amber_lt":     "#FFF8EE",
    "purple":       "#7367F0",
    "purple_lt":    "#F3F2FF",
    "teal":         "#00B4D8",
    "teal_lt":      "#E8FAFD",

    # ── Text ──
    "txt_dark":     "#2D3748",
    "txt_mid":      "#4A5568",
    "txt_light":    "#718096",
    "txt_muted":    "#A0AEC0",
}

FF   = "Segoe UI" if os.name == "nt" else "Helvetica"
MONO = "Consolas" if os.name == "nt" else "Courier New"

# Menu definition: (icon_emoji, label, page_key, colour_accent)
MENU = [
    ("⊞",  "Dashboard",     "dashboard", C["blue"]),
    ("✉",  "Analyse Email", "analyse",   C["orange"]),
    ("💬", "Chatbot",       "chatbot",   C["green"]),
    ("📈", "Model Metrics", "metrics",   C["purple"]),
    ("📊", "XAI Charts",    "charts",    C["teal"]),
    ("📂", "Datasets",      "datasets",  C["amber"]),
    ("⚙",  "Settings",     "settings",  C["txt_light"]),
]

# Sample emails for demo / quick-load
SAMPLE_EMAILS = {
    "⚠️ Credential Harvest": (
        "Subject: URGENT: Your Account Will Be Suspended\n\n"
        "Dear Valued Customer,\n\nWe have detected UNUSUAL ACTIVITY on your account. "
        "Your account will be SUSPENDED within 24 hours unless you verify your identity IMMEDIATELY.\n\n"
        "Click here to verify: http://secure-paypal-login.fake-domain.com/verify\n\n"
        "Failure to act NOW will result in permanent account suspension.\n\nPayPal Security Team"
    ),
    "⚠️ Prize Scam": (
        "Subject: Congratulations! You've Won £10,000!\n\n"
        "CONGRATULATIONS!!!\nYou have been selected as our LUCKY WINNER this month!\n"
        "Claim your £10,000 prize NOW before it expires in 48 hours!\n\n"
        "To claim: http://claim-your-prize-now.com/winner\n\nOffer expires TONIGHT. ACT NOW!!!"
    ),
    "✅ Business Email": (
        "Subject: Q3 Financial Report — Please Review Before Thursday\n\n"
        "Dear Team,\nPlease find attached the Q3 financial report ahead of our meeting "
        "on Thursday at 2:00 PM in Conference Room B.\n\n"
        "Key highlights: Revenue up 12%, costs reduced by 8%.\n\n"
        "Kind regards,\nSarah Thompson\nFinance Manager"
    ),
    "✅ IT Maintenance": (
        "Subject: Scheduled Maintenance Sunday 2–4 AM\n\n"
        "Dear All,\nOur IT systems will undergo scheduled maintenance this Sunday "
        "between 2:00 AM and 4:00 AM. Email and VPN will be unavailable during this window.\n\n"
        "Contact IT helpdesk at ext 2200 if you have questions.\n\nIT Department"
    ),
}

# ─────────────────────────────────────────────────────────
#  CHART STYLE
# ─────────────────────────────────────────────────────────
def set_chart_style():
    plt.rcParams.update({
        "figure.facecolor":  C["white"],
        "axes.facecolor":    "#FAFBFC",
        "axes.edgecolor":    C["border"],
        "axes.labelcolor":   C["txt_mid"],
        "xtick.color":       C["txt_light"],
        "ytick.color":       C["txt_light"],
        "text.color":        C["txt_dark"],
        "grid.color":        C["border"],
        "grid.linestyle":    "--",
        "grid.alpha":        0.55,
        "legend.facecolor":  C["white"],
        "legend.edgecolor":  C["border"],
        "legend.fontsize":   8,
        "axes.titlesize":    10,
        "axes.labelsize":    8,
    })

set_chart_style()
MODEL_COLOURS = [C["orange"], C["blue"], C["green"], C["purple"], C["teal"]]


# ═══════════════════════════════════════════════════════════
#  HELPER WIDGETS
# ═══════════════════════════════════════════════════════════

def make_btn(parent, text, command, bg, fg="white",
             font_size=9, padx=14, pady=6) -> tk.Button:
    return tk.Button(
        parent, text=text, command=command,
        bg=bg, fg=fg, font=(FF, font_size, "bold"),
        relief="flat", padx=padx, pady=pady,
        cursor="hand2", activebackground=bg,
        activeforeground=fg, bd=0)


def card_frame(parent, border_colour=None, **kwargs) -> tk.Frame:
    """White card with optional coloured left border."""
    outer = tk.Frame(parent, bg=border_colour or C["border"],
                     highlightthickness=0)
    inner = tk.Frame(outer, bg=C["white"], **kwargs)
    inner.pack(fill="both", expand=True,
               padx=(3 if border_colour else 1, 1),
               pady=1)
    return inner


def section_label(parent, text: str):
    tk.Label(parent, text=text, bg=C["bg"],
             fg=C["txt_light"], font=(FF, 8, "bold")).pack(
                 anchor="w", padx=24, pady=(16, 4))


# ═══════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ═══════════════════════════════════════════════════════════

class PhishGuardApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(f"PhishGuard — {BANNER_ID} | {PROGRAMME} | {UNIVERSITY}")
        self.configure(bg=C["bg"])
        try:    self.state("zoomed")
        except Exception:
            try:    self.attributes("-zoomed", True)
            except: self.geometry("1400x860")
        self.minsize(1100, 680)

        # Core objects
        self.detector    = PhishingDetector(max_features=10000)
        self.loader      = PhishingDataLoader()
        self._df         = None
        self._has_uploaded_data = False
        self._trained    = False
        self._chat_hist  = []     # [(role, text), ...]
        self._cur_page   = "dashboard"
        self._pages      = {}
        self._menu_btns  = {}

        # Live stats
        self._stats = {"total": 0, "phish": 0, "legit": 0,
                       "weekly": [4, 7, 2, 9, 3, 6, 8]}

        self._build_layout()
        self._set_startup_upload_required_state()

    # ══════════════════════════════════════════════════════
    #  TOP-LEVEL LAYOUT
    # ══════════════════════════════════════════════════════

    def _build_layout(self):
        self._ttk_style()

        # Sidebar (fixed 235px left)
        self.sidebar = tk.Frame(self, bg=C["sb"], width=235)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Main area
        self.main = tk.Frame(self, bg=C["bg"])
        self.main.pack(side="left", fill="both", expand=True)

        self._build_sidebar()
        self._build_topbar()
        self._build_content_area()

    def _ttk_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TScrollbar", background=C["border"],
                    troughcolor=C["bg"], arrowcolor=C["txt_light"],
                    borderwidth=0)
        s.configure("Treeview",
                    background=C["white"], foreground=C["txt_dark"],
                    fieldbackground=C["white"], rowheight=28,
                    font=(FF, 9), borderwidth=0)
        s.configure("Treeview.Heading",
                    background=C["bg"], foreground=C["txt_mid"],
                    font=(FF, 9, "bold"), relief="flat")
        s.map("Treeview",
              background=[("selected", C["orange_lt"])],
              foreground=[("selected", C["orange"])])
        s.configure("Horizontal.TProgressbar",
                    troughcolor=C["border"], background=C["orange"],
                    borderwidth=0, thickness=4)

    # ──────────────────────────────────────────────────────
    #  SIDEBAR
    # ──────────────────────────────────────────────────────

    def _build_sidebar(self):
        sb = self.sidebar

        # ── Brand ──
        brand = tk.Frame(sb, bg=C["sb"], height=72)
        brand.pack(fill="x"); brand.pack_propagate(False)

        logo_bg = tk.Frame(brand, bg=C["orange"], width=38, height=38)
        logo_bg.place(x=16, y=17); logo_bg.pack_propagate(False)
        tk.Label(logo_bg, text="🛡", bg=C["orange"], fg="white",
                 font=(FF, 16)).place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(brand, text=TITLE_SHORT,
                 bg=C["sb"], fg="white", font=(FF, 13, "bold")
                 ).place(x=62, y=20)
        tk.Label(brand, text="Cyber Defence AI",
                 bg=C["sb"], fg=C["sb_text"], font=(FF, 8)
                 ).place(x=62, y=42)

        # Divider
        tk.Frame(sb, bg=C["sb_hover"], height=1).pack(fill="x", padx=16)

        # ── MAIN MENU label ──
        tk.Label(sb, text="MAIN MENU",
                 bg=C["sb"], fg=C["sb_section"],
                 font=(FF, 8, "bold")).pack(anchor="w", padx=18, pady=(12, 4))

        # ── Menu items ──
        for icon, label, key, colour in MENU:
            self._menu_item(sb, icon, label, key, colour)

        # ── Spacer + divider before footer ──
        tk.Frame(sb, bg=C["sb"]).pack(fill="both", expand=True)
        tk.Frame(sb, bg=C["sb_hover"], height=1).pack(fill="x", padx=16)

        # ── Banner ID badge (bottom, no student name) ──
        footer = tk.Frame(sb, bg=C["sb"], height=60)
        footer.pack(fill="x"); footer.pack_propagate(False)

        badge = tk.Frame(footer, bg=C["sb_active"], height=44)
        badge.pack(fill="x", padx=12, pady=8); badge.pack_propagate(False)

        tk.Label(badge, text="🎓", bg=C["sb_active"],
                 fg=C["orange"], font=(FF, 14)
                 ).pack(side="left", padx=(10, 6))

        info = tk.Frame(badge, bg=C["sb_active"])
        info.pack(side="left", pady=6)
        tk.Label(info, text=BANNER_ID, bg=C["sb_active"],
                 fg="white", font=(FF, 9, "bold")).pack(anchor="w")
        tk.Label(info, text="UWS MSc IT", bg=C["sb_active"],
                 fg=C["sb_text"], font=(FF, 7)).pack(anchor="w")

    def _menu_item(self, parent, icon, label, key, accent):
        row = tk.Frame(parent, bg=C["sb"], height=42, cursor="hand2")
        row.pack(fill="x"); row.pack_propagate(False)

        # Active indicator strip (left edge)
        strip = tk.Frame(row, bg=C["sb"], width=3)
        strip.pack(side="left", fill="y")

        icon_lbl = tk.Label(row, text=icon, bg=C["sb"],
                             fg=C["sb_text"], font=(FF, 13), width=3)
        icon_lbl.pack(side="left", padx=(6, 0))

        text_lbl = tk.Label(row, text=label, bg=C["sb"],
                             fg=C["sb_text"], font=(FF, 10))
        text_lbl.pack(side="left", padx=(4, 0))

        # Hover / active logic
        def on_enter(e):
            if self._cur_page != key:
                for w in [row, icon_lbl, text_lbl, strip]:
                    w.configure(bg=C["sb_hover"])

        def on_leave(e):
            if self._cur_page != key:
                for w in [row, icon_lbl, text_lbl]:
                    w.configure(bg=C["sb"])
                strip.configure(bg=C["sb"])

        def on_click(e, k=key):
            self._navigate(k)

        for w in (row, icon_lbl, text_lbl):
            w.bind("<Enter>",   on_enter)
            w.bind("<Leave>",   on_leave)
            w.bind("<Button-1>",on_click)

        # Store refs so we can set active state
        row._strip     = strip
        row._icon      = icon_lbl
        row._text      = text_lbl
        row._accent    = accent
        self._menu_btns[key] = row

    def _set_active_menu(self, key):
        for k, row in self._menu_btns.items():
            if k == key:
                row.configure(bg=C["sb_active"])
                row._icon.configure(bg=C["sb_active"], fg=row._accent)
                row._text.configure(bg=C["sb_active"], fg="white")
                row._strip.configure(bg=row._accent)
            else:
                row.configure(bg=C["sb"])
                row._icon.configure(bg=C["sb"], fg=C["sb_text"])
                row._text.configure(bg=C["sb"], fg=C["sb_text"])
                row._strip.configure(bg=C["sb"])

    # ──────────────────────────────────────────────────────
    #  TOP BAR
    # ──────────────────────────────────────────────────────

    def _build_topbar(self):
        bar = tk.Frame(self.main, bg=C["white"], height=60,
                       highlightbackground=C["border"], highlightthickness=1)
        bar.pack(fill="x"); bar.pack_propagate(False)

        self._page_title = tk.StringVar(value="Dashboard")
        tk.Label(bar, textvariable=self._page_title,
                 bg=C["white"], fg=C["txt_dark"],
                 font=(FF, 15, "bold")).pack(side="left", padx=24)

        # Right side
        right = tk.Frame(bar, bg=C["white"]); right.pack(side="right", padx=16)

        from datetime import datetime
        tk.Label(right, text=datetime.now().strftime("%A, %B %d, %Y"),
                 bg=C["white"], fg=C["txt_light"],
                 font=(FF, 9)).pack(side="right", padx=(0, 12), pady=18)

        self._status_var = tk.StringVar(value="Initialising…")
        tk.Label(bar, textvariable=self._status_var,
                 bg=C["white"], fg=C["txt_light"],
                 font=(FF, 9)).pack(side="right", padx=12)

        self._badge_var = tk.StringVar(value="⏳ Loading")
        self._badge = tk.Label(bar, textvariable=self._badge_var,
                                bg=C["amber"], fg="white",
                                font=(FF, 9, "bold"), padx=10, pady=4)
        self._badge.pack(side="right", padx=8, pady=16)

    # ──────────────────────────────────────────────────────
    #  CONTENT AREA
    # ──────────────────────────────────────────────────────

    def _build_content_area(self):
        self._content = tk.Frame(self.main, bg=C["bg"])
        self._content.pack(fill="both", expand=True)

        self._page_dashboard()
        self._page_analyse()
        self._page_chatbot()
        self._page_metrics()
        self._page_charts()
        self._page_datasets()
        self._page_settings()

        self._navigate("dashboard")

    def _navigate(self, key: str):
        self._cur_page = key
        for k, frame in self._pages.items():
            if k == key: frame.pack(fill="both", expand=True)
            else:        frame.pack_forget()
        self._set_active_menu(key)
        titles = {
            "dashboard": "Dashboard",
            "analyse":   "Analyse Email",
            "chatbot":   "Phishing Awareness Chatbot",
            "metrics":   "Model Metrics",
            "charts":    "XAI & Analytics Charts",
            "datasets":  "Dataset Management",
            "settings":  "Settings",
        }
        self._page_title.set(titles.get(key, key.title()))

    def _new_page(self, key: str) -> tk.Frame:
        f = tk.Frame(self._content, bg=C["bg"])
        self._pages[key] = f
        return f

    # ══════════════════════════════════════════════════════
    #  PAGE: DASHBOARD
    # ══════════════════════════════════════════════════════

    def _page_dashboard(self):
        p = self._new_page("dashboard")

        # ── KPI cards ──────────────────────────────────────
        kpi_row = tk.Frame(p, bg=C["bg"])
        kpi_row.pack(fill="x", padx=24, pady=(20, 0))

        kpi_defs = [
            ("Total Analysed",    "total",  "✉",  C["blue"],   C["blue_lt"]),
            ("Phishing Detected", "phish",  "⚠",  C["red"],    C["red_lt"]),
            ("Legitimate",        "legit",  "✓",  C["green"],  C["green_lt"]),
            ("Detection Rate",    "rate",   "📊", C["orange"], C["orange_lt"]),
        ]
        self._kpi = {}
        for label, key, icon, colour, bg_lt in kpi_defs:
            card = tk.Frame(kpi_row, bg=C["white"],
                            highlightbackground=C["border"], highlightthickness=1)
            card.pack(side="left", fill="both", expand=True, padx=(0, 16))
            inner = tk.Frame(card, bg=C["white"])
            inner.pack(fill="x", padx=18, pady=16)
            # Icon box
            ibox = tk.Frame(inner, bg=bg_lt, width=48, height=48)
            ibox.pack(side="left"); ibox.pack_propagate(False)
            tk.Label(ibox, text=icon, bg=bg_lt, fg=colour,
                     font=(FF, 18)).place(relx=0.5, rely=0.5, anchor="center")
            # Text
            tbox = tk.Frame(inner, bg=C["white"]); tbox.pack(side="left", padx=(12, 0))
            v = tk.StringVar(value="0"); self._kpi[key] = v
            tk.Label(tbox, textvariable=v, bg=C["white"], fg=C["txt_dark"],
                     font=(FF, 22, "bold")).pack(anchor="w")
            tk.Label(tbox, text=label, bg=C["white"], fg=C["txt_light"],
                     font=(FF, 9)).pack(anchor="w")

        # ── Charts row ─────────────────────────────────────
        charts_row = tk.Frame(p, bg=C["bg"])
        charts_row.pack(fill="both", expand=True, padx=24, pady=16)

        # Weekly bar chart card
        wcard = tk.Frame(charts_row, bg=C["white"],
                         highlightbackground=C["border"], highlightthickness=1)
        wcard.pack(side="left", fill="both", expand=True, padx=(0, 12))
        wh = tk.Frame(wcard, bg=C["white"])
        wh.pack(fill="x", padx=16, pady=(14, 0))
        tk.Label(wh, text="Weekly Analyses", bg=C["white"],
                 fg=C["txt_dark"], font=(FF, 11, "bold")).pack(anchor="w")
        tk.Label(wh, text="Emails checked per day this week",
                 bg=C["white"], fg=C["txt_light"], font=(FF, 8)).pack(anchor="w")
        self._wfig    = plt.Figure(figsize=(7, 3.6), facecolor=C["white"])
        self._wcanvas = FigureCanvasTkAgg(self._wfig, master=wcard)
        self._wcanvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

        # Distribution donut card
        dcard = tk.Frame(charts_row, bg=C["white"],
                         highlightbackground=C["border"], highlightthickness=1)
        dcard.pack(side="right", fill="both", expand=True)
        dh = tk.Frame(dcard, bg=C["white"])
        dh.pack(fill="x", padx=16, pady=(14, 0))
        tk.Label(dh, text="Detection Distribution", bg=C["white"],
                 fg=C["txt_dark"], font=(FF, 11, "bold")).pack(anchor="w")
        tk.Label(dh, text="Phishing vs Legitimate breakdown",
                 bg=C["white"], fg=C["txt_light"], font=(FF, 8)).pack(anchor="w")
        self._dfig    = plt.Figure(figsize=(5, 3.6), facecolor=C["white"])
        self._dcanvas = FigureCanvasTkAgg(self._dfig, master=dcard)
        self._dcanvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)

        self._redraw_dashboard()

    def _update_kpis(self):
        t = self._stats["total"]
        p = self._stats["phish"]
        l = self._stats["legit"]
        self._kpi["total"].set(str(t))
        self._kpi["phish"].set(str(p))
        self._kpi["legit"].set(str(l))
        self._kpi["rate"].set(f"{p/max(1,t)*100:.1f}%")
        self._redraw_dashboard()

    def _redraw_dashboard(self):
        set_chart_style()
        # Weekly bar
        self._wfig.clear(); ax = self._wfig.add_subplot(111)
        ax.set_facecolor("#FAFBFC")
        days = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
        vals = self._stats["weekly"]
        clrs = [C["orange"] if v == max(vals) else C["blue"] for v in vals]
        bars = ax.bar(days, vals, color=clrs, alpha=0.85, width=0.52, zorder=3)
        for b, v in zip(bars, vals):
            ax.text(b.get_x()+b.get_width()/2, b.get_height()+0.15,
                    str(v), ha="center", fontsize=8,
                    color=C["txt_mid"], fontweight="bold")
        ax.set_ylim(0, max(vals)*1.28 if vals else 10)
        ax.yaxis.grid(True, alpha=0.4, zorder=0); ax.set_axisbelow(True)
        for sp in ax.spines.values(): sp.set_visible(False)
        ax.tick_params(bottom=False, left=False)
        self._wcanvas.draw()

        # Donut
        self._dfig.clear(); ax2 = self._dfig.add_subplot(111)
        ax2.set_facecolor(C["white"])
        p = self._stats["phish"]; l = self._stats["legit"]
        if p + l > 0:
            import matplotlib.patches as mpa
            ax2.pie([l, p], startangle=90, counterclock=False,
                    colors=[C["green"], C["red"]],
                    wedgeprops=dict(width=0.45, edgecolor=C["white"], linewidth=3))
            ax2.text(0, 0.08, f"{p+l}", ha="center", va="center",
                     fontsize=18, fontweight="bold", color=C["txt_dark"])
            ax2.text(0, -0.18, "analysed", ha="center", va="center",
                     fontsize=9, color=C["txt_light"])
            ax2.legend(handles=[
                mpa.Patch(color=C["green"], label=f"Legitimate  {l}"),
                mpa.Patch(color=C["red"],   label=f"Phishing   {p}"),
            ], loc="lower center", bbox_to_anchor=(0.5, -0.14),
               ncol=2, fontsize=8, frameon=False)
        else:
            ax2.text(0.5, 0.5, "Analyse emails\nto populate chart",
                     ha="center", va="center", fontsize=10,
                     color=C["txt_light"], transform=ax2.transAxes)
            ax2.axis("off")
        self._dcanvas.draw()

    # ══════════════════════════════════════════════════════
    #  PAGE: ANALYSE EMAIL
    # ══════════════════════════════════════════════════════

    def _page_analyse(self):
        p = self._new_page("analyse")

        # ── Input card ─────────────────────────────────────
        icard = tk.Frame(p, bg=C["white"],
                         highlightbackground=C["border"], highlightthickness=1)
        icard.pack(fill="x", padx=24, pady=(20, 0))

        ih = tk.Frame(icard, bg=C["white"]); ih.pack(fill="x", padx=16, pady=(14, 4))
        tk.Label(ih, text="Paste Email Content for Analysis",
                 bg=C["white"], fg=C["txt_dark"],
                 font=(FF, 11, "bold")).pack(anchor="w")
        tk.Label(ih,
                 text="Paste the full email text. The system classifies it and generates "
                      "an explainable AI rationale using SHAP/LIME.",
                 bg=C["white"], fg=C["txt_light"], font=(FF, 9)).pack(anchor="w")

        self._email_in = scrolledtext.ScrolledText(
            icard, height=8, bg="#FAFBFC", fg=C["txt_dark"],
            font=(FF, 10), relief="solid", bd=1,
            padx=12, pady=10, insertbackground=C["txt_dark"], wrap="word")
        self._email_in.pack(fill="x", padx=16, pady=(0, 8))

        # Quick-load sample row
        qrow = tk.Frame(icard, bg=C["white"]); qrow.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(qrow, text="Load sample:", bg=C["white"],
                 fg=C["txt_light"], font=(FF, 9)).pack(side="left")
        for name in SAMPLE_EMAILS:
            is_phish = "⚠️" in name
            col = C["red"] if is_phish else C["green"]
            bg_col = C["red_lt"] if is_phish else C["green_lt"]
            short = name.replace("⚠️ ","").replace("✅ ","")
            tk.Button(qrow, text=name, bg=bg_col, fg=col,
                      font=(FF, 8, "bold"), relief="flat", padx=8, pady=3,
                      cursor="hand2",
                      command=lambda n=name: self._load_sample(n)
                      ).pack(side="left", padx=3)

        # Outlook button (Windows only)
        if OUTLOOK_AVAILABLE:
            make_btn(icard, "📧  Import from Outlook Inbox",
                     self._load_from_outlook, C["blue"]
                     ).pack(anchor="w", padx=16, pady=(0, 8))

        # Action buttons
        brow = tk.Frame(icard, bg=C["white"]); brow.pack(fill="x", padx=16, pady=(0, 14))
        make_btn(brow, "🔍  Analyse Email", self._do_analyse, C["orange"]).pack(side="left", padx=(0, 8))
        make_btn(brow, "🗑  Clear", lambda: self._email_in.delete("1.0","end"), C["blue"]).pack(side="left")
        self._analyse_model_var = tk.StringVar(value="Best Model")
        tk.Label(brow, text="Model:", bg=C["white"], fg=C["txt_light"],
                 font=(FF, 9)).pack(side="left", padx=(16, 4))
        ttk.Combobox(brow, textvariable=self._analyse_model_var,
                     values=["Best Model","Logistic Regression","Decision Tree",
                             "SVM (LinearSVC)","Naïve Bayes","Random Forest"],
                     state="readonly", font=(FF, 9), width=20
                     ).pack(side="left")

        # ── Verdict + model results ─────────────────────────
        self._verdict_card = tk.Frame(p, bg=C["white"],
                                       highlightbackground=C["border"],
                                       highlightthickness=1)
        self._verdict_card.pack(fill="x", padx=24, pady=(10, 0))
        self._verdict_var = tk.StringVar(
            value="Paste an email above and click 'Analyse Email' to begin")
        self._verdict_lbl = tk.Label(
            self._verdict_card, textvariable=self._verdict_var,
            bg=C["white"], fg=C["txt_light"],
            font=(FF, 11), wraplength=950, justify="left")
        self._verdict_lbl.pack(padx=20, pady=12)

        self._model_row = tk.Frame(p, bg=C["bg"])
        self._model_row.pack(fill="x", padx=24, pady=(8, 0))

        # ── Explanation ─────────────────────────────────────
        ecard = tk.Frame(p, bg=C["white"],
                          highlightbackground=C["border"], highlightthickness=1)
        ecard.pack(fill="both", expand=True, padx=24, pady=(8, 20))
        eh = tk.Frame(ecard, bg=C["white"]); eh.pack(fill="x", padx=16, pady=(12, 4))
        tk.Label(eh, text="🤖  AI Explanation (SHAP + Rule-based)",
                 bg=C["white"], fg=C["txt_dark"],
                 font=(FF, 10, "bold")).pack(anchor="w")
        self._exp_text = scrolledtext.ScrolledText(
            ecard, height=9, bg="#FAFBFC", fg=C["txt_dark"],
            font=(FF, 10), relief="flat", padx=14, pady=10,
            state="disabled", wrap="word")
        self._exp_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _load_sample(self, name):
        self._email_in.delete("1.0", "end")
        self._email_in.insert("1.0", SAMPLE_EMAILS[name])

    def _load_from_outlook(self):
        """Fetch the 10 most recent inbox emails from Outlook."""
        if not OUTLOOK_AVAILABLE:
            messagebox.showinfo("Outlook N/A",
                "win32com not installed.\npip install pywin32"); return
        try:
            outlook = win32com.client.Dispatch("Outlook.Application")
            ns      = outlook.GetNamespace("MAPI")
            inbox   = ns.GetDefaultFolder(6)   # 6 = inbox
            msgs    = sorted(inbox.Items, key=lambda m: m.ReceivedTime, reverse=True)[:10]

            # Show picker
            win = tk.Toplevel(self)
            win.title("Select Outlook Email")
            win.geometry("600x400")
            win.configure(bg=C["bg"])
            tk.Label(win, text="Select an email to analyse:",
                     bg=C["bg"], fg=C["txt_dark"], font=(FF,10,"bold")
                     ).pack(padx=16, pady=(12,4), anchor="w")
            lb = tk.Listbox(win, bg=C["white"], fg=C["txt_dark"],
                            font=(FF,9), relief="solid", bd=1,
                            selectbackground=C["orange_lt"],
                            selectforeground=C["orange"])
            lb.pack(fill="both", expand=True, padx=16, pady=8)
            for i, m in enumerate(msgs):
                try:    lb.insert("end", f"{i+1}. [{m.SenderName}] {m.Subject}")
                except: lb.insert("end", f"{i+1}. (unreadable)")

            def load_selected():
                sel = lb.curselection()
                if not sel: return
                m   = msgs[sel[0]]
                try:
                    body = f"Subject: {m.Subject}\nFrom: {m.SenderName} <{m.SenderEmailAddress}>\n\n{m.Body}"
                except:
                    body = str(m)
                self._email_in.delete("1.0", "end")
                self._email_in.insert("1.0", body[:5000])
                win.destroy()

            make_btn(win, "Load Selected →", load_selected, C["orange"]).pack(pady=8)
        except Exception as e:
            messagebox.showerror("Outlook Error", str(e))

    def _do_analyse(self):
        text = self._email_in.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("Empty", "Paste an email to analyse."); return
        if not self._trained:
            messagebox.showinfo("Not Trained",
                "No trained model is available yet.\n"
                "Load datasets and train models first, or use Demo Fallback."); return

        sel = self._analyse_model_var.get()
        model_name = None if sel == "Best Model" else sel

        def worker():
            self._status_var.set("Analysing…")
            try:
                pred = self.detector.predict(text, model_name=model_name)
                shap = self.detector.explain_shap(text, model_name=model_name)
                exp  = self.detector.generate_explanation(text, pred, shap)
                # Update stats
                self._stats["total"] += 1
                if pred["prediction"] == 1: self._stats["phish"] += 1
                else:                       self._stats["legit"] += 1
                wk = self._stats["weekly"]
                wk[-1] = wk[-1] + 1
                # Add to chat
                self._chat_hist.append(
                    ("user", f"Analyse: {text[:120]}…"))
                self._chat_hist.append(("bot", exp))
                self.after(0, lambda: self._show_result(pred, exp))
                self.after(0, self._update_kpis)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, lambda: self._status_var.set("Ready"))

        threading.Thread(target=worker, daemon=True).start()

    def _show_result(self, pred: dict, exp: str):
        label  = pred["label"]
        conf   = pred["confidence"]
        colour = C["red"] if label == "PHISHING" else C["green"]
        emoji  = "⚠️" if label == "PHISHING" else "✅"
        self._verdict_card.configure(highlightbackground=colour, highlightthickness=2)
        self._verdict_var.set(
            f"{emoji}  {label}  —  {conf:.0f}% confidence   |   "
            f"Primary model: {pred['model']}")
        self._verdict_lbl.configure(fg=colour, font=(FF, 13, "bold"))
        # Per-model chips
        for w in self._model_row.winfo_children(): w.destroy()
        for name, res in pred["all_models"].items():
            mc   = C["red"] if res["label"]=="PHISHING" else C["green"]
            chip = tk.Frame(self._model_row, bg=C["white"],
                            highlightbackground=mc, highlightthickness=2)
            chip.pack(side="left", expand=True, fill="both", padx=(0, 8))
            tk.Frame(chip, bg=mc, height=3).pack(fill="x")
            tk.Label(chip, text=name.replace(" (LinearSVC)",""),
                     bg=C["white"], fg=C["txt_mid"], font=(FF, 8)).pack(pady=(6,2))
            tk.Label(chip, text=res["label"], bg=C["white"],
                     fg=mc, font=(FF, 10, "bold")).pack()
            tk.Label(chip, text=f"{res['confidence']:.0f}%",
                     bg=C["white"], fg=C["txt_light"], font=(FF, 8)).pack(pady=(0,8))
        # Explanation
        self._exp_text.configure(state="normal")
        self._exp_text.delete("1.0","end")
        self._exp_text.insert("1.0", exp)
        self._exp_text.configure(state="disabled")

    # ══════════════════════════════════════════════════════
    #  PAGE: CHATBOT
    # ══════════════════════════════════════════════════════

    def _page_chatbot(self):
        p = self._new_page("chatbot")

        # Info bar
        ibar = tk.Frame(p, bg=C["white"],
                         highlightbackground=C["border"], highlightthickness=1)
        ibar.pack(fill="x", padx=24, pady=(20, 0))
        irow = tk.Frame(ibar, bg=C["white"]); irow.pack(fill="x", padx=16, pady=12)
        tk.Label(irow, text="🤖", bg=C["white"], fg=C["orange"],
                 font=(FF, 22)).pack(side="left")
        tf = tk.Frame(irow, bg=C["white"]); tf.pack(side="left", padx=10)
        tk.Label(tf, text="PhishGuard AI Assistant",
                 bg=C["white"], fg=C["txt_dark"],
                 font=(FF, 12, "bold")).pack(anchor="w")
        tk.Label(tf,
                 text="Ask about phishing, submit emails for analysis, "
                      "or request a phishing awareness quiz.",
                 bg=C["white"], fg=C["txt_light"], font=(FF, 9)).pack(anchor="w")

        # Chat display
        chat_card = tk.Frame(p, bg=C["white"],
                              highlightbackground=C["border"], highlightthickness=1)
        chat_card.pack(fill="both", expand=True, padx=24, pady=10)

        self._chat_disp = scrolledtext.ScrolledText(
            chat_card, bg=C["white"], fg=C["txt_dark"],
            font=(FF, 10), relief="flat",
            padx=16, pady=12, state="disabled", wrap="word")
        self._chat_disp.pack(fill="both", expand=True)
        self._chat_disp.tag_configure("bot_name",
            foreground=C["orange"], font=(FF, 9, "bold"))
        self._chat_disp.tag_configure("user_name",
            foreground=C["blue"], font=(FF, 9, "bold"))
        self._chat_disp.tag_configure("bot_msg",
            foreground=C["txt_dark"], font=(FF, 10))
        self._chat_disp.tag_configure("user_msg",
            foreground=C["txt_mid"], font=(FF, 10))

        # Input row
        inp_row = tk.Frame(chat_card, bg=C["white"])
        inp_row.pack(fill="x", padx=12, pady=12)
        self._chat_in = tk.Entry(
            inp_row, bg="#FAFBFC", fg=C["txt_dark"],
            font=(FF, 10), relief="solid", bd=1,
            insertbackground=C["txt_dark"])
        self._chat_in.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        self._chat_in.bind("<Return>", lambda e: self._send_chat())
        make_btn(inp_row, "Send  ▶", self._send_chat, C["orange"]).pack(side="left")

        # Quick prompts
        qrow = tk.Frame(p, bg=C["bg"]); qrow.pack(fill="x", padx=24, pady=(0, 16))
        for prompt in [
            "What are phishing signs?",
            "Analyse the email I pasted",
            "How does SHAP work?",
            "Quiz me on phishing",
            "What is URL obfuscation?",
        ]:
            tk.Button(qrow, text=prompt,
                      bg=C["white"], fg=C["blue"],
                      font=(FF, 9), relief="solid", bd=1,
                      padx=10, pady=4, cursor="hand2",
                      command=lambda q=prompt: self._quick_prompt(q)
                      ).pack(side="left", padx=4)

        # Welcome
        self._bot_msg(
            "Hello! I am PhishGuard AI — your phishing awareness assistant.\n\n"
            "You can:\n"
            "• Paste an email and ask me to analyse it\n"
            "• Ask 'What are signs of phishing?'\n"
            "• Request a phishing awareness quiz\n"
            "• Ask how SHAP or LIME explain my decisions\n\n"
            "How can I help you today?")

    def _bot_msg(self, text: str):
        self._chat_disp.configure(state="normal")
        self._chat_disp.insert("end", "\nPhishGuard AI:  ", "bot_name")
        self._chat_disp.insert("end", text + "\n", "bot_msg")
        self._chat_disp.configure(state="disabled")
        self._chat_disp.see("end")

    def _user_msg(self, text: str):
        self._chat_disp.configure(state="normal")
        self._chat_disp.insert("end", "\nYou:  ", "user_name")
        self._chat_disp.insert("end", text + "\n", "user_msg")
        self._chat_disp.configure(state="disabled")
        self._chat_disp.see("end")

    def _send_chat(self):
        msg = self._chat_in.get().strip()
        if not msg: return
        self._chat_in.delete(0, "end")
        self._user_msg(msg)
        threading.Thread(target=lambda: self._process_chat(msg), daemon=True).start()

    def _quick_prompt(self, prompt):
        self._chat_in.delete(0, "end")
        self._chat_in.insert(0, prompt)
        self._send_chat()

    def _process_chat(self, msg: str):
        resp = self._chat_response(msg)
        self.after(0, lambda: self._bot_msg(resp))

    def _chat_response(self, msg: str) -> str:
        m = msg.lower()
        if any(k in m for k in ["analyse","analyze","check","classify"]):
            txt = self._email_in.get("1.0","end").strip() if hasattr(self,"_email_in") else ""
            if txt and self._trained:
                pred = self.detector.predict(txt)
                return self.detector.generate_explanation(txt, pred)
            return "Paste an email in the Analyse tab first, then ask me to classify it."
        if "sign" in m or "indicator" in m or "spot" in m:
            return (
                "Common Phishing Indicators:\n\n"
                "1. Urgency & Threats — 'Your account will be suspended!'\n"
                "2. Suspicious Sender — domain does not match the company\n"
                "3. Suspicious URLs — hover to reveal the real destination\n"
                "4. Poor Grammar — unusual spelling, odd phrasing\n"
                "5. Unusual Requests — asking for passwords or OTPs\n"
                "6. Generic Greetings — 'Dear Customer' instead of your name\n\n"
                "Always verify suspicious emails by contacting the sender directly."
            )
        if "shap" in m:
            return (
                "SHAP (SHapley Additive exPlanations) explains my decisions:\n\n"
                "• Positive SHAP value → word pushes toward PHISHING\n"
                "• Negative SHAP value → word pushes toward LEGITIMATE\n\n"
                "Example: 'click here' might have SHAP +0.25, meaning it strongly "
                "increased the phishing probability.\n\n"
                "SHAP is grounded in cooperative game theory (Shapley values), "
                "ensuring consistent and theoretically justified attributions."
            )
        if "lime" in m:
            return (
                "LIME (Local Interpretable Model-agnostic Explanations):\n\n"
                "LIME explains individual predictions by creating a simplified "
                "linear model around each email.\n\n"
                "It works by:\n"
                "1. Masking/replacing words in your email\n"
                "2. Observing how my prediction changes\n"
                "3. Fitting a simple model to approximate the decision boundary\n\n"
                "This reveals which specific words drove the classification."
            )
        if "quiz" in m:
            return (
                "Phishing Awareness Quiz — Question 1:\n\n"
                "An email from 'support@paypa1.com' asks you to verify your "
                "PayPal account urgently.\n\n"
                "Is this:\n"
                "A) Legitimate — PayPal often verifies accounts\n"
                "B) Phishing — 'paypa1.com' uses '1' instead of 'l'\n"
                "C) Spam — unsolicited but harmless\n\n"
                "Type A, B, or C to answer!"
            )
        if msg.strip().upper() in ["A","B","C"]:
            if "B" in msg.upper():
                return "✅ Correct! 'paypa1.com' is typosquatting — replacing 'l' with '1'. Always inspect sender domains carefully."
            return "❌ The answer is B — 'paypa1.com' uses '1' instead of 'l', a classic phishing trick."
        if "url obfuscat" in m:
            return (
                "URL Obfuscation Techniques:\n\n"
                "• Typosquatting: paypa1.com, g00gle.com\n"
                "• Subdomains: paypal.com.evil-site.com\n"
                "• URL shorteners: bit.ly hides the real destination\n"
                "• Lookalike characters: рауpal.com (Cyrillic 'р')\n"
                "• Long URLs: real-paypal.com-secure.verify.phishing.com\n\n"
                "Tip: Always hover over links to see the full URL before clicking."
            )
        return (
            "I can help with:\n\n"
            "• Email Analysis — paste email in Analyse tab\n"
            "• Phishing Signs — ask 'What are phishing indicators?'\n"
            "• XAI — ask 'How does SHAP work?'\n"
            "• Quiz — ask 'Quiz me on phishing'\n"
            "• URL Safety — ask 'What is URL obfuscation?'\n\n"
            f"You said: '{msg[:80]}' — please rephrase or choose a topic above."
        )

    # ══════════════════════════════════════════════════════
    #  PAGE: MODEL METRICS
    # ══════════════════════════════════════════════════════

    def _page_metrics(self):
        p = self._new_page("metrics")

        # Control bar
        cbar = tk.Frame(p, bg=C["white"],
                         highlightbackground=C["border"], highlightthickness=1)
        cbar.pack(fill="x", padx=24, pady=(20, 0))
        crow = tk.Frame(cbar, bg=C["white"]); crow.pack(fill="x", padx=16, pady=12)
        tk.Label(crow, text="Model Performance", bg=C["white"],
                 fg=C["txt_dark"], font=(FF, 11, "bold")).pack(side="left")
        make_btn(crow, "🚀  Train All Models", self._run_training, C["orange"]).pack(side="right")
        make_btn(crow, "🧪  Use Demo Fallback", self._train_demo_fallback, C["amber"]
                 ).pack(side="right", padx=(0, 8))
        make_btn(crow, "📂  Load Datasets First",
                 lambda: self._navigate("datasets"), C["blue"]
                 ).pack(side="right", padx=(0, 8))

        self._train_prog_var = tk.StringVar(value="Load datasets then click Train")
        tk.Label(cbar, textvariable=self._train_prog_var,
                 bg=C["white"], fg=C["txt_light"], font=(FF, 9)
                 ).pack(anchor="w", padx=16, pady=(0, 4))
        self._train_pb = ttk.Progressbar(cbar, mode="indeterminate",
                                          style="Horizontal.TProgressbar", length=500)
        self._train_pb.pack(anchor="w", padx=16, pady=(0, 12))

        # Scrollable metrics area
        outer = tk.Frame(p, bg=C["bg"]); outer.pack(fill="both", expand=True, padx=24, pady=12)
        canvas = tk.Canvas(outer, bg=C["bg"], highlightthickness=0)
        vsb    = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y"); canvas.pack(fill="both", expand=True)
        self._metrics_inner = tk.Frame(canvas, bg=C["bg"])
        canvas.create_window((0, 0), window=self._metrics_inner, anchor="nw")
        self._metrics_inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        tk.Label(self._metrics_inner,
                 text="Train models to view evaluation results.",
                 bg=C["bg"], fg=C["txt_light"], font=(FF, 12)).pack(pady=40)

    def _run_training(self):
        if not self._has_uploaded_data or self._df is None:
            messagebox.showinfo(
                "Upload Required",
                "On first startup, upload datasets first and then train.\n"
                "Use 'Demo Fallback' only when you need a temporary model."
            )
            return

        def worker():
            self.after(0, self._train_pb.start)
            cb = lambda m: self.after(0, lambda msg=m: self._train_prog_var.set(msg))
            try:
                self.detector = PhishingDetector(max_features=10000)
                self.detector.fit(self._df, test_size=0.2, cv_folds=5, progress_cb=cb)
                self._trained = True
                self.after(0, self._on_trained)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Training Error", str(e)))
            finally:
                self.after(0, self._train_pb.stop)

        threading.Thread(target=worker, daemon=True).start()

    def _train_demo_fallback(self):
        msg = (
            "This will train on the built-in demo emails.\n\n"
            "Use this only as a temporary fallback. Production training should use uploaded datasets.\n\n"
            "Continue?"
        )
        if not messagebox.askyesno("Use Demo Fallback", msg):
            return
        self._load_demo_data(as_fallback=True)

    def _on_trained(self):
        for w in self._metrics_inner.winfo_children(): w.destroy()
        valid = {k: v for k, v in self.detector.results.items() if "f1" in v}
        best  = self.detector.best_model()

        if best and best in valid:
            br = valid[best]
            banner = tk.Frame(self._metrics_inner, bg=C["green_lt"],
                               highlightbackground=C["green"], highlightthickness=2)
            banner.pack(fill="x", pady=(0, 12))
            tk.Label(banner,
                     text=f"🏆  Best Model: {best}  —  "
                          f"F1={br['f1']:.4f}   Accuracy={br['accuracy']:.4f}   "
                          f"AUC={br['auc']:.4f}",
                     bg=C["green_lt"], fg=C["green"],
                     font=(FF, 11, "bold")).pack(pady=10)

        for (name, res), colour in zip(valid.items(), MODEL_COLOURS * 3):
            card = tk.Frame(self._metrics_inner, bg=C["white"],
                            highlightbackground=colour, highlightthickness=2)
            card.pack(fill="x", pady=8)
            hdr = tk.Frame(card, bg=colour); hdr.pack(fill="x")
            tk.Label(hdr, text=f"  {name}", bg=colour, fg="white",
                     font=(FF, 10, "bold")).pack(side="left", pady=8)
            cm = res.get("cm")
            if cm is not None and cm.shape == (2, 2):
                tn, fp, fn, tp = cm.ravel()
                tk.Label(hdr, text=f"TP:{tp}  FP:{fp}  FN:{fn}  TN:{tn}",
                         bg=colour, fg="white", font=(FF, 9)).pack(side="right", padx=12)
            mrow = tk.Frame(card, bg=C["white"]); mrow.pack(fill="x", padx=16, pady=10)
            for lbl, key, mc in [
                ("Accuracy","accuracy",C["blue"]),("Precision","precision",C["green"]),
                ("Recall","recall",C["orange"]),("F1","f1",C["purple"]),("AUC","auc",C["red"]),
            ]:
                val = res.get(key, 0)
                cf  = tk.Frame(mrow, bg=C["white"]); cf.pack(side="left", expand=True)
                tk.Label(cf, text=lbl, bg=C["white"], fg=C["txt_light"], font=(FF, 8)).pack()
                tk.Label(cf, text=f"{val:.4f}", bg=C["white"], fg=mc,
                         font=(FF, 14, "bold")).pack()
                track = tk.Frame(cf, bg=C["border"], height=4, width=80)
                track.pack(); track.pack_propagate(False)
                tk.Frame(track, bg=mc, height=4, width=max(2, int(val*80))).place(x=0, y=0)
            cv = self.detector.cv_scores.get(name)
            if cv is not None:
                cvf = tk.Frame(card, bg=C["bg"]); cvf.pack(fill="x", padx=16, pady=(0,10))
                tk.Label(cvf,
                         text=f"5-Fold CV F1: {cv.mean():.4f} ± {cv.std():.4f}",
                         bg=C["bg"], fg=colour, font=(FF, 9, "bold")).pack(anchor="w")

        self._badge_var.set(f"✅ Trained  |  Best: {best}")
        self._badge.configure(bg=C["green"])
        self._train_prog_var.set(f"✅ Training complete. Best: {best}")
        self._status_var.set(f"Trained. Best: {best}")
        self._draw_charts()

    # ══════════════════════════════════════════════════════
    #  PAGE: XAI CHARTS
    # ══════════════════════════════════════════════════════

    def _page_charts(self):
        p = self._new_page("charts")
        ctrl = tk.Frame(p, bg=C["white"],
                         highlightbackground=C["border"], highlightthickness=1)
        ctrl.pack(fill="x", padx=24, pady=(20, 0))
        crow = tk.Frame(ctrl, bg=C["white"]); crow.pack(fill="x", padx=16, pady=10)
        tk.Label(crow, text="Select Chart:", bg=C["white"],
                 fg=C["txt_mid"], font=(FF, 9, "bold")).pack(side="left")
        self._chart_sel = tk.StringVar(value="All Charts")
        ttk.Combobox(crow, textvariable=self._chart_sel, state="readonly",
                     values=["All Charts","ROC Curves","Confusion Matrices",
                             "Feature Importance","K-Fold CV","Metrics Comparison"],
                     font=(FF, 9), width=22).pack(side="left", padx=8)
        make_btn(crow, "🔃  Refresh", self._draw_charts, C["orange"]).pack(side="left")
        self._charts_fig    = plt.Figure(figsize=(13, 8), facecolor=C["white"])
        self._charts_canvas = FigureCanvasTkAgg(self._charts_fig, master=p)
        self._charts_canvas.get_tk_widget().configure(
            highlightthickness=1, highlightbackground=C["border"])
        self._charts_canvas.get_tk_widget().pack(
            fill="both", expand=True, padx=24, pady=12)

    def _draw_charts(self):
        if not self.detector.is_trained(): return
        self._charts_fig.clear()
        self._charts_fig.patch.set_facecolor(C["white"])
        set_chart_style()
        valid = {k: v for k, v in self.detector.results.items() if "f1" in v}
        sel   = self._chart_sel.get()
        COLS  = MODEL_COLOURS

        if sel == "ROC Curves":
            self._draw_roc(self._charts_fig.add_subplot(111), valid, COLS)
        elif sel == "Confusion Matrices":
            n = len(valid)
            for i, (name, res) in enumerate(valid.items()):
                self._draw_cm(self._charts_fig.add_subplot(1,n,i+1), res.get("cm"), name)
        elif sel == "Feature Importance":
            self._draw_feat_imp(self._charts_fig.add_subplot(111))
        elif sel == "K-Fold CV":
            self._draw_kfold(self._charts_fig.add_subplot(111))
        elif sel == "Metrics Comparison":
            self._draw_metrics_bar(self._charts_fig.add_subplot(111), valid, COLS)
        else:
            gs = GridSpec(2, 3, figure=self._charts_fig, hspace=0.58, wspace=0.44)
            self._draw_roc(self._charts_fig.add_subplot(gs[0,0]), valid, COLS)
            self._draw_metrics_bar(self._charts_fig.add_subplot(gs[0,1]), valid, COLS)
            self._draw_kfold(self._charts_fig.add_subplot(gs[0,2]))
            self._draw_feat_imp(self._charts_fig.add_subplot(gs[1,0]))
            best = self.detector.best_model()
            if best and "cm" in valid.get(best, {}):
                self._draw_cm(self._charts_fig.add_subplot(gs[1,1]),
                               valid[best]["cm"], f"Best: {best.split()[0]}")
            self._draw_pr(self._charts_fig.add_subplot(gs[1,2]), valid, COLS)
        self._charts_canvas.draw()

    def _draw_roc(self, ax, valid, COLS):
        ax.plot([0,1],[0,1],"--",color=C["txt_light"],lw=1.2,label="Random (0.50)")
        for (name,res),col in zip(valid.items(),COLS):
            fpr,tpr = res.get("fpr"),res.get("tpr")
            if fpr is not None:
                ax.plot(fpr,tpr,lw=2.5,color=col,label=f"{name.split()[0]} {res['auc']:.3f}")
                ax.fill_between(fpr,tpr,alpha=0.07,color=col)
        ax.set_xlim([0,1]); ax.set_ylim([0,1.02])
        ax.set_xlabel("FPR"); ax.set_ylabel("TPR")
        ax.set_title("ROC Curves",pad=6); ax.legend(fontsize=7)
        ax.yaxis.grid(True,alpha=0.4)

    def _draw_pr(self, ax, valid, COLS):
        for (name,res),col in zip(valid.items(),COLS):
            pre,rec = res.get("pre"),res.get("rec")
            if pre is not None:
                ax.plot(rec,pre,lw=2.5,color=col,label=name.split()[0])
                ax.fill_between(rec,pre,alpha=0.07,color=col)
        ax.set_xlim([0,1]); ax.set_ylim([0,1.02])
        ax.set_xlabel("Recall"); ax.set_ylabel("Precision")
        ax.set_title("Precision-Recall",pad=6); ax.legend(fontsize=7)
        ax.yaxis.grid(True,alpha=0.4)

    def _draw_cm(self, ax, cm, title):
        if cm is None: return
        ax.imshow(cm, cmap="Oranges", aspect="auto")
        ax.set_xticks([0,1]); ax.set_yticks([0,1])
        ax.set_xticklabels(["Legit","Phish"],fontsize=8)
        ax.set_yticklabels(["Legit","Phish"],fontsize=8)
        ax.set_xlabel("Predicted",fontsize=8); ax.set_ylabel("Actual",fontsize=8)
        lbl=["TN","FP","FN","TP"]
        for i in range(2):
            for j in range(2):
                v=cm[i,j]; tc="white" if v>cm.max()/2 else C["txt_dark"]
                ax.text(j,i-0.15,f"{v:,}",ha="center",fontsize=12,fontweight="bold",color=tc)
                ax.text(j,i+0.2,f"({lbl[i*2+j]})",ha="center",fontsize=7,color=C["txt_light"])
        ax.set_title(f"CM — {title.split()[0]}",pad=4,fontsize=9)

    def _draw_feat_imp(self, ax):
        imp = self.detector.get_feature_importance(top_n=15)
        if not imp:
            ax.text(0.5,0.5,"Train first",ha="center",va="center",
                     color=C["txt_light"],transform=ax.transAxes); return
        items = sorted(imp.items(),key=lambda x:x[1])
        feats=[i[0] for i in items]; vals=[i[1] for i in items]
        clrs=[C["red"] if v>0 else C["green"] for v in vals]
        ax.barh(feats,vals,color=clrs,alpha=0.85)
        ax.axvline(0,color=C["txt_light"],lw=1,ls="--")
        ax.set_title("Feature Importance\n(red=Phishing, green=Legit)",pad=6,fontsize=9)
        ax.xaxis.grid(True,alpha=0.4)

    def _draw_kfold(self, ax):
        cv = self.detector.cv_scores
        if not cv:
            ax.text(0.5,0.5,"No CV data",ha="center",va="center",
                     color=C["txt_light"],transform=ax.transAxes); return
        names=list(cv.keys()); scores=[cv[n] for n in names]
        bp = ax.boxplot(scores,patch_artist=True,
                         medianprops=dict(color="white",linewidth=2.5),
                         whiskerprops=dict(color=C["txt_light"]),
                         capprops=dict(color=C["txt_light"]))
        for patch,col in zip(bp["boxes"],MODEL_COLOURS):
            patch.set_facecolor(col); patch.set_alpha(0.8)
        for i,(sl,col) in enumerate(zip(scores,MODEL_COLOURS),1):
            ax.scatter(np.full_like(sl,i)+np.random.normal(0,0.04,len(sl)),
                        sl,color=col,s=30,zorder=5,edgecolors="white",lw=0.5)
            ax.text(i,np.mean(sl)+0.004,f"μ={np.mean(sl):.3f}",
                     ha="center",fontsize=7,color=C["txt_mid"],fontweight="bold")
        ax.set_xticks(range(1,len(names)+1))
        ax.set_xticklabels([n.split()[0] for n in names],fontsize=8,rotation=10)
        ax.set_ylim(0,1.08); ax.set_ylabel("F1-Score")
        ax.set_title("5-Fold CV F1 Scores",pad=6,fontsize=9)
        ax.yaxis.grid(True,alpha=0.4)

    def _draw_metrics_bar(self, ax, valid, COLS):
        mkeys=["accuracy","precision","recall","f1","auc"]
        mlbls=["Acc","Prec","Rec","F1","AUC"]
        mclrs=[C["blue"],C["green"],C["orange"],C["purple"],C["red"]]
        x=np.arange(len(valid)); w=0.14
        for i,(mk,mc,ml) in enumerate(zip(mkeys,mclrs,mlbls)):
            vals=[v.get(mk,0) for v in valid.values()]
            bars=ax.bar(x+i*w,vals,w,label=ml,color=mc,alpha=0.85)
            for bar,val in zip(bars,vals):
                ax.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.006,
                        f"{val:.2f}",ha="center",va="bottom",fontsize=5.5,color=C["txt_mid"])
        ax.set_xticks(x+w*2)
        ax.set_xticklabels([k.split()[0] for k in valid.keys()],fontsize=8,rotation=6)
        ax.set_ylim(0,1.18); ax.set_title("Metrics Comparison",pad=6,fontsize=9)
        ax.legend(fontsize=7,ncol=5); ax.yaxis.grid(True,alpha=0.4)

    # ══════════════════════════════════════════════════════
    #  PAGE: DATASETS
    # ══════════════════════════════════════════════════════

    def _page_datasets(self):
        p = self._new_page("datasets")
        dcard = tk.Frame(p, bg=C["white"],
                          highlightbackground=C["border"], highlightthickness=1)
        dcard.pack(fill="x", padx=24, pady=(20, 0))
        drow = tk.Frame(dcard, bg=C["white"]); drow.pack(fill="x", padx=16, pady=12)
        tk.Label(drow, text="Dataset Management", bg=C["white"],
                 fg=C["txt_dark"], font=(FF, 11, "bold")).pack(side="left")
        make_btn(drow,"📂  Load CSV/XLSX Files",self._load_datasets,C["orange"]).pack(side="right")
        make_btn(drow,"📁  Load Folder",self._load_folder,C["blue"]).pack(side="right",padx=(0,8))

        note = tk.Frame(dcard,bg=C["orange_lt"]); note.pack(fill="x",padx=16,pady=(0,12))
        tk.Label(note,
                 text="ℹ  Accepted: CSV, XLSX — needs a text/email column and "
                      "label column (0=legit, 1=phishing).\n"
                      "  Datasets used: Enron (legit) · Kaggle · CEAS · Nazario · "
                      "Nigerian Fraud · SpamAssassin (phishing)",
                 bg=C["orange_lt"], fg=C["orange"], font=(FF,9),
                 wraplength=900, justify="left").pack(padx=12, pady=8)

        # Info cards
        irow = tk.Frame(p,bg=C["bg"]); irow.pack(fill="x",padx=24,pady=12)
        self._ds_vars = {}
        for label,key in [("Files Loaded","files"),("Total Emails","total"),
                           ("Phishing","phish"),("Legitimate","legit"),("Rate","rate")]:
            c2 = tk.Frame(irow,bg=C["white"],
                          highlightbackground=C["border"],highlightthickness=1)
            c2.pack(side="left",expand=True,fill="both",padx=(0,12))
            tk.Label(c2,text=label,bg=C["white"],fg=C["txt_light"],font=(FF,8)
                     ).pack(pady=(10,2))
            v=tk.StringVar(value="—"); self._ds_vars[key]=v
            tk.Label(c2,textvariable=v,bg=C["white"],fg=C["txt_dark"],
                     font=(FF,14,"bold")).pack(pady=(0,10))

        # Log
        tk.Label(p,text="Load Log",bg=C["bg"],fg=C["txt_light"],
                 font=(FF,9,"bold")).pack(anchor="w",padx=24)
        log_card = tk.Frame(p,bg=C["white"],
                             highlightbackground=C["border"],highlightthickness=1)
        log_card.pack(fill="both",expand=True,padx=24,pady=(4,24))
        self._ds_log = scrolledtext.ScrolledText(
            log_card,height=10,bg="#FAFBFC",fg=C["txt_mid"],
            font=(MONO,8),relief="flat",padx=12)
        self._ds_log.pack(fill="both",expand=True)

    def _load_datasets(self):
        paths = filedialog.askopenfilenames(
            title="Select Email Dataset Files",
            filetypes=[("CSV/Excel","*.csv *.xlsx *.xls"),
                       ("CSV","*.csv"),("Excel","*.xlsx"),("All","*.*")])
        if paths: self._do_load(list(paths))

    def _load_folder(self):
        folder = filedialog.askdirectory(title="Select folder with email datasets")
        if folder:
            import glob
            paths = glob.glob(os.path.join(folder,"**/*.csv"),recursive=True)
            paths+= glob.glob(os.path.join(folder,"**/*.xlsx"),recursive=True)
            if paths: self._do_load(paths)

    def _do_load(self, paths: list):
        def worker():
            self._status_var.set("Loading datasets…")
            loaded_ok = False
            try:
                loader = PhishingDataLoader()
                df     = loader.load_files(paths)
                self._df = df
                self._has_uploaded_data = True
                loaded_ok = True
                self.after(0, lambda: self._update_ds_info(df, loader))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Load Error", str(e)))
            finally:
                if not loaded_ok:
                    self.after(0, lambda: self._status_var.set("Ready"))
        threading.Thread(target=worker, daemon=True).start()

    def _update_ds_info(self, df, loader):
        n  = len(df)
        nf = int((df["label"]==1).sum())
        self._ds_vars["files"].set(str(len(loader.file_stats)))
        self._ds_vars["total"].set(f"{n:,}")
        self._ds_vars["phish"].set(f"{nf:,}")
        self._ds_vars["legit"].set(f"{n-nf:,}")
        self._ds_vars["rate"].set(f"{nf/max(1,n)*100:.2f}%")
        self._ds_log.configure(state="normal")
        self._ds_log.delete("1.0","end")
        for ln in loader.load_report: self._ds_log.insert("end",ln+"\n")
        self._ds_log.configure(state="disabled")
        self._status_var.set(f"Loaded {n:,} emails. Go to Models tab to train.")

    # ══════════════════════════════════════════════════════
    #  PAGE: SETTINGS
    # ══════════════════════════════════════════════════════

    def _page_settings(self):
        p = self._new_page("settings")
        mcard = tk.Frame(p,bg=C["white"],
                          highlightbackground=C["border"],highlightthickness=1)
        mcard.pack(fill="x",padx=24,pady=20)
        tk.Label(mcard,text="Model Configuration",bg=C["white"],
                 fg=C["txt_dark"],font=(FF,11,"bold")).pack(anchor="w",padx=16,pady=(14,4))
        self._cfg = {}
        for label,default,key in [
            ("Max TF-IDF Features","10000","max_features"),
            ("Test Split (0.1–0.4)","0.2","test_size"),
            ("CV Folds","5","cv_folds"),
            ("Outlook Mailbox (optional)","","outlook_folder"),
        ]:
            row = tk.Frame(mcard,bg=C["white"]); row.pack(fill="x",padx=16,pady=6)
            tk.Label(row,text=label,bg=C["white"],fg=C["txt_mid"],
                     font=(FF,9),width=30,anchor="w").pack(side="left")
            v=tk.StringVar(value=default); self._cfg[key]=v
            tk.Entry(row,textvariable=v,bg="#FAFBFC",fg=C["txt_dark"],
                     relief="solid",bd=1,font=(FF,9),width=28).pack(side="left")
        make_btn(mcard,"💾  Save Settings",
                 lambda: messagebox.showinfo("Saved","Settings saved."),
                 C["orange"]).pack(anchor="w",padx=16,pady=16)

        # About (Banner ID only)
        acard = tk.Frame(p,bg=C["white"],
                          highlightbackground=C["border"],highlightthickness=1)
        acard.pack(fill="x",padx=24,pady=(0,24))
        tk.Label(acard,text="About",bg=C["white"],
                 fg=C["txt_dark"],font=(FF,11,"bold")).pack(anchor="w",padx=16,pady=(14,4))
        tk.Label(acard,
                 text=f"Banner ID      : {BANNER_ID}\n"
                      f"Programme      : {PROGRAMME}\n"
                      f"University     : {UNIVERSITY}\n\n"
                      f"Title          : {TITLE_LONG}\n\n"
                      f"Models         : Logistic Regression · Decision Tree · "
                      f"SVM · Naïve Bayes · Random Forest\n"
                      f"XAI            : SHAP · LIME · Prompt-based LLM Explanations\n"
                      f"Datasets       : Enron · Kaggle · CEAS · Nazario · "
                      f"Nigerian Fraud · SpamAssassin\n"
                      f"Gmail          : Browser extension (see extension/ folder)\n"
                      f"Outlook        : Native win32com integration (Windows only)",
                 bg=C["white"],fg=C["txt_light"],font=(FF,9),justify="left"
                 ).pack(anchor="w",padx=16,pady=(0,16))

    # ══════════════════════════════════════════════════════
    #  STARTUP + DEMO FALLBACK
    # ══════════════════════════════════════════════════════

    def _set_startup_upload_required_state(self):
        self._badge_var.set("⚠ Upload Data")
        self._badge.configure(bg=C["amber"])
        self._status_var.set("Upload datasets first, then train models.")
        if hasattr(self, "_train_prog_var"):
            self._train_prog_var.set("Startup requires uploaded datasets before training.")

    def _load_demo_data(self, as_fallback: bool = False):
        def worker():
            time.sleep(0.3)
            legit = [
                "Dear team, please find attached the Q3 financial report. Meeting Thursday 2pm.",
                "Hi Sarah, can we reschedule our call to Friday afternoon?",
                "Your order has been confirmed and will ship within 2 business days.",
                "Please submit your expense reports by end of day Friday for processing.",
                "System maintenance window: Sunday 2am to 4am. Email and VPN unavailable.",
                "Welcome to the team! Your onboarding documents are attached. Start Monday.",
                "Q4 budget approval has been granted. Please proceed with expenditures.",
                "Meeting notes from yesterday are attached. Action items highlighted.",
                "Your leave request for December 23-27 has been approved by HR.",
                "Project delivery deadline extended to January 15th per client request.",
                "Please find the attached invoice. Payment is due within 30 days.",
                "Following up on last week's conversation regarding the merger timeline.",
            ] * 16
            phish = [
                "URGENT: Your account has been SUSPENDED! Click here IMMEDIATELY: http://paypal-secure.evil.com",
                "Congratulations! You WON £5000! Claim NOW before expiry: http://prize.fake.net",
                "Your password EXPIRES TODAY. Reset immediately: http://login-secure.phish.com",
                "SECURITY ALERT: Unusual login on your Microsoft account! Verify NOW.",
                "Your PayPal account is LIMITED. Click here to restore access immediately.",
                "HMRC NOTICE: Tax refund of £837.00 awaiting. Claim: http://hmrc-refund.fake.uk",
                "Your Netflix subscription has EXPIRED! Update payment NOW to keep watching.",
                "FINAL NOTICE: Amazon account closes in 24 hours unless you act NOW!",
                "DHL parcel cannot be delivered. Pay customs fee: http://dhl-customs.fake.com",
                "Bank security alert: Your card compromised. Verify: http://lloyds-verify.evil.net",
                "Apple ID suspended due to suspicious activity. Verify now or lose access forever.",
                "You have been selected for an exclusive reward! Provide details to claim your voucher.",
            ] * 16
            import pandas as pd
            emails = legit + phish
            labels = [0]*len(legit) + [1]*len(phish)
            import random; combined = list(zip(emails,labels)); random.shuffle(combined)
            emails, labels = zip(*combined)
            df = pd.DataFrame({"text":list(emails),"label":list(labels),"source":"demo"})
            df = df.sample(frac=1,random_state=42).reset_index(drop=True)
            if self._df is None:
                self._df = df
            self.detector.fit(df, test_size=0.2, cv_folds=3)
            self._trained = True
            self.after(0, self._on_trained)
            if as_fallback:
                self.after(0, lambda: self._badge_var.set("⚠ Demo Fallback"))
                self.after(0, lambda: self._badge.configure(bg=C["amber"]))
                self.after(0, lambda: self._train_prog_var.set(
                    "⚠ Demo fallback active. Upload datasets for production training."))
                self.after(0, lambda: self._status_var.set(
                    "Demo fallback trained. Upload datasets for full training."))
            else:
                self.after(0, lambda: self._status_var.set("Demo data trained. Ready."))

        threading.Thread(target=worker, daemon=True).start()


# ═══════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = PhishGuardApp()
    app.mainloop()
