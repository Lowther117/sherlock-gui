#!/usr/bin/env python3
"""Sherlock GUI - a desktop OSINT front end.

Username tab : Sherlock + Maigret run side by side, results merged into one
               table with descriptions, categories, detection detail, a
               confidence score, a page preview and a Verify pass.
Email tab    : holehe (which services an address is registered with) plus
               Gravatar and mail-domain checks.
Phone tab    : offline number parsing (region, type, carrier, formats).
Domain tab   : RDAP/WHOIS registration data, DNS records, web probe and
               certificate-transparency subdomains.

Settings live beside the app (never inside a macOS bundle).
"""

import csv
import json
import os
import platform
import queue
import re
import subprocess
import sys
import threading
import time
import webbrowser

import engines
import images
import site_info
import tools

APP_NAME = "Sherlock GUI"
SETTINGS_FILE = "sherlock_gui.json"
VERSION = "2.1"


def _app_dir():
    if getattr(sys, "frozen", False):
        exe = os.path.realpath(sys.executable)
        if sys.platform == "darwin":
            m = re.search(r"^(.*?)/[^/]+\.app/Contents/MacOS/", exe + "/")
            if m:
                return m.group(1) or "/"
        return os.path.dirname(exe)
    return os.path.dirname(os.path.realpath(__file__))


HERE = _app_dir()

DEFAULTS = {
    "timeout": 20, "proxy": "", "hide_fp": True, "min_conf": "Any", "show_available": False,
    "show_unknown": False, "show_desc": True, "category": "All", "appearance": "system",
    "flaky_sites": list(site_info.DEFAULT_FLAKY_SITES), "geometry": "", "use_sherlock": True,
    "use_maigret": True, "maigret_scope": "All", "auto_verify": False, "variations": False,
    "variation_patterns": list(engines.DEFAULT_VARIATION_PATTERNS), "phone_region": "GB",
    "email_only_registered": True, "domain_subdomains": True, "last_tab": 0, "show_tab_intros": True,
}

# One-paragraph description shown at the top of each tab (Settings > Show tab descriptions),
# and a longer guide under Help > What each tab does.
TAB_INTROS = {
    "user": (
        "Find accounts by username",
        "Type one or more usernames and every site Sherlock (~370) and Maigret (~3,000) know about is asked "
        "whether that name is taken. Rows arrive live with a description and category for the site, which engine "
        "claimed it, how it decided (status code, redirect or a missing 'not found' string) and a confidence. "
        "Both engines are fooled by bot walls and soft-404 pages, so Low rows are hidden by default and "
        "'Verify claimed' re-requests each profile independently. Select a row to read what the page actually "
        "says; double-click to open it. 'Fetch pictures' downloads each claimed profile's picture so the same "
        "photo can be spotted across sites and sent to a reverse image search."),
    "image": (
        "Reverse image search",
        "Paste an image URL or pick a file, and open it in Google Lens, Bing, Yandex or TinEye to find where "
        "else that picture appears. The image is also compared against every profile picture fetched on the "
        "Username tab, so a photo from one place can be matched to the accounts found there. Nothing is "
        "uploaded by the app itself: URL searches hand the address to the engine, and a local file opens the "
        "engine's own upload page for you to drop it on."),
    "email": (
        "Find accounts by email address",
        "Asks around 120 services whether an address is registered with them, the way a password-reset form "
        "does, without ever sending anything to the address. Also checks whether the address has a Gravatar "
        "and whether its domain can receive mail at all (MX records). 'Rate limited' means the service refused "
        "to answer, not that the address is unknown there."),
    "phone": (
        "Look up a phone number",
        "Entirely offline: parses the number, checks it is valid, and reports the country or region, line type "
        "(mobile, landline, VoIP...), the carrier the number was originally issued to (ports are not tracked), "
        "time zones and the standard E.164 / national formats, plus quick search links. Set the default region "
        "for numbers typed without a + country code. Nothing identifies the current owner."),
    "domain": (
        "Look up a domain",
        "Collects registration details via RDAP (WHOIS as fallback: registrar, dates, name servers, contacts "
        "where the registry publishes them), DNS records (A, AAAA, MX, NS, TXT, CNAME), a probe of the website "
        "itself (status, redirects, server, title) and, optionally, every hostname that has appeared in a "
        "public TLS certificate for the domain - a quick way to find subdomains the site never links to."),
}

TAB_GUIDE = """WHAT EACH TAB DOES

USERNAME
Type one or more usernames (space or comma separated) and press Search. Sherlock and Maigret run at the same
time and their results are merged into one table by profile URL, so a profile both engines found is one row
with Engine = "Maigret + Sherlock".

Columns: Site and Category / Description (hand-written for the best-known sites), Status (Claimed, Available,
Unknown/error), Confidence (High / Medium / Low), Engine, Detection (how the engine decided: status code,
redirect, or a "not found" message missing from the page), HTTP status, and Why (the reasons behind the
confidence). Select a row to see a preview of the page - title, description, the sentences that mention the
username and anything Maigret extracted. Double-click opens the profile in your browser; right-click for
copy / verify / add or remove the site from the false-positive list.

Options: Variations tries common forms of each name (dan.lowther -> danlowther, dan_lowther, danlowther1...;
edit the patterns under Settings). Auto-verify re-checks every claimed profile as soon as the run finishes.
The Show bar hides or reveals Available and Unknown rows, filters by category or free text and sets a minimum
confidence. File > Export writes the visible rows as CSV, JSON or a plain list of URLs.

Why results need checking: both engines decide a profile exists from a status code, a redirect, or an
error string missing from the page. Bot walls, rate limits and soft-404 pages fool those rules, which is why
each claimed row gets a confidence and why Verify exists (Help > How the false-positive filter works).

EMAIL
Type an address and press Check. holehe asks ~120 services (Adobe, Amazon, Discord, GitHub, Instagram,
Spotify, Twitter...) whether the address is registered, using the same requests a password-reset or sign-up
form makes. Nothing is ever sent to the address and its owner is not notified. Results: Registered, Not
registered, Rate limited (the service refused to answer this time - try again later) or Error. Some services
also return hints such as a partially masked phone number or recovery address. Gravatar shows whether the
address has a public avatar profile; MX shows whether the domain can receive mail at all - if it cannot, the
address is not in use anywhere. "Only show registered / hints" hides the negative rows. Export CSV saves the
table.

PHONE
Type a number and press Look up. Everything happens offline using Google's libphonenumber data: validity,
possible vs valid, country/region, line type (mobile, fixed line, VoIP, toll-free, premium...), the carrier
the number block was originally issued to (numbers that have since been ported keep the original carrier),
time zones and the E.164, international, national and RFC3966 formats, plus quick links to search the
number on the web. Default region is only used when the number is typed without a + country code (GB for
07..., for example). This tab cannot tell you who currently owns a number.

DOMAIN
Type a domain and press Look up. Registration: RDAP (the structured successor to WHOIS, with WHOIS as
fallback) gives registrar, creation / expiry / update dates, status codes, name servers and whatever contact
details the registry still publishes. DNS: A, AAAA, MX, NS, TXT (SPF, DMARC, verification records), CNAME and
SOA. Web probe: whether the site answers on http and https, where it redirects, the server header and page
title. Subdomains: every hostname that has appeared in a public TLS certificate for the domain (certificate
transparency logs via crt.sh) - slower, so it can be switched off, but it often reveals staging, mail, VPN
and admin hosts the main site never links to.

IMAGE
Reverse image search without an API key. Give it an image URL (or the profile picture of any row on the
Username tab via right-click) and the four engines open in your browser with that URL: Google Lens, Bing
Visual Search, Yandex Images (usually the strongest for faces and social-media avatars) and TinEye (exact
and near-exact copies, with first-seen dates). For a file on disk the engines need you to drop the file on
their page yourself - the app opens the right page and puts the file path on the clipboard.

The app also fingerprints images (a perceptual "dHash", so re-encoded, resized or lightly cropped copies
still match). "Fetch pictures" on the Username tab downloads the profile picture from every claimed page
it has text for; rows sharing the same picture are marked in the Picture column and gain confidence,
because the same photo on two sites is the best sign that two accounts belong to the same person. On the
Image tab, "Compare with fetched pictures" lists the accounts whose picture matches the one loaded.

ALL TABS
Everything the app looks at is already public. Requests go out from your own connection (or the proxy set on
the Username tab), and the log at the bottom shows what each run did. Copy buttons put the full text output
on the clipboard.
"""


def load_settings():
    s = dict(DEFAULTS)
    try:
        with open(os.path.join(HERE, SETTINGS_FILE), "r", encoding="utf-8") as f:
            s.update(json.load(f))
    except Exception:
        pass
    return s


def save_settings(s):
    try:
        with open(os.path.join(HERE, SETTINGS_FILE), "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except Exception:
        pass


LIGHT = {
    "bg": "#f3f4f6", "fg": "#111827", "panel": "#ffffff", "field": "#ffffff", "border": "#c7cbd1",
    "accent": "#2563eb", "accent_fg": "#ffffff", "sel": "#dbeafe", "sel_fg": "#111827", "muted": "#6b7280",
    "tree_alt": "#f9fafb", "ok": "#15803d", "warn": "#b45309", "bad": "#b91c1c", "hover": "#e5e7eb",
}
DARK = {
    "bg": "#1e1f24", "fg": "#e5e7eb", "panel": "#26272d", "field": "#2c2d33", "border": "#3f4148",
    "accent": "#3b82f6", "accent_fg": "#ffffff", "sel": "#1d4ed8", "sel_fg": "#ffffff", "muted": "#9ca3af",
    "tree_alt": "#2a2b31", "ok": "#4ade80", "warn": "#fbbf24", "bad": "#f87171", "hover": "#34353c",
}


def system_dark():
    try:
        if sys.platform == "darwin":
            r = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"], capture_output=True,
                               text=True, timeout=3)
            return "dark" in (r.stdout or "").lower()
        if sys.platform.startswith("win"):
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            return winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 0
    except Exception:
        pass
    return False


COLUMNS = [
    ("username", "Username", 100), ("site", "Site", 150), ("category", "Category", 100),
    ("status", "Status", 75), ("confidence", "Confidence", 80), ("verify", "Verified", 75),
    ("avatar", "Picture", 85),
    ("engines", "Engine", 110), ("http_status", "HTTP", 50), ("time", "Time (s)", 60),
    ("url", "URL", 300), ("description", "Description", 220), ("detection", "Detection", 95),
    ("why", "Why", 240),
]
EMAIL_COLUMNS = [
    ("site", "Site", 150), ("domain", "Domain", 150), ("state", "Result", 110),
    ("recovery", "Recovery email hint", 170), ("phone", "Phone hint", 110), ("other", "Other", 320),
    ("method", "Method", 90),
]
CONF_CHOICES = ["Any", "Medium", "High"]
REGIONS = ["GB", "IE", "US", "CA", "AU", "NZ", "FR", "DE", "ES", "IT", "NL", "BE", "PT", "PL", "RO", "SE",
           "NO", "DK", "IN", "PK", "BD", "NG", "ZA", "BR", "MX", "AE", "TR", "RU", "UA", "CN", "JP"]


def main():
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog

    class App:
        def __init__(self, root):
            self.root = root
            self.S = load_settings()
            self.q = queue.Queue()
            self.runner = None
            self.verifier = None
            self.email_thread = None
            self.domain_thread = None
            self.rows = []
            self.row_key = {}
            self.site_key = {}          # (engine, username, site) -> key
            self.sherlock_sites = {}
            self.flaky = set(site_info.norm_name(n) for n in self.S["flaky_sites"])
            self.sort_col, self.sort_rev = "confidence", True
            self.total, self.done = 0, 0
            self._render_after = None
            self._iid_map = {}
            self.email_rows = []
            self.avatar_threads = []
            self.image_file = None
            self.image_data = None
            self.image_hash = None
            self.image_url_loaded = None
            self._image_photo = None

            root.title(APP_NAME)
            root.minsize(960, 600)
            try:
                root.geometry(self.S.get("geometry") or "1320x820")
            except Exception:
                root.geometry("1320x820")

            if sys.platform.startswith("win"):
                self.font_family, self.mono_family, self.font_size = "Segoe UI", "Consolas", 10
            elif sys.platform == "darwin":
                self.font_family, self.mono_family, self.font_size = "Helvetica Neue", "Menlo", 13
            else:
                self.font_family, self.mono_family, self.font_size = "DejaVu Sans", "DejaVu Sans Mono", 10

            self.mode_dark = self._resolve_dark()
            self.P = DARK if self.mode_dark else LIGHT
            self.style = ttk.Style(root)
            try:
                self.style.theme_use("clam")
            except Exception:
                pass
            self.text_widgets = []
            self.tab_intro_frames = []
            self.menus = []
            self._build_menu()
            self._build_ui()
            self._apply_theme()
            self._load_sites()
            root.protocol("WM_DELETE_WINDOW", self.on_close)
            root.after(100, self._poll)
            root.after(20000, self._theme_tick)

        # ------------------------------------------------------------------ theme
        def _resolve_dark(self):
            a = self.S.get("appearance", "system")
            return True if a == "dark" else False if a == "light" else system_dark()

        def _theme_tick(self):
            if self.S.get("appearance", "system") == "system":
                d = system_dark()
                if d != self.mode_dark:
                    self.mode_dark, self.P = d, (DARK if d else LIGHT)
                    self._apply_theme()
            self.root.after(20000, self._theme_tick)

        def set_appearance(self, mode):
            self.S["appearance"] = mode
            self.mode_dark = self._resolve_dark()
            self.P = DARK if self.mode_dark else LIGHT
            self._apply_theme()

        def _apply_theme(self):
            P, s = self.P, self.style
            base_font = (self.font_family, self.font_size)
            self.root.configure(bg=P["bg"])
            s.configure(".", background=P["bg"], foreground=P["fg"], fieldbackground=P["field"],
                        bordercolor=P["border"], lightcolor=P["panel"], darkcolor=P["panel"],
                        troughcolor=P["panel"], font=base_font, focuscolor=P["accent"])
            s.configure("TFrame", background=P["bg"])
            s.configure("TLabel", background=P["bg"], foreground=P["fg"])
            s.configure("Muted.TLabel", foreground=P["muted"])
            s.configure("Head.TLabel", font=(self.font_family, self.font_size + 1, "bold"))
            s.configure("TCheckbutton", background=P["bg"], foreground=P["fg"])
            s.map("TCheckbutton", background=[("active", P["bg"])])
            s.configure("TRadiobutton", background=P["bg"], foreground=P["fg"])
            s.map("TRadiobutton", background=[("active", P["bg"])])
            s.configure("TButton", background=P["panel"], foreground=P["fg"], padding=(10, 4), bordercolor=P["border"])
            s.map("TButton", background=[("active", P["hover"]), ("disabled", P["bg"])],
                  foreground=[("disabled", P["muted"])])
            s.configure("Accent.TButton", background=P["accent"], foreground=P["accent_fg"], bordercolor=P["accent"])
            s.map("Accent.TButton", background=[("active", P["sel"]), ("disabled", P["border"])],
                  foreground=[("disabled", P["muted"])])
            s.configure("TEntry", fieldbackground=P["field"], foreground=P["fg"], insertcolor=P["fg"], bordercolor=P["border"])
            s.configure("TSpinbox", fieldbackground=P["field"], foreground=P["fg"], arrowcolor=P["fg"],
                        insertcolor=P["fg"], bordercolor=P["border"])
            s.configure("TCombobox", fieldbackground=P["field"], foreground=P["fg"], arrowcolor=P["fg"], bordercolor=P["border"])
            s.map("TCombobox", fieldbackground=[("readonly", P["field"])], foreground=[("readonly", P["fg"])],
                  selectbackground=[("readonly", P["field"])], selectforeground=[("readonly", P["fg"])])
            self.root.option_add("*TCombobox*Listbox.background", P["field"])
            self.root.option_add("*TCombobox*Listbox.foreground", P["fg"])
            self.root.option_add("*TCombobox*Listbox.selectBackground", P["sel"])
            self.root.option_add("*TCombobox*Listbox.selectForeground", P["sel_fg"])
            s.configure("Treeview", background=P["panel"], fieldbackground=P["panel"], foreground=P["fg"],
                        bordercolor=P["border"], rowheight=24)
            s.map("Treeview", background=[("selected", P["sel"])], foreground=[("selected", P["sel_fg"])])
            s.configure("Treeview.Heading", background=P["bg"], foreground=P["fg"], bordercolor=P["border"],
                        relief="flat", padding=(6, 4))
            s.map("Treeview.Heading", background=[("active", P["hover"])])
            s.configure("TProgressbar", background=P["accent"], troughcolor=P["panel"], bordercolor=P["border"])
            for o in ("Vertical", "Horizontal"):
                s.configure("%s.TScrollbar" % o, background=P["panel"], troughcolor=P["bg"], arrowcolor=P["fg"],
                            bordercolor=P["border"])
            s.configure("TLabelframe", background=P["bg"], bordercolor=P["border"])
            s.configure("TLabelframe.Label", background=P["bg"], foreground=P["muted"])
            s.configure("TNotebook", background=P["bg"], bordercolor=P["border"], tabmargins=(4, 4, 4, 0))
            s.configure("TNotebook.Tab", background=P["panel"], foreground=P["fg"], padding=(14, 6),
                        bordercolor=P["border"])
            s.map("TNotebook.Tab", background=[("selected", P["bg"]), ("active", P["hover"])],
                  foreground=[("selected", P["accent"])])
            s.configure("TPanedwindow", background=P["bg"])
            for w in self.text_widgets:
                w.configure(bg=P["field"], fg=P["fg"], insertbackground=P["fg"], highlightbackground=P["border"],
                            highlightcolor=P["accent"], selectbackground=P["sel"], selectforeground=P["sel_fg"])
                w.tag_configure("h", foreground=P["accent"], font=(self.font_family, self.font_size, "bold"))
                w.tag_configure("k", foreground=P["muted"])
                w.tag_configure("ok", foreground=P["ok"])
                w.tag_configure("bad", foreground=P["bad"])
                w.tag_configure("warn", foreground=P["warn"])
            for tree in (self.tree, self.etree):
                tree.tag_configure("odd", background=P["tree_alt"])
                tree.tag_configure("even", background=P["panel"])
                tree.tag_configure("low", foreground=P["bad"])
                tree.tag_configure("med", foreground=P["warn"])
                tree.tag_configure("high", foreground=P["ok"])
                tree.tag_configure("avail", foreground=P["muted"])
            try:
                for m in [self.menubar] + self.menus:
                    m.configure(bg=P["panel"], fg=P["fg"], activebackground=P["sel"], activeforeground=P["sel_fg"])
            except Exception:
                pass
            self._render()

        # ------------------------------------------------------------------ menu
        def _build_menu(self):
            self.menubar = tk.Menu(self.root)
            fm = tk.Menu(self.menubar, tearoff=0)
            fm.add_command(label="Export visible rows as CSV...", command=lambda: self.export("csv"))
            fm.add_command(label="Export visible rows as JSON...", command=lambda: self.export("json"))
            fm.add_command(label="Export visible URLs as text...", command=lambda: self.export("txt"))
            fm.add_separator()
            fm.add_command(label="Clear username results", command=self.clear)
            fm.add_separator()
            fm.add_command(label="Quit", command=self.on_close)
            self.menubar.add_cascade(label="File", menu=fm)
            em = tk.Menu(self.menubar, tearoff=0)
            em.add_command(label="Open selected in browser", command=self.open_selected)
            em.add_command(label="Fetch profile pictures for claimed rows", command=self.fetch_avatars)
            em.add_command(label="Copy selected URLs", command=self.copy_urls)
            em.add_command(label="Copy selected rows (tab-separated)", command=self.copy_rows)
            em.add_command(label="Select all", command=self.select_all)
            em.add_separator()
            em.add_command(label="Mark selected sites as false-positive-prone", command=self.mark_flaky)
            em.add_command(label="Unmark selected sites", command=self.unmark_flaky)
            self.menubar.add_cascade(label="Edit", menu=em)
            sm = tk.Menu(self.menubar, tearoff=0)
            sm.add_command(label="False-positive site list...", command=self.edit_flaky)
            sm.add_command(label="Username variation patterns...", command=self.edit_patterns)
            sm.add_separator()
            self.use_sherlock_var = tk.BooleanVar(value=bool(self.S["use_sherlock"]))
            self.use_maigret_var = tk.BooleanVar(value=bool(self.S["use_maigret"]))
            sm.add_checkbutton(label="Engine: Sherlock (%s)" % engines.SHERLOCK_VERSION, variable=self.use_sherlock_var)
            sm.add_checkbutton(label="Engine: Maigret (%s)" % engines.MAIGRET_VERSION, variable=self.use_maigret_var,
                               state="normal" if engines.MAIGRET_OK else "disabled")
            mm = tk.Menu(sm, tearoff=0)
            self.maigret_scope_var = tk.StringVar(value=str(self.S.get("maigret_scope", "All")))
            for lbl in ("All", "Top 1500", "Top 500"):
                mm.add_radiobutton(label=lbl + " Maigret sites", value=lbl, variable=self.maigret_scope_var)
            sm.add_cascade(label="Maigret scope", menu=mm)
            am = tk.Menu(sm, tearoff=0)
            self.appearance_var = tk.StringVar(value=self.S.get("appearance", "system"))
            for lbl, val in (("Match system", "system"), ("Light", "light"), ("Dark", "dark")):
                am.add_radiobutton(label=lbl, value=val, variable=self.appearance_var,
                                   command=lambda v=val: self.set_appearance(v))
            sm.add_cascade(label="Appearance", menu=am)
            self.show_intros_var = tk.BooleanVar(value=bool(self.S.get("show_tab_intros", True)))
            sm.add_checkbutton(label="Show tab descriptions", variable=self.show_intros_var,
                               command=self.toggle_tab_intros)
            self.menubar.add_cascade(label="Settings", menu=sm)
            hm = tk.Menu(self.menubar, tearoff=0)
            hm.add_command(label="What each tab does", command=self.help_tabs)
            hm.add_command(label="How the false-positive filter works", command=self.help_fp)
            hm.add_command(label="About", command=self.about)
            self.menubar.add_cascade(label="Help", menu=hm)
            self.menus += [fm, em, sm, mm, am, hm]
            self.root.config(menu=self.menubar)
            if sys.platform == "darwin":
                try:
                    self.root.createcommand("tk::mac::Quit", self.on_close)
                except Exception:
                    pass

        # ------------------------------------------------------------------ UI
        def _text(self, parent, height, wrap="word", mono=False):
            t = tk.Text(parent, height=height, wrap=wrap, relief="flat", highlightthickness=1,
                        font=(self.mono_family if mono else self.font_family, self.font_size - (1 if mono else 0)))
            self.text_widgets.append(t)
            return t

        def _tab_intro(self, tab, key):
            """Heading + one-paragraph description at the top of a tab; wraps with the window."""
            title, text = TAB_INTROS[key]
            box = ttk.Frame(tab)
            box.pack(fill="x", pady=(0, 8))
            ttk.Label(box, text=title, font=(self.font_family, self.font_size + 1, "bold")).pack(anchor="w")
            lbl = ttk.Label(box, text=text, style="Muted.TLabel", justify="left", wraplength=900)
            lbl.pack(anchor="w", fill="x", pady=(2, 0))
            box.bind("<Configure>", lambda e, l=lbl: l.configure(wraplength=max(300, e.width - 8)))
            self.tab_intro_frames.append(box)
            if not self.S.get("show_tab_intros", True):
                box.pack_forget()
            return box

        def toggle_tab_intros(self):
            show = bool(self.show_intros_var.get())
            self.S["show_tab_intros"] = show
            for box in self.tab_intro_frames:
                if show:
                    others = [w for w in box.master.winfo_children() if w is not box]
                    if others:
                        box.pack(fill="x", pady=(0, 8), before=others[0])
                    else:
                        box.pack(fill="x", pady=(0, 8))
                else:
                    box.pack_forget()

        def help_tabs(self):
            win = tk.Toplevel(self.root)
            win.title("What each tab does")
            win.geometry("760x640")
            win.configure(bg=self.P["bg"])
            t = tk.Text(win, wrap="word", bg=self.P["field"], fg=self.P["fg"], relief="flat", highlightthickness=1,
                        highlightbackground=self.P["border"], font=(self.font_family, self.font_size), padx=10, pady=8)
            vs = ttk.Scrollbar(win, orient="vertical", command=t.yview)
            t.configure(yscrollcommand=vs.set)
            t.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=10)
            vs.pack(side="left", fill="y", pady=10, padx=(0, 10))
            t.insert("1.0", TAB_GUIDE.strip())
            t.tag_configure("h", font=(self.font_family, self.font_size + 1, "bold"))
            for i, line in enumerate(TAB_GUIDE.strip().splitlines(), 1):
                if line and line == line.upper() and line.replace(" ", "").isalpha():
                    t.tag_add("h", "%d.0" % i, "%d.end" % i)
            t.configure(state="disabled")

        def _build_ui(self):
            outer = ttk.Frame(self.root, padding=(8, 6))
            outer.pack(fill="both", expand=True)
            self.nb = ttk.Notebook(outer)
            self.nb.pack(fill="both", expand=True)
            self.tab_user = ttk.Frame(self.nb, padding=(6, 8))
            self.tab_email = ttk.Frame(self.nb, padding=(6, 8))
            self.tab_phone = ttk.Frame(self.nb, padding=(6, 8))
            self.tab_domain = ttk.Frame(self.nb, padding=(6, 8))
            self.tab_image = ttk.Frame(self.nb, padding=(6, 8))
            self.nb.add(self.tab_user, text="  Username  ")
            self.nb.add(self.tab_email, text="  Email  ")
            self.nb.add(self.tab_phone, text="  Phone  ")
            self.nb.add(self.tab_domain, text="  Domain  ")
            self.nb.add(self.tab_image, text="  Image  ")
            self._build_user_tab(self.tab_user)
            self._build_email_tab(self.tab_email)
            self._build_phone_tab(self.tab_phone)
            self._build_domain_tab(self.tab_domain)
            self._build_image_tab(self.tab_image)
            self.log = self._text(outer, 3, mono=True)
            self.log.pack(fill="x", pady=(6, 0))
            self.log.configure(state="disabled")
            try:
                self.nb.select(int(self.S.get("last_tab", 0)))
            except Exception:
                pass

        # ---- Username tab
        def _build_user_tab(self, tab):
            S = self.S
            self._tab_intro(tab, "user")
            r1 = ttk.Frame(tab)
            r1.pack(fill="x")
            ttk.Label(r1, text="Username(s):").pack(side="left")
            self.user_var = tk.StringVar()
            e = ttk.Entry(r1, textvariable=self.user_var, font=(self.font_family, self.font_size + 2))
            e.pack(side="left", fill="x", expand=True, padx=(6, 8))
            e.bind("<Return>", lambda ev: self.start())
            e.focus_set()
            self.btn_start = ttk.Button(r1, text="Search", style="Accent.TButton", command=self.start)
            self.btn_start.pack(side="left")
            self.btn_stop = ttk.Button(r1, text="Stop", command=self.stop, state="disabled")
            self.btn_stop.pack(side="left", padx=(6, 0))
            self.btn_verify = ttk.Button(r1, text="Verify claimed", command=self.verify, state="disabled")
            self.btn_verify.pack(side="left", padx=(6, 0))
            ttk.Button(r1, text="Export CSV", command=lambda: self.export("csv")).pack(side="left", padx=(14, 0))
            ttk.Button(r1, text="Export TXT", command=lambda: self.export("txt")).pack(side="left", padx=(6, 0))
            self.btn_avatars = ttk.Button(r1, text="Fetch pictures", command=self.fetch_avatars, state="disabled")
            self.btn_avatars.pack(side="left", padx=(14, 0))

            r2 = ttk.Frame(tab)
            r2.pack(fill="x", pady=(8, 0))
            ttk.Label(r2, text="Timeout (s):").pack(side="left")
            self.timeout_var = tk.IntVar(value=int(S["timeout"]))
            ttk.Spinbox(r2, from_=3, to=120, width=5, textvariable=self.timeout_var).pack(side="left", padx=(4, 12))
            self.variations_var = tk.BooleanVar(value=bool(S["variations"]))
            ttk.Checkbutton(r2, text="Try username variations", variable=self.variations_var,
                            command=self._variation_hint).pack(side="left", padx=(0, 12))
            self.auto_verify_var = tk.BooleanVar(value=bool(S["auto_verify"]))
            ttk.Checkbutton(r2, text="Auto-verify when finished", variable=self.auto_verify_var).pack(side="left", padx=(0, 12))
            ttk.Label(r2, text="Proxy:").pack(side="left")
            self.proxy_var = tk.StringVar(value=S["proxy"])
            ttk.Entry(r2, textvariable=self.proxy_var, width=26).pack(side="left", padx=(4, 6))
            self.var_hint = ttk.Label(r2, text="", style="Muted.TLabel")
            self.var_hint.pack(side="left")
            self.user_var.trace_add("write", lambda *a: self._variation_hint())

            r3 = ttk.LabelFrame(tab, text="Show", padding=(8, 4))
            r3.pack(fill="x", pady=(8, 0))
            self.hide_fp_var = tk.BooleanVar(value=bool(S["hide_fp"]))
            ttk.Checkbutton(r3, text="Hide likely false positives", variable=self.hide_fp_var,
                            command=self._render).pack(side="left", padx=(0, 10))
            ttk.Label(r3, text="Min confidence:").pack(side="left")
            self.min_conf_var = tk.StringVar(value=S["min_conf"] if S["min_conf"] in CONF_CHOICES else "Any")
            cb = ttk.Combobox(r3, textvariable=self.min_conf_var, values=CONF_CHOICES, width=8, state="readonly")
            cb.pack(side="left", padx=(4, 12))
            cb.bind("<<ComboboxSelected>>", lambda e: self._render())
            self.show_avail_var = tk.BooleanVar(value=bool(S["show_available"]))
            ttk.Checkbutton(r3, text="Available", variable=self.show_avail_var, command=self._render).pack(side="left", padx=(0, 8))
            self.show_unknown_var = tk.BooleanVar(value=bool(S["show_unknown"]))
            ttk.Checkbutton(r3, text="Unknown / errors", variable=self.show_unknown_var, command=self._render).pack(side="left", padx=(0, 12))
            self.show_desc_var = tk.BooleanVar(value=bool(S["show_desc"]))
            ttk.Checkbutton(r3, text="Descriptions", variable=self.show_desc_var, command=self._apply_columns).pack(side="left", padx=(0, 12))
            ttk.Label(r3, text="Category:").pack(side="left")
            self.cat_var = tk.StringVar(value=S["category"])
            cbc = ttk.Combobox(r3, textvariable=self.cat_var, values=["All"] + site_info.CATEGORIES, width=16, state="readonly")
            cbc.pack(side="left", padx=(4, 12))
            cbc.bind("<<ComboboxSelected>>", lambda e: self._render())
            ttk.Label(r3, text="Filter:").pack(side="left")
            self.filter_var = tk.StringVar()
            ttk.Entry(r3, textvariable=self.filter_var, width=20).pack(side="left", padx=(4, 0))
            self.filter_var.trace_add("write", lambda *a: self._schedule_render())

            pw = ttk.Panedwindow(tab, orient="vertical")
            pw.pack(fill="both", expand=True, pady=(8, 0))
            mid = ttk.Frame(pw)
            pw.add(mid, weight=4)
            cols = [c[0] for c in COLUMNS]
            self.tree = ttk.Treeview(mid, columns=cols, show="headings", selectmode="extended")
            for key, label, width in COLUMNS:
                self.tree.heading(key, text=label, command=lambda k=key: self.sort_by(k))
                self.tree.column(key, width=width, minwidth=40, stretch=(key in ("url", "description", "why")))
            vs = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
            hs = ttk.Scrollbar(mid, orient="horizontal", command=self.tree.xview)
            self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
            self.tree.grid(row=0, column=0, sticky="nsew")
            vs.grid(row=0, column=1, sticky="ns")
            hs.grid(row=1, column=0, sticky="ew")
            mid.rowconfigure(0, weight=1)
            mid.columnconfigure(0, weight=1)
            self.tree.bind("<Double-1>", lambda e: self.open_selected())
            self.tree.bind("<Return>", lambda e: (self.open_selected(), "break")[1])
            self.tree.bind("<Control-a>", lambda e: (self.select_all(), "break")[1])
            self.tree.bind("<Command-a>", lambda e: (self.select_all(), "break")[1])
            self.tree.bind("<Control-c>", lambda e: (self.copy_urls(), "break")[1])
            self.tree.bind("<Command-c>", lambda e: (self.copy_urls(), "break")[1])
            self.tree.bind("<Button-3>", self._popup)
            self.tree.bind("<Button-2>", self._popup)
            self.tree.bind("<Control-Button-1>", self._popup_mac)
            self.tree.bind("<<TreeviewSelect>>", lambda e: self._show_preview())
            self.ctx = tk.Menu(self.root, tearoff=0)
            self.ctx.add_command(label="Open in browser", command=self.open_selected)
            self.ctx.add_command(label="Copy URL", command=self.copy_urls)
            self.ctx.add_command(label="Copy row", command=self.copy_rows)
            self.ctx.add_separator()
            self.ctx.add_command(label="Verify this row", command=self.verify_selected)
            self.ctx.add_command(label="Mark site as false-positive-prone", command=self.mark_flaky)
            self.ctx.add_command(label="Unmark site", command=self.unmark_flaky)
            self.ctx.add_separator()
            self.ctx_img = tk.Menu(self.ctx, tearoff=0)
            for name, _ in images.ENGINES:
                self.ctx_img.add_command(label=name, command=lambda n=name: self.reverse_search_selected(n))
            self.ctx_img.add_separator()
            self.ctx_img.add_command(label="All four engines", command=lambda: self.reverse_search_selected(None))
            self.ctx.add_cascade(label="Reverse image search profile picture", menu=self.ctx_img)
            self.ctx.add_command(label="Fetch profile picture", command=self.fetch_avatar_selected)
            self.ctx.add_command(label="Open profile picture", command=self.open_avatar_selected)
            self.ctx.add_command(label="Send picture to Image tab", command=self.avatar_to_image_tab)
            self.menus += [self.ctx, self.ctx_img]

            pv = ttk.LabelFrame(pw, text="Page preview (select a row)", padding=(6, 4))
            pw.add(pv, weight=1)
            side = ttk.Frame(pv, width=images.THUMB + 12)
            side.pack(side="left", fill="y", padx=(0, 8))
            side.pack_propagate(False)
            self.avatar_label = ttk.Label(side, text="no picture", style="Muted.TLabel", anchor="center",
                                          justify="center", wraplength=images.THUMB)
            self.avatar_label.pack(fill="x", pady=(2, 4))
            self.avatar_label.bind("<Button-1>", lambda e: self.open_avatar_selected())
            self.btn_avatar_search = ttk.Menubutton(side, text="Search image", state="disabled")
            m = tk.Menu(self.btn_avatar_search, tearoff=0)
            for name, _ in images.ENGINES:
                m.add_command(label=name, command=lambda n=name: self.reverse_search_selected(n))
            m.add_separator()
            m.add_command(label="All four engines", command=lambda: self.reverse_search_selected(None))
            m.add_command(label="Send to Image tab", command=self.avatar_to_image_tab)
            self.btn_avatar_search.configure(menu=m)
            self.menus.append(m)
            self.btn_avatar_search.pack(fill="x")
            self._avatar_photo = None
            self.preview = self._text(pv, 7)
            self.preview.pack(side="left", fill="both", expand=True)
            self.preview.configure(state="disabled")

            bot = ttk.Frame(tab)
            bot.pack(fill="x", pady=(6, 0))
            self.prog = ttk.Progressbar(bot, mode="determinate", maximum=100)
            self.prog.pack(fill="x")
            self.status_var = tk.StringVar(value="Ready.")
            ttk.Label(bot, textvariable=self.status_var, style="Muted.TLabel").pack(anchor="w", pady=(3, 0))
            self._apply_columns()

        # ---- Email tab
        def _build_email_tab(self, tab):
            self._tab_intro(tab, "email")
            r1 = ttk.Frame(tab)
            r1.pack(fill="x")
            ttk.Label(r1, text="Email address:").pack(side="left")
            self.email_var = tk.StringVar()
            e = ttk.Entry(r1, textvariable=self.email_var, font=(self.font_family, self.font_size + 2))
            e.pack(side="left", fill="x", expand=True, padx=(6, 8))
            e.bind("<Return>", lambda ev: self.email_start())
            self.btn_email = ttk.Button(r1, text="Check", style="Accent.TButton", command=self.email_start)
            self.btn_email.pack(side="left")
            self.btn_email_stop = ttk.Button(r1, text="Stop", command=self.email_stop, state="disabled")
            self.btn_email_stop.pack(side="left", padx=(6, 0))
            ttk.Button(r1, text="Export CSV", command=self.email_export).pack(side="left", padx=(14, 0))
            r2 = ttk.Frame(tab)
            r2.pack(fill="x", pady=(8, 0))
            self.email_only_var = tk.BooleanVar(value=bool(self.S["email_only_registered"]))
            ttk.Checkbutton(r2, text="Only show registered / hints", variable=self.email_only_var,
                            command=self._render_email).pack(side="left")
            ok, ver = tools.holehe_status()
            ttk.Label(r2, text=("holehe %s" % ver) if ok else
                      "holehe is not installed - only Gravatar and mail-domain checks will run.",
                      style="Muted.TLabel").pack(side="left", padx=(12, 0))
            mid = ttk.Frame(tab)
            mid.pack(fill="both", expand=True, pady=(8, 0))
            cols = [c[0] for c in EMAIL_COLUMNS]
            self.etree = ttk.Treeview(mid, columns=cols, show="headings", selectmode="extended")
            for key, label, width in EMAIL_COLUMNS:
                self.etree.heading(key, text=label)
                self.etree.column(key, width=width, minwidth=40, stretch=(key == "other"))
            vs = ttk.Scrollbar(mid, orient="vertical", command=self.etree.yview)
            self.etree.configure(yscrollcommand=vs.set)
            self.etree.grid(row=0, column=0, sticky="nsew")
            vs.grid(row=0, column=1, sticky="ns")
            mid.rowconfigure(0, weight=1)
            mid.columnconfigure(0, weight=1)
            self.etree.bind("<Double-1>", lambda e: self._email_open())
            bot = ttk.Frame(tab)
            bot.pack(fill="x", pady=(6, 0))
            self.eprog = ttk.Progressbar(bot, mode="indeterminate")
            self.eprog.pack(fill="x")
            self.email_status = tk.StringVar(value="Ready.")
            ttk.Label(bot, textvariable=self.email_status, style="Muted.TLabel").pack(anchor="w", pady=(3, 0))

        # ---- Phone tab
        def _build_phone_tab(self, tab):
            self._tab_intro(tab, "phone")
            r1 = ttk.Frame(tab)
            r1.pack(fill="x")
            ttk.Label(r1, text="Phone number:").pack(side="left")
            self.phone_var = tk.StringVar()
            e = ttk.Entry(r1, textvariable=self.phone_var, font=(self.font_family, self.font_size + 2))
            e.pack(side="left", fill="x", expand=True, padx=(6, 8))
            e.bind("<Return>", lambda ev: self.phone_lookup())
            ttk.Label(r1, text="Default region:").pack(side="left")
            self.region_var = tk.StringVar(value=self.S.get("phone_region", "GB"))
            ttk.Combobox(r1, textvariable=self.region_var, values=REGIONS, width=5).pack(side="left", padx=(4, 8))
            ttk.Button(r1, text="Look up", style="Accent.TButton", command=self.phone_lookup).pack(side="left")
            ttk.Button(r1, text="Copy", command=lambda: self._copy_text(self.phone_out)).pack(side="left", padx=(6, 0))
            self.phone_out = self._text(tab, 20, mono=True)
            self.phone_out.pack(fill="both", expand=True, pady=(8, 0))
            self.phone_out.configure(state="disabled")

        # ---- Domain tab
        def _build_domain_tab(self, tab):
            self._tab_intro(tab, "domain")
            r1 = ttk.Frame(tab)
            r1.pack(fill="x")
            ttk.Label(r1, text="Domain:").pack(side="left")
            self.domain_var = tk.StringVar()
            e = ttk.Entry(r1, textvariable=self.domain_var, font=(self.font_family, self.font_size + 2))
            e.pack(side="left", fill="x", expand=True, padx=(6, 8))
            e.bind("<Return>", lambda ev: self.domain_start())
            self.btn_domain = ttk.Button(r1, text="Look up", style="Accent.TButton", command=self.domain_start)
            self.btn_domain.pack(side="left")
            ttk.Button(r1, text="Copy", command=lambda: self._copy_text(self.domain_out)).pack(side="left", padx=(6, 0))
            r2 = ttk.Frame(tab)
            r2.pack(fill="x", pady=(8, 0))
            self.subdomains_var = tk.BooleanVar(value=bool(self.S["domain_subdomains"]))
            ttk.Checkbutton(r2, text="Include subdomains from certificate transparency (crt.sh - slower)",
                            variable=self.subdomains_var).pack(side="left")
            self.domain_out = self._text(tab, 20, wrap="none", mono=True)
            self.domain_out.pack(fill="both", expand=True, pady=(8, 0))
            self.domain_out.configure(state="disabled")
            self.dprog = ttk.Progressbar(tab, mode="indeterminate")
            self.dprog.pack(fill="x", pady=(6, 0))

        # ---- Image tab
        def _build_image_tab(self, tab):
            self._tab_intro(tab, "image")
            r1 = ttk.Frame(tab)
            r1.pack(fill="x")
            ttk.Label(r1, text="Image URL:").pack(side="left")
            self.image_url_var = tk.StringVar()
            e = ttk.Entry(r1, textvariable=self.image_url_var, font=(self.font_family, self.font_size + 2))
            e.pack(side="left", fill="x", expand=True, padx=(6, 8))
            e.bind("<Return>", lambda ev: self.image_load())
            ttk.Button(r1, text="Load", style="Accent.TButton", command=self.image_load).pack(side="left")
            ttk.Button(r1, text="Open file...", command=self.image_browse).pack(side="left", padx=(6, 0))
            r2 = ttk.Frame(tab)
            r2.pack(fill="x", pady=(8, 0))
            ttk.Label(r2, text="Search with:").pack(side="left")
            self.image_buttons = []
            for name, _ in images.ENGINES:
                b = ttk.Button(r2, text=name, command=lambda n=name: self.image_search(n), state="disabled")
                b.pack(side="left", padx=(6, 0))
                self.image_buttons.append(b)
            b = ttk.Button(r2, text="All four", command=lambda: self.image_search(None), state="disabled")
            b.pack(side="left", padx=(12, 0))
            self.image_buttons.append(b)
            b = ttk.Button(r2, text="Compare with fetched pictures", command=self.image_compare, state="disabled")
            b.pack(side="left", padx=(12, 0))
            self.image_buttons.append(b)
            mid = ttk.Frame(tab)
            mid.pack(fill="both", expand=True, pady=(8, 0))
            left = ttk.Frame(mid, width=260)
            left.pack(side="left", fill="y", padx=(0, 8))
            left.pack_propagate(False)
            self.image_preview = ttk.Label(left, text="No image loaded.", style="Muted.TLabel", anchor="center",
                                           justify="center", wraplength=240)
            self.image_preview.pack(fill="both", expand=True)
            self.image_info = ttk.Label(left, text="", style="Muted.TLabel", justify="left", wraplength=240)
            self.image_info.pack(fill="x", pady=(4, 0))
            self.image_out = self._text(mid, 16)
            self.image_out.pack(side="left", fill="both", expand=True)
            self.image_out.configure(state="disabled")
            if not images.PIL_OK:
                self.logmsg("Pillow is not installed: JPEG/WebP previews and picture matching are unavailable "
                            "(pip install pillow).")

        def image_browse(self):
            path = filedialog.askopenfilename(title="Choose an image",
                                              filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.webp *.bmp *.tif *.tiff"),
                                                         ("All files", "*.*")])
            if not path:
                return
            try:
                with open(path, "rb") as f:
                    data = f.read(images.MAX_BYTES + 1)
                if len(data) > images.MAX_BYTES:
                    raise ValueError("file is larger than %d MB" % (images.MAX_BYTES // (1024 * 1024)))
            except Exception as e:
                messagebox.showerror(APP_NAME, "Could not read the file: %s" % e)
                return
            self.image_file = path
            self.image_url_var.set(path)
            self._image_loaded(data, "", None, label=os.path.basename(path))

        def image_load(self):
            src = self.image_url_var.get().strip()
            if not src:
                return
            if os.path.isfile(src):
                self.image_file = src
                try:
                    with open(src, "rb") as f:
                        data = f.read(images.MAX_BYTES + 1)
                except Exception as e:
                    messagebox.showerror(APP_NAME, "Could not read the file: %s" % e)
                    return
                self._image_loaded(data, "", None, label=os.path.basename(src))
                return
            if not src.lower().startswith(("http://", "https://")):
                src = "https://" + src
                self.image_url_var.set(src)
            self.image_file = None
            self._set_text(self.image_out, [("Downloading %s ...\n" % src, "k")])
            self.image_preview.configure(image="", text="loading...")

            def work():
                try:
                    data, ct = images.fetch(src, timeout=self._timeout(), proxy=self.proxy_var.get().strip() or None)
                    self.q.put(("image_loaded", src, data, ct, None))
                except Exception as e:
                    self.q.put(("image_loaded", src, None, "", str(e)))
            threading.Thread(target=work, daemon=True).start()

        def _image_loaded(self, data, ct, url, label=None):
            self.image_data, self.image_url_loaded = data, url
            self.image_hash = images.dhash(data)
            photo = images.thumbnail_photo(data, tk, size=240)
            self._image_photo = photo
            if photo is not None:
                self.image_preview.configure(image=photo, text="")
            else:
                self.image_preview.configure(image="", text="(preview unavailable for this format)")
            self.image_info.configure(text="%s%s\nfingerprint %s" % (
                (label + "\n") if label else "", images.describe(data, ct), self.image_hash or "n/a"))
            for b in self.image_buttons:
                b.configure(state="normal")
            chunks = [("Loaded. ", "k")]
            if url:
                chunks.append(("Search buttons open each engine with this image URL. ", None))
            else:
                chunks.append(("This is a local file: the search buttons open each engine's upload page and copy "
                               "the file path to the clipboard - drop or paste the file there. ", None))
            if self._avatar_index_size():
                chunks.append(("'Compare with fetched pictures' checks it against the %d profile picture(s) "
                               "fetched on the Username tab.\n" % self._avatar_index_size(), None))
            else:
                chunks.append(("Fetch pictures on the Username tab first to compare it against profile pictures.\n", None))
            self._set_text(self.image_out, chunks)

        def image_search(self, engine):
            if self.image_url_loaded:
                for name, u in images.search_urls(self.image_url_loaded):
                    if engine is None or name == engine:
                        webbrowser.open(u)
                self.logmsg("Reverse image search (%s) for %s" % (engine or "all engines", self.image_url_loaded))
            elif self.image_file:
                self.root.clipboard_clear()
                self.root.clipboard_append(self.image_file)
                for name, u in images.UPLOAD_PAGES:
                    if engine is None or name == engine:
                        webbrowser.open(u)
                self.logmsg("Opened %s upload page(s); file path copied to clipboard: %s" % (
                    engine or "all", self.image_file))

        def image_compare(self):
            if not self.image_hash:
                messagebox.showinfo(APP_NAME, "Could not fingerprint this image%s." % (
                    "" if images.PIL_OK else " - Pillow is not installed"))
                return
            hashed = [r for r in self.rows if (r.get("avatar") or {}).get("hash")]
            if not hashed:
                messagebox.showinfo(APP_NAME, "No profile pictures fetched yet - use 'Fetch pictures' on the Username tab.")
                return
            scored = sorted(((images.distance(self.image_hash, r["avatar"]["hash"]), r) for r in hashed), key=lambda t: t[0])
            chunks = [("Compared against %d fetched profile picture(s).\n\n" % len(hashed), "k")]
            matches = [(d, r) for d, r in scored if d <= images.MATCH_THRESHOLD]
            if matches:
                chunks.append(("Same picture (distance <= %d):\n" % images.MATCH_THRESHOLD, "ok"))
                for d, r in matches:
                    chunks.append(("  %2d  %s @ %s  %s\n" % (d, r["username"], r["site"], r.get("url") or ""), None))
            else:
                chunks.append(("No fetched profile picture matches this image.\n", "warn"))
            chunks.append(("\nNearest (lower is more similar; 0 = identical, 64 = nothing alike):\n", "k"))
            for d, r in scored[:8]:
                chunks.append(("  %2d  %s @ %s\n" % (d, r["username"], r["site"]), None))
            self._set_text(self.image_out, chunks)

        # ------------------------------------------------------------------ helpers
        def _apply_columns(self):
            cols = [c[0] for c in COLUMNS]
            if not self.show_desc_var.get():
                cols = [c for c in cols if c not in ("description", "category")]
            self.tree["displaycolumns"] = cols

        def _popup(self, ev):
            iid = self.tree.identify_row(ev.y)
            if iid and iid not in self.tree.selection():
                self.tree.selection_set(iid)
            try:
                self.ctx.tk_popup(ev.x_root, ev.y_root)
            finally:
                self.ctx.grab_release()

        def _popup_mac(self, ev):
            if sys.platform == "darwin":
                self._popup(ev)
                return "break"

        def logmsg(self, msg):
            self.log.configure(state="normal")
            self.log.insert("end", time.strftime("%H:%M:%S ") + msg + "\n")
            lines = int(self.log.index("end-1c").split(".")[0])
            if lines > 400:
                self.log.delete("1.0", "%d.0" % (lines - 400))
            self.log.see("end")
            self.log.configure(state="disabled")

        def _set_text(self, widget, chunks):
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            for text, tag in chunks:
                if tag:
                    widget.insert("end", text, tag)
                else:
                    widget.insert("end", text)
            widget.configure(state="disabled")

        def _copy_text(self, widget):
            self.root.clipboard_clear()
            self.root.clipboard_append(widget.get("1.0", "end").strip())

        def _timeout(self):
            try:
                return max(3, int(self.timeout_var.get()))
            except Exception:
                return 20

        def _load_sites(self):
            try:
                self.sherlock_sites, src = engines.load_sherlock_sites(HERE)
                self.logmsg("Sherlock: %d sites (%s)." % (len(self.sherlock_sites), src))
                if engines.SHERLOCK_FUNC is None:
                    self.logmsg("Sherlock engine not importable (%s) - built-in checker will stand in." % engines.SHERLOCK_ERROR)
            except Exception as e:
                self.sherlock_sites = {}
                self.logmsg(str(e))
            if engines.MAIGRET_OK:
                try:
                    n = len(engines.maigret_sites())
                    self.logmsg("Maigret %s: %d sites." % (engines.MAIGRET_VERSION, n))
                except Exception as e:
                    self.logmsg("Maigret is installed but its database failed to load: %r" % e)
            else:
                self.logmsg("Maigret not installed (%s) - searching with Sherlock only." % (engines.MAIGRET_ERROR or "?"))
            self.status_var.set("Ready - every site is searched (NSFW included).")

        def _usernames_raw(self):
            names = [n for n in re.split(r"[\s,;]+", self.user_var.get().strip()) if n]
            seen, out = set(), []
            for n in names:
                if n.lower() not in seen:
                    seen.add(n.lower())
                    out.append(n)
            return out

        def _expand(self, names):
            if not self.variations_var.get():
                return names
            out, seen = [], set()
            for n in names:
                for v in engines.variations(n, self.S.get("variation_patterns")):
                    if v.lower() not in seen:
                        seen.add(v.lower())
                        out.append(v)
            return out

        def _variation_hint(self):
            names = self._expand(self._usernames_raw())
            if self.variations_var.get() and names:
                self.var_hint.configure(text="%d names: %s%s" % (len(names), ", ".join(names[:6]), "..." if len(names) > 6 else ""))
            else:
                self.var_hint.configure(text="")

        # ------------------------------------------------------------------ search
        def start(self):
            if self.runner and self.runner.is_alive():
                return
            names = self._expand(self._usernames_raw())
            if not names:
                messagebox.showinfo(APP_NAME, "Type one or more usernames first (separate several with spaces or commas).")
                return
            if not self.sherlock_sites and not engines.MAIGRET_OK:
                messagebox.showerror(APP_NAME, "No engine available - see the log.")
                return
            lower = {n.lower() for n in names}
            self.rows = [r for r in self.rows if r["username"].lower() not in lower]
            self.row_key = {r["key"]: r for r in self.rows}
            self.site_key = {k: v for k, v in self.site_key.items() if k[1].lower() not in lower}
            scope = self.maigret_scope_var.get()
            top = None if scope == "All" else int(scope.split()[-1])
            self.runner = engines.Runner(names, self.sherlock_sites, self.q, timeout=self._timeout(),
                                        proxy=self.proxy_var.get().strip() or None,
                                        use_sherlock=self.use_sherlock_var.get(),
                                        use_maigret=self.use_maigret_var.get(), maigret_top=top)
            self.total, self.done = 0, 0
            self.prog.configure(value=0, maximum=1)
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            self.btn_verify.configure(state="disabled")
            eng = [e for e, on in (("Sherlock" if engines.SHERLOCK_FUNC else "built-in checker", self.use_sherlock_var.get()),
                                   ("Maigret", self.use_maigret_var.get() and engines.MAIGRET_OK)) if on]
            self.logmsg("Searching for %s with %s." % (", ".join(names), " + ".join(eng) or "nothing (enable an engine in Settings)"))
            self.runner.start()
            self._render()

        def stop(self):
            if self.runner and self.runner.is_alive():
                self.runner.stop()
                self.logmsg("Stopping - results already received are kept; requests already in flight end when they time out.")
            if self.verifier and self.verifier.is_alive():
                self.verifier.stop()
            self.btn_stop.configure(state="disabled")

        def _stop_all_workers(self):
            """Ask every background worker to stop (used on close)."""
            workers = [self.runner, self.verifier, self.email_thread, self.domain_thread] + list(self.avatar_threads)
            for th in workers:
                if th and th.is_alive():
                    try:
                        (th.stop if hasattr(th, "stop") else th.stop_flag.set)()
                    except Exception:
                        pass

        def verify(self, rows=None, quiet=False):
            if self.verifier and self.verifier.is_alive():
                return
            if rows is None:
                rows = self.rows
            rows = [r for r in rows if r["status"] == "Claimed"]
            if not rows:
                if not quiet:
                    messagebox.showinfo(APP_NAME, "No claimed results to verify.")
                return
            for r in rows:
                r["verify"] = "..."
            self.verifier = engines.Verifier(rows, self.sherlock_sites, self.q, timeout=self._timeout(),
                                             proxy=self.proxy_var.get().strip() or None)
            self.total, self.done = len(rows), 0
            self.prog.configure(value=0, maximum=max(1, len(rows)))
            self.btn_verify.configure(state="disabled")
            self.btn_stop.configure(state="normal")
            self.logmsg("Verifying %d claimed result(s) (hidden ones included) with a second, independent request..." % len(rows))
            self.verifier.start()
            self._render()

        def verify_selected(self):
            rows = [self._iid_map.get(i) for i in self.tree.selection()]
            self.verify([r for r in rows if r])

        # ------------------------------------------------------------------ queue
        def _poll(self):
            try:
                for _ in range(600):
                    self._handle(self.q.get_nowait())
            except queue.Empty:
                pass
            self.root.after(100, self._poll)

        def _merge_row(self, new):
            engine = new.get("engine", "?")
            username = new["username"]
            k = engines.url_key(new.get("url")) or ("site:" + site_info.norm_name(new["site"]))
            key = (username.lower(), k)
            row = self.row_key.get(key)
            if row is not None and engine in row["eng"] and site_info.norm_name(row["site"]) != site_info.norm_name(new["site"]):
                # same engine, two site entries sharing one URL pattern - keep them apart
                key = (username.lower(), k + "#" + site_info.norm_name(new["site"]))
                row = self.row_key.get(key)
            self.site_key[(engine, username, new["site"])] = key
            if row is None:
                row = {"key": key, "username": username, "site": new["site"], "url": new.get("url"),
                       "eng": {}, "verify": "", "text": "", "http_status": None, "time": None, "context": None,
                       "similar": False, "ids": {}, "tags": [], "final_url": None}
                self.row_key[key] = row
                self.rows.append(row)
            row["eng"][engine] = new.get("status", "Unknown")
            if engine == "Sherlock" and new["site"] != row["site"]:
                row["site"] = new["site"]
            if not row.get("url") and new.get("url"):
                row["url"] = new["url"]
            for fld in ("time", "context", "http_status"):
                if new.get(fld) is not None and row.get(fld) is None:
                    row[fld] = new[fld]
            if new.get("text") and len(new["text"]) > len(row.get("text") or ""):
                row["text"] = new["text"]
            if new.get("similar"):
                row["similar"] = True
            if new.get("ids"):
                row["ids"].update(new["ids"])
            if new.get("tags"):
                row["tags"] = list(new["tags"])
            self._finalise(row)
            return row

        def _finalise(self, row):
            st = set(row["eng"].values())
            if "Claimed" in st:
                row["status"] = "Claimed"
            elif "Available" in st:
                row["status"] = "Available"
            elif "Waf" in st or "WAF" in st:
                row["status"] = "WAF"
            elif "Illegal" in st:
                row["status"] = "Illegal"
            else:
                row["status"] = "Unknown"
            row["engines"] = " + ".join(sorted(row["eng"]))
            info = self.sherlock_sites.get(row["site"]) or {}
            if not info:
                for (eng, u, s), k in self.site_key.items():
                    if k == row["key"] and eng == "Sherlock":
                        info = self.sherlock_sites.get(s) or {}
                        break
            cat, desc = site_info.lookup(row["site"], info or {"urlMain": row.get("url")})
            if not info and row.get("tags") and (desc == "No description available" or cat == "Other"
                                                 or desc == site_info._domain({"urlMain": row.get("url")})):
                mcat, mdesc, _ = engines.maigret_site_meta(type("S", (), {"tags": row["tags"], "url_main": ""})())
                if mdesc and desc in ("No description available", site_info._domain({"urlMain": row.get("url")})):
                    desc = "Maigret tags: " + mdesc
                if mcat and cat == "Other":
                    cat = mcat
            row["category"], row["description"] = cat, desc
            row["detection"] = info.get("errorType") if info else ("maigret" if "Maigret" in row["eng"] else "?")
            engines.score(row, info, self.flaky)

        def _handle(self, msg):
            kind = msg[0]
            if kind == "row":
                self._merge_row(msg[1])
                self.done += 1
                self.prog.configure(value=min(self.done, self.total) if self.total else 0)
                self.status_var.set("Checked %d / %d ... %d claimed so far." % (
                    self.done, self.total, sum(1 for r in self.rows if r["status"] == "Claimed")))
                self._schedule_render()
            elif kind == "enrich":
                _, engine, username, data = msg
                for site, extra in data.items():
                    key = self.site_key.get((engine, username, site))
                    row = self.row_key.get(key) if key else None
                    if not row:
                        row = self._merge_row({"engine": engine, "username": username, "site": site,
                                               "url": extra.get("url"), "status": extra.get("status", "Unknown")})
                    if extra.get("http_status") is not None:
                        row["http_status"] = extra["http_status"]
                    if extra.get("text") and len(extra["text"]) >= len(row.get("text") or ""):
                        row["text"] = extra["text"]
                    if extra.get("url") and not row.get("url"):
                        row["url"] = extra["url"]
                    if extra.get("status") and engine in row["eng"]:
                        row["eng"][engine] = extra["status"]
                    if extra.get("similar"):
                        row["similar"] = True
                    if extra.get("ids"):
                        row["ids"].update(extra["ids"])
                    if extra.get("tags"):
                        row["tags"] = list(extra["tags"])
                    self._finalise(row)
                self._schedule_render()
            elif kind == "start":
                self.total += msg[2]
                self.prog.configure(maximum=max(1, self.total))
                self.logmsg("Checking '%s' against %d site entries..." % (msg[1], msg[2]))
            elif kind == "engine_done":
                pass
            elif kind == "done_user":
                claimed = sum(1 for r in self.rows if r["username"] == msg[1] and r["status"] == "Claimed")
                self.logmsg("'%s': %d claimed." % (msg[1], claimed))
            elif kind == "finished":
                self.btn_avatars.configure(state="normal")
                stopped = msg[1]
                self.btn_start.configure(state="normal")
                self.btn_stop.configure(state="disabled")
                self.btn_verify.configure(state="normal")
                if not stopped:
                    self.prog.configure(value=self.prog["maximum"])
                self._render()
                self.logmsg("Stopped." if stopped else "Search finished.")
                self.status_var.set(self._summary())
                if not stopped and self.auto_verify_var.get():
                    self.verify(quiet=True)
            elif kind == "verified":
                _, key, label, res = msg
                row = self.row_key.get(key)
                if row:
                    row["verify"] = label
                    if res.get("http_status") is not None:
                        row["verify_http"] = res["http_status"]
                    if res.get("final_url"):
                        row["final_url"] = res["final_url"]
                    if res.get("text") and not row.get("text"):
                        row["text"] = res["text"]
                    self._finalise(row)
                self.done += 1
                self.prog.configure(value=min(self.done, self.total))
                self._schedule_render()
            elif kind == "verify_done":
                self.btn_verify.configure(state="normal")
                self.btn_stop.configure(state="disabled")
                c = {}
                for r in self.rows:
                    if r.get("verify") == "...":
                        r["verify"] = ""
                    if r.get("verify"):
                        c[r["verify"]] = c.get(r["verify"], 0) + 1
                self.logmsg("Verify finished: " + (", ".join("%s %d" % kv for kv in sorted(c.items())) or "nothing to do"))
                self._render()
                self.status_var.set(self._summary())
            elif kind == "avatar":
                _, key, res = msg
                row = self.row_key.get(key)
                if row:
                    row["avatar"] = res
                    self._recompute_avatar_matches()
                    self._schedule_render()
                    sel = self._selected_avatar_row()
                    if sel is row:
                        self._show_preview()
            elif kind == "image_loaded":
                _, src, data, ct, err = msg
                if data is None:
                    self.image_preview.configure(image="", text="failed")
                    self._set_text(self.image_out, [("Download failed: %s\n" % err, "bad")])
                else:
                    self._image_loaded(data, ct, src)
            elif kind == "avatars_done":
                self.avatar_threads = [t for t in self.avatar_threads if t.is_alive()]
                if not self.avatar_threads:
                    self.btn_avatars.configure(state="normal")
                got = self._avatar_index_size()
                grouped = sum(1 for r in self.rows if r.get("avatar_matches"))
                if got:
                    self.logmsg("Profile pictures: %d fetched, %d row(s) share a picture with another row." % (got, grouped))
                self._render()
            elif kind == "log":
                self.logmsg(msg[1])
            elif kind == "email_start":
                self.email_rows = []
                self._render_email()
            elif kind == "email_row":
                self.email_rows.append(msg[1])
                self.email_status.set("%d checks back, %d registered." % (
                    len(self.email_rows), sum(1 for r in self.email_rows if r["state"] == "Registered")))
                self._render_email()
            elif kind == "email_done":
                self.eprog.stop()
                self.btn_email.configure(state="normal")
                self.btn_email_stop.configure(state="disabled")
                reg = [r["site"] for r in self.email_rows if r["state"] == "Registered"]
                rl = sum(1 for r in self.email_rows if r["state"] == "Rate limited")
                self.email_status.set("Done: %d registered%s%s" % (
                    len(reg), (" - " + ", ".join(reg[:12]) + ("..." if len(reg) > 12 else "")) if reg else "",
                    (" (%d rate-limited - try again later)" % rl) if rl else ""))
                self.logmsg("Email check finished: %d registered." % len(reg))
            elif kind == "domain_start":
                self._set_text(self.domain_out, [("%s\n" % msg[1], "h")])
            elif kind == "domain_section":
                _, title, lines = msg
                self.domain_out.configure(state="normal")
                self.domain_out.insert("end", "\n" + title + "\n", "h")
                self.domain_out.insert("end", "\n".join(lines) + "\n")
                self.domain_out.configure(state="disabled")
            elif kind == "domain_done":
                self.dprog.stop()
                self.btn_domain.configure(state="normal")

        def _summary(self):
            claimed = [r for r in self.rows if r["status"] == "Claimed"]
            return "%d claimed (%d shown after filters) across %d merged result(s)." % (
                len(claimed), len(self._visible_rows()), len(self.rows))

        # ------------------------------------------------------------------ rendering
        def _schedule_render(self):
            if self._render_after is None:
                self._render_after = self.root.after(150, self._render)

        def _visible_rows(self):
            hide_fp = self.hide_fp_var.get()
            mc = self.min_conf_var.get()
            min_conf = engines.CONF_ORDER.get(mc, 0) if mc != "Any" else 0
            show_avail, show_unknown = self.show_avail_var.get(), self.show_unknown_var.get()
            cat, flt = self.cat_var.get(), self.filter_var.get().strip().lower()
            out = []
            for r in self.rows:
                st = r["status"]
                if st == "Claimed":
                    if hide_fp and r.get("confidence") == "Low":
                        continue
                    if min_conf and engines.CONF_ORDER.get(r.get("confidence", ""), 0) < min_conf:
                        continue
                elif st == "Available":
                    if not show_avail:
                        continue
                elif not show_unknown:
                    continue
                if cat != "All" and r.get("category") != cat:
                    continue
                if flt and flt not in " ".join(str(r.get(k, "")) for k in
                                              ("username", "site", "url", "description", "category", "why", "engines")).lower():
                    continue
                out.append(r)
            return out

        def _render(self):
            self._render_after = None
            if not hasattr(self, "tree"):
                return
            rows = self._visible_rows()
            key = self.sort_col

            def sk(r):
                v = r.get(key)
                if key == "confidence":
                    return (engines.CONF_ORDER.get(v or "", 0), 1 if r.get("verify") == "Verified" else 0)
                if key in ("time", "http_status"):
                    return v if isinstance(v, (int, float)) else -1
                return str(v or "").lower()
            try:
                rows.sort(key=sk, reverse=self.sort_rev)
            except Exception:
                pass
            sel_keys = {self._iid_map[i]["key"] for i in self.tree.selection() if i in self._iid_map}
            self.tree.delete(*self.tree.get_children())
            self._iid_map = {}
            for i, r in enumerate(rows):
                tags = ["odd" if i % 2 else "even"]
                if r["status"] == "Claimed":
                    tags.append({"High": "high", "Medium": "med", "Low": "low"}.get(r.get("confidence"), ""))
                else:
                    tags.append("avail")
                vals = []
                for k, _, _ in COLUMNS:
                    v = r.get("avatar_col") if k == "avatar" else r.get(k)
                    if k == "time" and isinstance(v, (int, float)):
                        v = "%.2f" % v
                    if k == "status" and r.get("context") and r["status"] not in ("Claimed", "Available"):
                        v = "%s (%s)" % (v, str(r["context"])[:40])
                    vals.append("" if v is None else v)
                iid = self.tree.insert("", "end", values=vals, tags=[t for t in tags if t])
                self._iid_map[iid] = r
                if r["key"] in sel_keys:
                    self.tree.selection_add(iid)
            busy = (self.runner and self.runner.is_alive()) or (self.verifier and self.verifier.is_alive())
            if not busy and self.rows:
                self.status_var.set(self._summary())

        def sort_by(self, col):
            if self.sort_col == col:
                self.sort_rev = not self.sort_rev
            else:
                self.sort_col, self.sort_rev = col, col in ("confidence", "time")
            self._render()

        def _show_preview(self):
            sel = self.tree.selection()
            if not sel or sel[0] not in self._iid_map:
                return
            r = self._iid_map[sel[0]]
            chunks = [("%s  " % r["site"], "h"), ("%s\n" % (r.get("url") or ""), None), ("Status: ", "k"),
                      ("%s   " % r["status"], None)]
            if r.get("confidence"):
                chunks.append(("Confidence: ", "k"))
                chunks.append(("%s" % r["confidence"], {"High": "ok", "Medium": "warn", "Low": "bad"}.get(r["confidence"])))
                chunks.append(("  (%s)   " % r.get("why", ""), None))
            if r.get("eng"):
                chunks.append(("Engines: ", "k"))
                chunks.append((", ".join("%s=%s" % kv for kv in r["eng"].items()) + "   ", None))
            if r.get("verify"):
                chunks.append(("Verify: ", "k"))
                chunks.append((r["verify"], {"Verified": "ok", "Failed": "bad", "Blocked": "bad"}.get(r["verify"], "warn")))
            chunks.append(("\n", None))
            pv = engines.page_preview(r.get("text"), r["username"])
            for k, lbl in (("title", "Title"), ("og_title", "OG title"), ("h1", "Heading"),
                           ("description", "Description"), ("canonical", "Canonical"), ("image", "Image")):
                if pv.get(k):
                    chunks.append(("%s: " % lbl, "k"))
                    chunks.append((pv[k] + "\n", None))
            for s in pv.get("snippets", []):
                chunks.append(("Mentions: ", "k"))
                chunks.append((s + "\n", None))
            if r.get("ids"):
                chunks.append(("Extracted (Maigret): ", "k"))
                chunks.append(("; ".join("%s=%s" % kv for kv in list(r["ids"].items())[:20]) + "\n", None))
            if r.get("final_url") and r["final_url"] != r.get("url"):
                chunks.append(("Verify landed on: ", "k"))
                chunks.append((r["final_url"] + "\n", None))
            av = r.get("avatar")
            if av:
                if av.get("data"):
                    chunks.append(("Picture: ", "k"))
                    chunks.append(("%s  %s\n" % (av.get("info", ""), av.get("url", "")), None))
                    if r.get("avatar_matches"):
                        chunks.append(("Same picture on: ", "k"))
                        chunks.append((", ".join(r["avatar_matches"]) + "\n", "ok"))
                    elif self._avatar_index_size() > 1:
                        chunks.append(("No other fetched profile shares this picture.\n", "k"))
                elif av.get("error"):
                    chunks.append(("Picture: ", "k"))
                    chunks.append((av["error"] + "\n", "k"))
            if not pv and not r.get("text"):
                chunks.append(("No page text captured for this result yet - run Verify to fetch the page.", "k"))
            self._set_text(self.preview, chunks)
            self._show_avatar(r)
            if r["status"] == "Claimed" and r.get("text") and av is None:
                self._fetch_avatar_rows([r], quiet=True)

        # ---- profile pictures
        def _show_avatar(self, r):
            av = (r or {}).get("avatar") or {}
            photo = None
            if av.get("data"):
                photo = images.thumbnail_photo(av["data"], tk)
            self._avatar_photo = photo
            if photo is not None:
                self.avatar_label.configure(image=photo, text="")
                self.btn_avatar_search.configure(state="normal")
            else:
                self.avatar_label.configure(image="", text=("fetching..." if av.get("pending") else
                                                            av.get("error", "no picture") if av else "no picture"))
                self.btn_avatar_search.configure(state="normal" if av.get("url") else "disabled")

        def _avatar_index_size(self):
            return sum(1 for r in self.rows if (r.get("avatar") or {}).get("hash"))

        def _fetch_avatar_rows(self, rows, quiet=False):
            rows = [r for r in rows if r["status"] == "Claimed" and r.get("text") and not (r.get("avatar") or {}).get("pending")]
            if not rows:
                if not quiet:
                    messagebox.showinfo(APP_NAME, "No claimed rows with page text - run a search (or Verify) first.")
                return
            for r in rows:
                r["avatar"] = {"pending": True}
            f = engines.AvatarFetcher(rows, self.q, timeout=self._timeout(), proxy=self.proxy_var.get().strip() or None)
            self.avatar_threads.append(f)
            if not quiet:
                self.btn_avatars.configure(state="disabled")
                self.logmsg("Fetching profile pictures for %d claimed result(s)..." % len(rows))
            f.start()

        def fetch_avatars(self):
            self._fetch_avatar_rows(self._visible_rows())

        def fetch_avatar_selected(self):
            rows = [self._iid_map[i] for i in self.tree.selection() if i in self._iid_map]
            for r in rows:
                r.pop("avatar", None)
            self._fetch_avatar_rows(rows)

        def _recompute_avatar_matches(self):
            """Group rows whose profile pictures are the same image (dHash distance)."""
            hashed = [r for r in self.rows if (r.get("avatar") or {}).get("hash")]
            changed = set()
            for r in self.rows:
                if r.pop("avatar_matches", None):
                    changed.add(r["key"])
            for r in hashed:
                same = []
                for o in hashed:
                    if o is r or o["key"] == r["key"]:
                        continue
                    if images.same_picture(r["avatar"]["hash"], o["avatar"]["hash"]):
                        lbl = o["site"] if o["username"].lower() == r["username"].lower() else "%s (%s)" % (o["site"], o["username"])
                        if lbl not in same:
                            same.append(lbl)
                if same:
                    r["avatar_matches"] = sorted(same)
                    changed.add(r["key"])
            for r in self.rows:
                if r["key"] in changed:
                    engines.score(r, self.sherlock_sites.get(r["site"]) or {}, self.flaky)
            for r in self.rows:
                av = r.get("avatar") or {}
                if av.get("hash"):
                    n = len(r.get("avatar_matches") or [])
                    r["avatar_col"] = ("same as %d" % n) if n else "fetched"
                elif av.get("error"):
                    r["avatar_col"] = "none"
                elif av.get("pending"):
                    r["avatar_col"] = "..."
                else:
                    r["avatar_col"] = ""

        def _selected_avatar_row(self):
            sel = self.tree.selection()
            if not sel or sel[0] not in self._iid_map:
                return None
            return self._iid_map[sel[0]]

        def _avatar_url_for(self, r):
            av = r.get("avatar") or {}
            if av.get("url"):
                return av["url"]
            cands = images.find_avatar_candidates(r.get("text") or "", r.get("url"), r.get("username"))
            return cands[0] if cands else None

        def reverse_search_selected(self, engine):
            r = self._selected_avatar_row()
            if not r:
                return
            url = self._avatar_url_for(r)
            if not url:
                messagebox.showinfo(APP_NAME, "No profile picture is known for this row yet - fetch it first, "
                                    "or run Verify so the page text is available.")
                return
            for name, u in images.search_urls(url):
                if engine is None or name == engine:
                    webbrowser.open(u)
            self.logmsg("Reverse image search (%s) for %s" % (engine or "all engines", url))

        def open_avatar_selected(self):
            r = self._selected_avatar_row()
            url = self._avatar_url_for(r) if r else None
            if url:
                webbrowser.open(url)

        def avatar_to_image_tab(self):
            r = self._selected_avatar_row()
            if not r:
                return
            av = r.get("avatar") or {}
            url = self._avatar_url_for(r)
            if not url and not av.get("data"):
                messagebox.showinfo(APP_NAME, "No profile picture is known for this row yet.")
                return
            self.image_url_var.set(url or "")
            self.image_file = None
            if av.get("data"):
                self._image_loaded(av["data"], av.get("ct", ""), url, label="%s @ %s" % (r["username"], r["site"]))
            else:
                self.image_load()
            self.nb.select(self.tab_image)

        # ------------------------------------------------------------------ actions
        def open_selected(self):
            sel = self.tree.selection()
            if len(sel) > 15 and not messagebox.askyesno(APP_NAME, "Open %d tabs?" % len(sel)):
                return
            for iid in sel:
                r = self._iid_map.get(iid)
                if r and r.get("url"):
                    webbrowser.open(r["url"])

        def copy_urls(self):
            urls = [self._iid_map[i].get("url") or "" for i in self.tree.selection() if i in self._iid_map]
            if urls:
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(urls))

        def copy_rows(self):
            lines = ["\t".join(str(v) for v in self.tree.item(i, "values")) for i in self.tree.selection()]
            if lines:
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(lines))

        def select_all(self):
            self.tree.selection_set(self.tree.get_children())

        def clear(self):
            self.rows, self.row_key, self.site_key = [], {}, {}
            self._render()
            self._set_text(self.preview, [])
            self._show_avatar(None)
            self.status_var.set("Cleared.")

        def _rescore_all(self):
            for r in self.rows:
                self._finalise(r)
            self._render()

        def mark_flaky(self):
            names = {self._iid_map[i]["site"] for i in self.tree.selection() if i in self._iid_map}
            for n in names:
                if n not in self.S["flaky_sites"]:
                    self.S["flaky_sites"].append(n)
            self.flaky = set(site_info.norm_name(n) for n in self.S["flaky_sites"])
            self._rescore_all()

        def unmark_flaky(self):
            names = {site_info.norm_name(self._iid_map[i]["site"]) for i in self.tree.selection() if i in self._iid_map}
            self.S["flaky_sites"] = [n for n in self.S["flaky_sites"] if site_info.norm_name(n) not in names]
            self.flaky = set(site_info.norm_name(n) for n in self.S["flaky_sites"])
            self._rescore_all()

        def _list_editor(self, title, intro, items, on_save, defaults):
            win = tk.Toplevel(self.root)
            win.title(title)
            win.geometry("460x540")
            win.configure(bg=self.P["bg"])
            ttk.Label(win, text=intro, style="Muted.TLabel", wraplength=430, justify="left").pack(anchor="w", padx=10, pady=(10, 4))
            txt = tk.Text(win, wrap="none", bg=self.P["field"], fg=self.P["fg"], insertbackground=self.P["fg"],
                          relief="flat", highlightthickness=1, highlightbackground=self.P["border"])
            txt.pack(fill="both", expand=True, padx=10)
            txt.insert("1.0", "\n".join(items))
            bf = ttk.Frame(win)
            bf.pack(fill="x", padx=10, pady=8)

            def save():
                on_save([l.strip() for l in txt.get("1.0", "end").splitlines() if l.strip()])
                win.destroy()

            def reset():
                txt.delete("1.0", "end")
                txt.insert("1.0", "\n".join(defaults))
            ttk.Button(bf, text="Save", style="Accent.TButton", command=save).pack(side="right")
            ttk.Button(bf, text="Reset to defaults", command=reset).pack(side="right", padx=(0, 6))
            ttk.Button(bf, text="Cancel", command=win.destroy).pack(side="left")

        def edit_flaky(self):
            def save(names):
                self.S["flaky_sites"] = names
                self.flaky = set(site_info.norm_name(n) for n in names)
                self._rescore_all()
            self._list_editor("False-positive-prone sites",
                              "One site name per line. Claimed results from these sites are scored Low and hidden "
                              "while 'Hide likely false positives' is on.",
                              self.S["flaky_sites"], save, site_info.DEFAULT_FLAKY_SITES)

        def edit_patterns(self):
            def save(pats):
                self.S["variation_patterns"] = pats or list(engines.DEFAULT_VARIATION_PATTERNS)
                self._variation_hint()
            self._list_editor("Username variation patterns",
                              "One pattern per line; {u} is the username. Separator variants (dan.lowther / "
                              "dan_lowther / danlowther) and a lower-case form are always tried too. At most 16 "
                              "names per username are searched.",
                              self.S.get("variation_patterns") or engines.DEFAULT_VARIATION_PATTERNS, save,
                              engines.DEFAULT_VARIATION_PATTERNS)

        def export(self, fmt):
            rows = self._visible_rows()
            if not rows:
                messagebox.showinfo(APP_NAME, "Nothing to export - no rows are visible.")
                return
            ext = {"csv": ".csv", "json": ".json", "txt": ".txt"}[fmt]
            names = "_".join(sorted({r["username"] for r in rows}))[:60] or "results"
            path = filedialog.asksaveasfilename(defaultextension=ext, initialfile="sherlock_%s%s" % (names, ext),
                                                filetypes=[(fmt.upper(), "*" + ext), ("All files", "*.*")])
            if not path:
                return
            keys = [c[0] for c in COLUMNS]
            try:
                if fmt == "csv":
                    with open(path, "w", newline="", encoding="utf-8") as f:
                        w = csv.writer(f)
                        w.writerow([c[1] for c in COLUMNS])
                        for r in rows:
                            w.writerow(["" if r.get(k) is None else r.get(k) for k in keys])
                elif fmt == "json":
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump([{k: r.get(k) for k in keys + ["eng", "ids"]} for r in rows], f, indent=2, default=str)
                else:
                    with open(path, "w", encoding="utf-8") as f:
                        for r in rows:
                            if r.get("url"):
                                f.write("%s\t%s\t%s\t%s\n" % (r["username"], r["site"], r.get("confidence", ""), r["url"]))
                self.logmsg("Exported %d row(s) to %s" % (len(rows), path))
            except Exception as e:
                messagebox.showerror(APP_NAME, "Export failed: %s" % e)

        # ------------------------------------------------------------------ email tab
        def email_start(self):
            if self.email_thread and self.email_thread.is_alive():
                return
            email = self.email_var.get().strip()
            if not tools.EMAIL_RX.match(email):
                messagebox.showinfo(APP_NAME, "That does not look like an email address.")
                return
            self.email_thread = tools.EmailChecker(email, self.q, timeout=min(self._timeout(), 15))
            self.btn_email.configure(state="disabled")
            self.btn_email_stop.configure(state="normal")
            self.eprog.start(12)
            self.email_status.set("Checking %s ..." % email)
            self.logmsg("Email check for %s started." % email)
            self.email_thread.start()

        def email_stop(self):
            if self.email_thread and self.email_thread.is_alive():
                self.email_thread.stop()
            self.btn_email_stop.configure(state="disabled")

        def _render_email(self):
            only = self.email_only_var.get()
            self.etree.delete(*self.etree.get_children())
            order = {"Registered": 0, "Accepts mail": 0, "Rate limited": 1, "Unknown": 2, "Error": 3,
                     "Not registered": 4, "No MX record": 4}
            rows = sorted(self.email_rows, key=lambda r: (order.get(r["state"], 2), r["site"].lower()))
            self._email_iid = {}
            for i, r in enumerate(rows):
                interesting = r["state"] in ("Registered", "Accepts mail") or r.get("recovery") or r.get("phone")
                if only and not interesting and r["state"] != "Rate limited":
                    continue
                tag = "high" if r["state"] in ("Registered", "Accepts mail") else \
                    "med" if r["state"] == "Rate limited" else "avail"
                iid = self.etree.insert("", "end", values=[r.get(k, "") for k, _, _ in EMAIL_COLUMNS],
                                        tags=["odd" if i % 2 else "even", tag])
                self._email_iid[iid] = r

        def _email_open(self):
            for iid in self.etree.selection():
                r = getattr(self, "_email_iid", {}).get(iid)
                if r:
                    m = re.search(r"https?://\S+", r.get("other") or "")
                    webbrowser.open(m.group(0) if m else "https://" + (r.get("domain") or ""))

        def email_export(self):
            if not self.email_rows:
                messagebox.showinfo(APP_NAME, "Nothing to export yet.")
                return
            path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                initialfile="email_%s.csv" % re.sub(r"[^\w.-]", "_", self.email_var.get()),
                                                filetypes=[("CSV", "*.csv")])
            if not path:
                return
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow([c[1] for c in EMAIL_COLUMNS])
                for r in self.email_rows:
                    w.writerow([r.get(k, "") for k, _, _ in EMAIL_COLUMNS])
            self.logmsg("Exported %d email rows to %s" % (len(self.email_rows), path))

        # ------------------------------------------------------------------ phone tab
        def phone_lookup(self):
            lines = tools.phone_lookup(self.phone_var.get(), self.region_var.get().strip().upper() or "GB")
            chunks = []
            for k, v in lines:
                chunks.append(("%-20s" % (k + ":"), "k"))
                tag = "ok" if (k == "Valid" and v == "yes") else "bad" if k == "Error" or (k == "Valid" and v == "no") else None
                chunks.append((str(v) + "\n", tag))
            self._set_text(self.phone_out, chunks)

        # ------------------------------------------------------------------ domain tab
        def domain_start(self):
            if self.domain_thread and self.domain_thread.is_alive():
                return
            d = tools.clean_domain(self.domain_var.get())
            if not d:
                return
            self.domain_thread = tools.DomainLookup(d, self.q, want_subdomains=self.subdomains_var.get())
            self.btn_domain.configure(state="disabled")
            self.dprog.start(12)
            self._set_text(self.domain_out, [("Looking up %s ...\n" % d, "k")])
            self.domain_thread.start()

        # ------------------------------------------------------------------ help/close
        def help_fp(self):
            messagebox.showinfo("False-positive filter",
                "Both engines decide a profile exists from a status code, a redirect, or an error string "
                "missing from the page. Bot walls, rate limits and soft-404 pages fool those rules, so every "
                "Claimed row gets a confidence:\n\n"
                "  High   - matched cleanly (stronger when Sherlock and Maigret agree)\n"
                "  Medium - username not found anywhere in the page, near-empty page, Maigret 'similar' page, "
                "or no page text available\n"
                "  Low    - site is on the false-positive list; HTTP 403/429/5xx; a bot wall or a 'not found' "
                "message in the page; the engines disagree; redirected to a generic/login page; or a Verify "
                "re-request failed\n\n"
                "'Hide likely false positives' hides Low rows; 'Min confidence' tightens further.\n\n"
                "Verify re-requests each visible claimed URL with a browser-like User-Agent, applies the "
                "same rule plus the soft-404, redirect and username-in-page checks, and marks the row "
                "Verified / Unclear / Failed / Blocked. Tick 'Auto-verify when finished' to do this "
                "automatically after every search.\n\n"
                "The Why column and the preview pane spell out the reasons for each row.")

        def about(self):
            messagebox.showinfo("About", "%s %s\n\nSherlock %s\nMaigret %s\nholehe %s\n\n%s %s / Python %s\nSettings: %s" % (
                APP_NAME, VERSION, engines.SHERLOCK_VERSION, engines.MAIGRET_VERSION, tools.holehe_status()[1],
                platform.system(), platform.release(), platform.python_version(), os.path.join(HERE, SETTINGS_FILE)))

        def on_close(self):
            # Whatever happens below, the process is gone within 3 s: worker threads, Maigret's event
            # loop and any HTTP requests still in flight are not allowed to keep it alive.
            threading.Timer(3.0, lambda: os._exit(0)).start()
            try:
                self._stop_all_workers()
                S = self.S
                S["timeout"] = self._timeout()
                S["proxy"] = self.proxy_var.get()
                S["hide_fp"] = bool(self.hide_fp_var.get())
                S["min_conf"] = self.min_conf_var.get()
                S["show_available"] = bool(self.show_avail_var.get())
                S["show_unknown"] = bool(self.show_unknown_var.get())
                S["show_desc"] = bool(self.show_desc_var.get())
                S["category"] = self.cat_var.get()
                S["use_sherlock"] = bool(self.use_sherlock_var.get())
                S["use_maigret"] = bool(self.use_maigret_var.get())
                S["maigret_scope"] = self.maigret_scope_var.get()
                S["auto_verify"] = bool(self.auto_verify_var.get())
                S["variations"] = bool(self.variations_var.get())
                S["phone_region"] = self.region_var.get()
                S["email_only_registered"] = bool(self.email_only_var.get())
                S["domain_subdomains"] = bool(self.subdomains_var.get())
                try:
                    S["last_tab"] = int(self.nb.index(self.nb.select()))
                except Exception:
                    pass
                S["geometry"] = str(self.root.geometry())
                save_settings(S)
            finally:
                try:
                    self.root.destroy()
                finally:
                    os._exit(0)

    root = tk.Tk()
    App(root)
    root.mainloop()


def selftest():
    """Non-GUI health check used by the build scripts."""
    lines = ["%s %s selftest" % (APP_NAME, VERSION),
             "python %s  frozen=%s" % (platform.python_version(), bool(getattr(sys, "frozen", False))),
             "app dir: %s" % HERE]
    ok = True
    try:
        import tkinter
        lines.append("tkinter %s OK" % tkinter.TkVersion)
        if float(tkinter.TkVersion) < 8.6:
            ok = False
            lines.append("PROBLEM: Tk older than 8.6")
    except Exception as e:
        ok = False
        lines.append("PROBLEM: tkinter import failed: %r" % e)
    try:
        import requests
        lines.append("requests %s OK" % requests.__version__)
    except Exception as e:
        ok = False
        lines.append("PROBLEM: requests missing: %r" % e)
    lines.append("sherlock_project: %s%s" % (engines.SHERLOCK_VERSION,
                 "" if engines.SHERLOCK_FUNC else " (engine NOT importable: %s)" % engines.SHERLOCK_ERROR))
    try:
        data, src = engines.load_sherlock_sites(HERE)
        lines.append("sherlock sites: %d (%s)" % (len(data), src))
        n = sum(1 for k in data if site_info.lookup(k, data[k])[1] != "No description available")
        lines.append("descriptions: %d/%d sherlock sites described" % (n, len(data)))
    except Exception as e:
        ok = False
        lines.append("PROBLEM: %s" % e)
    if engines.MAIGRET_OK:
        try:
            lines.append("maigret %s: %d sites" % (engines.MAIGRET_VERSION, len(engines.maigret_sites())))
        except Exception as e:
            lines.append("WARNING: maigret installed but database failed: %r" % e)
    else:
        lines.append("maigret: not bundled (%s) - optional, Sherlock-only searching" % (engines.MAIGRET_ERROR or "?"))
    hok, hver = tools.holehe_status()
    lines.append("holehe: %s" % (hver if hok else "not bundled (%s) - optional" % hver))
    try:
        import PIL
        from PIL import ImageTk  # noqa
        lines.append("Pillow %s OK (picture previews + matching)" % getattr(PIL, "__version__", ""))
    except Exception as e:
        lines.append("WARNING: Pillow missing (%r) - JPEG/WebP previews and picture matching unavailable" % e)
    try:
        import phonenumbers
        lines.append("phonenumbers %s OK" % getattr(phonenumbers, "__version__", ""))
    except Exception as e:
        lines.append("WARNING: phonenumbers missing (%r) - Phone tab will not work" % e)
    try:
        import dns.resolver  # noqa
        lines.append("dnspython OK")
    except Exception:
        lines.append("WARNING: dnspython missing - DNS limited to A/AAAA")
    lines.append("RESULT: " + ("OK" if ok else "PROBLEMS FOUND"))
    return ok, "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        ok, text = selftest()
        print(text)
        sys.exit(0 if ok else 1)
    main()
