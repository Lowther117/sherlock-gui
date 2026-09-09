"""Search engines behind Sherlock GUI: Sherlock, Maigret, the built-in checker,
false-positive scoring and the Verify pass.

Everything here is GUI-free and thread-safe; results are pushed to a
queue.Queue as ("row", row_dict) messages.  Both external engines are
imported defensively - their APIs have shifted between releases - and the
app keeps working with whichever ones are available.
"""

import asyncio
import inspect
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlsplit

import site_info

logging.getLogger("maigret").setLevel(logging.ERROR)
logging.getLogger("asyncio").setLevel(logging.ERROR)

# ----------------------------------------------------------------------------
# Output-stream guard (windowed builds have no console; colorama & friends
# touch sys.stdout at import time)
# ----------------------------------------------------------------------------


def guard_streams():
    class _Null:
        encoding = "utf-8"

        def write(self, *a, **k):
            return 0

        def flush(self):
            pass

        def isatty(self):
            return False

        def fileno(self):
            raise OSError("no console")
    if sys.stdout is None:
        sys.stdout = _Null()
    if sys.stderr is None:
        sys.stderr = _Null()
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass


guard_streams()

# ----------------------------------------------------------------------------
# Sherlock
# ----------------------------------------------------------------------------

SHERLOCK_FUNC = None
QueryNotifyBase = object
SHERLOCK_ERROR = None
SHERLOCK_VERSION = "not installed"


def _load_sherlock():
    global SHERLOCK_FUNC, QueryNotifyBase, SHERLOCK_ERROR, SHERLOCK_VERSION
    try:
        from sherlock_project.sherlock import sherlock as _fn
        SHERLOCK_FUNC = _fn
        try:
            from sherlock_project.notify import QueryNotify as _QN
            QueryNotifyBase = _QN
        except Exception:
            pass
        try:
            from sherlock_project import __version__ as _v
            SHERLOCK_VERSION = str(_v)
        except Exception:
            try:
                from importlib.metadata import version
                SHERLOCK_VERSION = version("sherlock-project")
            except Exception:
                SHERLOCK_VERSION = "unknown"
    except Exception as e:
        SHERLOCK_ERROR = repr(e)


_load_sherlock()


def _resource_candidates(rel, here):
    out = []
    base = getattr(sys, "_MEIPASS", None)
    if base:
        out.append(os.path.join(base, rel))
    out.append(os.path.join(here, rel))
    out.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), rel))
    return out


def load_sherlock_sites(here):
    """Return ({site_name: info_dict}, source_label) for Sherlock's data.json."""
    try:
        from sherlock_project.sites import SitesInformation
        data_path = None
        try:
            import sherlock_project
            p = os.path.join(os.path.dirname(sherlock_project.__file__), "resources", "data.json")
            if os.path.isfile(p):
                data_path = p
        except Exception:
            pass
        sites = SitesInformation(data_path) if data_path else SitesInformation()
        data = {}
        for s in sites:
            data[s.name] = dict(s.information)
            if getattr(s, "is_nsfw", None) and "isNSFW" not in data[s.name]:
                data[s.name]["isNSFW"] = True
        if data:
            return data, "sherlock_project %s" % SHERLOCK_VERSION
    except Exception:
        pass
    for p in _resource_candidates(os.path.join("sherlock_project", "resources", "data.json"), here) + \
            _resource_candidates("data.json", here):
        if os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as f:
                raw = json.load(f)
            raw.pop("$schema", None)
            return {k: v for k, v in raw.items() if isinstance(v, dict)}, p
    raise RuntimeError(
        "Sherlock's site list (data.json) was not found. Install it with:  pip install sherlock-project"
        + (("\n\nImport error: " + SHERLOCK_ERROR) if SHERLOCK_ERROR else ""))


# ----------------------------------------------------------------------------
# Maigret
# ----------------------------------------------------------------------------

MAIGRET_OK = False
MAIGRET_ERROR = None
MAIGRET_VERSION = "not installed"
_maigret_db = None
_maigret_lock = threading.Lock()


def _load_maigret():
    global MAIGRET_OK, MAIGRET_ERROR, MAIGRET_VERSION
    try:
        import maigret  # noqa
        from maigret.maigret import maigret as _fn  # noqa
        from maigret.sites import MaigretDatabase  # noqa
        MAIGRET_OK = True
        try:
            MAIGRET_VERSION = str(getattr(maigret, "__version__", None) or "")
            if not MAIGRET_VERSION:
                from importlib.metadata import version
                MAIGRET_VERSION = version("maigret")
        except Exception:
            MAIGRET_VERSION = "unknown"
    except Exception as e:
        MAIGRET_ERROR = repr(e)


_load_maigret()


def maigret_db():
    """Load Maigret's site database once."""
    global _maigret_db
    if not MAIGRET_OK:
        return None
    with _maigret_lock:
        if _maigret_db is not None:
            return _maigret_db
        import maigret
        from maigret.sites import MaigretDatabase
        pkg = os.path.dirname(maigret.__file__)
        path = None
        for cand in (getattr(maigret, "MAIGRET_DB_FILE", None),
                     os.path.join(pkg, "resources", "data.json"),
                     os.path.join(pkg, "resources", "data.yaml")):
            if cand and os.path.isfile(cand):
                path = cand
                break
        db = MaigretDatabase()
        loaded = False
        for meth in ("load_from_path", "load_from_file", "load_from_json"):
            fn = getattr(db, meth, None)
            if fn is None or path is None:
                continue
            try:
                r = fn(path)
                db = r if r is not None else db
                loaded = True
                break
            except Exception:
                continue
        if not loaded:
            raise RuntimeError("Maigret database could not be loaded (%s)" % path)
        _maigret_db = db
        return db


def maigret_sites(top=None):
    """{name: MaigretSite} - all enabled username sites, best-ranked first."""
    db = maigret_db()
    if db is None:
        return {}
    kwargs = {"disabled": False, "id_type": "username"}
    try:
        params = inspect.signature(db.ranked_sites_dict).parameters
    except Exception:
        params = {}
    if "top" in params:
        kwargs["top"] = top or 100000
    if "tags" in params:
        kwargs["tags"] = []
    if "names" in params:
        kwargs["names"] = []
    kwargs = {k: v for k, v in kwargs.items() if k in params} if params else kwargs
    try:
        sd = db.ranked_sites_dict(**kwargs)
    except Exception:
        sd = {}
        for s in getattr(db, "sites", []):
            if not getattr(s, "disabled", False):
                sd[s.name] = s
    return sd


def maigret_site_meta(site):
    """(category, description, url_main) from a MaigretSite's tags."""
    tags = [str(t) for t in (getattr(site, "tags", None) or [])]
    url_main = getattr(site, "url_main", "") or ""
    country = [t for t in tags if len(t) == 2 and t.isalpha() and t.islower()]
    topics = [t for t in tags if t not in country]
    cat = None
    tag_map = {
        "coding": "Developer", "tech": "Developer", "hacking": "Security", "security": "Security",
        "gaming": "Gaming", "games": "Gaming", "music": "Music", "video": "Video", "streaming": "Video",
        "photo": "Photo", "art": "Art & Design", "design": "Art & Design", "forum": "Forum",
        "blog": "Blogging", "news": "Blogging", "porn": "Adult", "adult": "Adult", "sex": "Adult",
        "dating": "Dating", "shopping": "Shopping", "business": "Business", "freelance": "Business",
        "finance": "Finance & Crypto", "crypto": "Finance & Crypto", "education": "Education",
        "science": "Education", "books": "Books & Writing", "writing": "Books & Writing",
        "sport": "Sport & Outdoors", "sports": "Sport & Outdoors", "travel": "Other",
        "social": "Social", "messaging": "Social", "fediverse": "Fediverse", "mastodon": "Fediverse",
        "q&a": "Q&A", "qa": "Q&A",
    }
    for t in topics:
        if t.lower() in tag_map:
            cat = tag_map[t.lower()]
            break
    desc_bits = []
    if topics:
        desc_bits.append(", ".join(topics[:4]))
    if country:
        desc_bits.append("(" + ", ".join(c.upper() for c in country[:3]) + ")")
    return cat, " ".join(desc_bits), url_main


# ----------------------------------------------------------------------------
# Built-in checker (mirrors Sherlock's rules) - Verify pass + fallback engine
# ----------------------------------------------------------------------------

VERIFY_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
WAF_HINTS = (
    ".loading-spinner{visibility:hidden}body.no-js .challenge-running{display:none}",
    "<span id=\"challenge-error-text\">",
    "AwsWafIntegration.forceRefreshToken",
    "{return l.onPageView}}),Object.defineProperty(r,\"perimeterxIdentifiers\"",
    "cf-browser-verification", "Just a moment...", "Attention Required! | Cloudflare",
    "Request unsuccessful. Incapsula", "_Incapsula_Resource", "px-captcha",
    "Checking your browser before accessing", "DDoS-Guard", "captcha-delivery.com",
    "Pardon Our Interruption", "Access to this page has been denied",
)
# Phrases that mean "no such profile" even when the HTTP status says 200.
SOFT404_HINTS = (
    "page not found", "user not found", "profile not found", "account not found",
    "this page doesn't exist", "this page does not exist", "page doesn't exist",
    "doesn't exist", "does not exist", "no longer available", "has been suspended",
    "account suspended", "user has been banned", "this account has been deactivated",
    "couldn't find this account", "could not find this account", "not be found",
    "sorry, nobody on reddit goes by that name", "there is no such user", "no such user",
    "the page you requested was not found", "404 not found", "error 404", "http 404",
    "oops! that page can", "we couldn't find", "we could not find", "nothing to see here",
    "the user you are looking for", "this user does not exist", "user does not exist",
    "profile unavailable", "this profile is unavailable", "is not available",
    "seite nicht gefunden", "nicht gefunden", "página no encontrada", "страница не найдена",
    "пользователь не найден", "page introuvable", "pagina non trovata",
)
LOGIN_HINTS = ("/login", "/signin", "/sign-in", "/signup", "/sign-up", "/register", "/auth", "/account/login")
CONF_ORDER = {"High": 3, "Medium": 2, "Low": 1, "": 0}


def url_key(url):
    """Normalise a profile URL so the same page from two engines matches."""
    if not url:
        return ""
    try:
        p = urlsplit(url.strip())
        host = (p.netloc or "").lower()
        if host.startswith("www."):
            host = host[4:]
        path = (p.path or "").rstrip("/").lower()
        return host + path
    except Exception:
        return url.strip().lower()


def _redirect_suspicious(req_url, final_url):
    """True if a request ended somewhere that is clearly not the profile."""
    if not final_url or final_url == req_url:
        return False
    try:
        a, b = urlsplit(req_url), urlsplit(final_url)
    except Exception:
        return False
    fp = (b.path or "/").lower()
    if any(h in fp for h in LOGIN_HINTS):
        return True
    if fp in ("", "/") and (a.path or "/") not in ("", "/"):
        return True
    return False


def own_check(name, info, username, timeout=15, proxy=None, ua=VERIFY_UA):
    """Check one Sherlock-style site entry.  Returns a result dict."""
    import requests
    out = {"site": name, "username": username, "status": "Unknown", "http_status": None,
           "url": None, "final_url": None, "time": None, "context": None, "text": ""}
    rx = info.get("regexCheck")
    if rx and not re.search(rx, username):
        out["status"] = "Illegal"
        out["url"] = info.get("url", "").replace("{}", username)
        return out
    url = info.get("url", "").replace("{}", username)
    probe = info.get("urlProbe")
    req_url = probe.replace("{}", username) if probe else url
    out["url"] = url
    method = (info.get("request_method") or "GET").upper()
    payload = info.get("request_payload")
    headers = {"User-Agent": ua, "Accept-Language": "en-GB,en;q=0.9"}
    headers.update(info.get("headers") or {})
    if isinstance(payload, dict):
        payload = json.dumps(payload).replace("{}", username)
        headers.setdefault("Content-Type", "application/json")
    etype = info.get("errorType", "status_code")
    allow_redirects = etype != "response_url"
    proxies = {"http": proxy, "https": proxy} if proxy else None
    t0 = time.time()
    try:
        r = requests.request(method, req_url, headers=headers, data=payload, timeout=timeout,
                             allow_redirects=allow_redirects, proxies=proxies)
    except requests.exceptions.RequestException as e:
        out["context"] = type(e).__name__
        out["time"] = time.time() - t0
        return out
    out["time"] = time.time() - t0
    out["http_status"] = r.status_code
    out["final_url"] = r.url
    text = r.text or ""
    out["text"] = text[:200000]
    if any(h in text for h in WAF_HINTS) or r.status_code in (403, 429):
        out["status"] = "WAF"
        return out
    if etype == "message":
        msgs = info.get("errorMsg") or []
        if isinstance(msgs, str):
            msgs = [msgs]
        out["status"] = "Available" if any(m in text for m in msgs) else "Claimed"
    elif etype == "status_code":
        codes = info.get("errorCode")
        if isinstance(codes, int):
            codes = [codes]
        if codes and r.status_code in codes:
            out["status"] = "Available"
        elif 200 <= r.status_code < 300:
            out["status"] = "Claimed"
        else:
            out["status"] = "Available"
    elif etype == "response_url":
        out["status"] = "Claimed" if 200 <= r.status_code < 300 else "Available"
    else:
        out["status"] = "Unknown"
        out["context"] = "unknown errorType %r" % etype
    return out


# ----------------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------------


def _title_of(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def score(row, info, flaky_set):
    """Set row['confidence'] and row['why'] from everything known about the row."""
    if row.get("status") != "Claimed":
        row["confidence"] = ""
        row["why"] = ""
        return
    info = info or {}
    reasons = []
    conf = "High"

    def down(level, why):
        nonlocal conf
        if CONF_ORDER[level] < CONF_ORDER[conf]:
            conf = level
        reasons.append(why)

    if site_info.norm_name(row["site"]) in flaky_set:
        down("Low", "site on false-positive list")

    eng = row.get("eng") or {}
    claimed_by = sorted(e for e, s in eng.items() if s == "Claimed")
    denied_by = sorted(e for e, s in eng.items() if s == "Available")
    if len(claimed_by) >= 2:
        reasons.append("found by " + " + ".join(claimed_by))
    if claimed_by and denied_by:
        down("Low", "engines disagree (%s says available)" % ", ".join(denied_by))
    if row.get("similar"):
        down("Medium", "Maigret: looks like a similar/generic page")

    hs = row.get("http_status")
    if isinstance(hs, int):
        if hs in (403, 429) or hs >= 500:
            down("Low", "HTTP %d (blocked/rate-limited)" % hs)
        elif not (200 <= hs < 300) and info.get("errorType") == "status_code":
            down("Low", "HTTP %d for a status-code site" % hs)

    text = row.get("text") or ""
    low = text.lower()
    etype = info.get("errorType", row.get("detection", ""))
    uname = row["username"].lower()
    if text:
        if any(h in text for h in WAF_HINTS):
            down("Low", "bot wall in page")
        title = _title_of(text).lower()
        hit = next((h for h in SOFT404_HINTS if h in title), None) or \
            next((h for h in SOFT404_HINTS if h in low[:6000]), None)
        if hit:
            down("Low", "page says '%s'" % hit)
        if uname not in low:
            down("Medium", "username not in page")
        elif len(text) < 300 and etype == "status_code":
            down("Medium", "almost empty page")
    elif etype == "message":
        down("Medium", "no page text to inspect")

    if _redirect_suspicious(row.get("url") or "", row.get("final_url") or ""):
        down("Low", "redirected to a generic/login page")

    if etype == "response_url" and conf == "High":
        reasons.append("redirect-based check")

    am = row.get("avatar_matches") or []
    if am:
        n = len(am)
        reasons.insert(0, "same profile picture as %s" % (", ".join(am[:3]) + (" +%d" % (n - 3) if n > 3 else "")))
        if conf == "Low" and "site on false-positive list" not in reasons:
            conf = "Medium"
        elif conf == "Medium":
            conf = "High"

    v = row.get("verify")
    if v == "Verified":
        if site_info.norm_name(row["site"]) in flaky_set:
            conf = "Medium"
            reasons = ["re-request confirmed, but site is on the false-positive list"] + \
                [x for x in reasons if x != "site on false-positive list"]
        elif conf == "Low":
            conf = "Medium"
            reasons.insert(0, "re-request confirmed despite warnings")
        else:
            conf = "High"
            reasons.insert(0, "re-request confirmed")
    elif v in ("Failed", "Blocked"):
        conf = "Low"
        reasons.insert(0, "re-request %s" % v.lower())
    elif v == "Unclear" and conf == "High":
        conf = "Medium"
        reasons.insert(0, "re-request unclear")

    row["confidence"] = conf
    row["why"] = "; ".join(reasons) if reasons else "matched cleanly"


def verify_row(row, info, timeout, proxy):
    """Second, independent request for a claimed result.  Returns (label, result)."""
    info = info or {}
    if not info.get("url"):
        # Maigret-only site: synthesise a status-code check on the profile URL.
        info = {"url": row["url"].replace(row["username"], "{}", 1) if row.get("url") else "",
                "errorType": "status_code"}
        if "{}" not in info["url"]:
            return "Unclear", {}
    res = own_check(row["site"], info, row["username"], timeout=timeout, proxy=proxy)
    st = res["status"]
    if st == "WAF":
        return "Blocked", res
    if st in ("Available", "Illegal"):
        return "Failed", res
    if st != "Claimed":
        return "Unclear", res
    txt = (res.get("text") or "")
    low = txt.lower()
    title = _title_of(txt).lower()
    if any(h in title for h in SOFT404_HINTS) or any(h in low[:6000] for h in SOFT404_HINTS):
        return "Failed", res
    if _redirect_suspicious(res.get("url") or "", res.get("final_url") or ""):
        return "Failed", res
    if txt and row["username"].lower() not in low:
        return "Unclear", res
    return "Verified", res


# ----------------------------------------------------------------------------
# Username variations
# ----------------------------------------------------------------------------

DEFAULT_VARIATION_PATTERNS = [
    "{u}", "{u}_", "_{u}", "{u}1", "{u}01", "{u}123", "{u}x", "x{u}", "the{u}", "real{u}",
    "{u}official", "{u}uk",
]


def variations(username, patterns=None, max_total=16):
    """Return a de-duplicated list of username variants, the original first."""
    pats = patterns or DEFAULT_VARIATION_PATTERNS
    base = username.strip()
    seps = [c for c in "._-" if c in base]
    roots = [base]
    if seps:
        stripped = re.sub(r"[._-]", "", base)
        roots.append(stripped)
        for s in "._-":
            roots.append(re.sub(r"[._-]", s, base))
    lower = base.lower()
    if lower != base:
        roots.append(lower)
    out, seen = [], set()
    for r in roots:
        for p in pats:
            v = p.replace("{u}", r)
            k = v.lower()
            if v and k not in seen:
                seen.add(k)
                out.append(v)
            if len(out) >= max_total:
                return out
    return out


# ----------------------------------------------------------------------------
# Runner: Sherlock and Maigret side by side
# ----------------------------------------------------------------------------


class RunStopped(Exception):
    """Raised inside an engine callback to abort the engine when Stop is pressed."""


class _SherlockNotify(QueryNotifyBase):
    def __init__(self, q, username, runner):
        try:
            super().__init__()
        except Exception:
            pass
        self.q, self.username, self.runner = q, username, runner

    def start(self, message=None):
        pass

    def update(self, result):
        if self.runner.stop_flag.is_set():
            raise RunStopped()
        try:
            raw = getattr(result.status, "name", None) or getattr(result.status, "value", None) or str(result.status)
            status = str(raw).strip().title()
            if status.upper() == "WAF":
                status = "WAF"
            self.q.put(("row", {
                "engine": "Sherlock", "username": self.username, "site": result.site_name,
                "url": result.site_url_user, "status": status,
                "time": getattr(result, "query_time", None), "context": getattr(result, "context", None),
                "http_status": None, "text": "",
            }))
        except Exception as e:
            self.q.put(("log", "Sherlock notify error: %r" % e))

    def finish(self, message=None):
        pass

    def countdown(self, *a, **k):
        pass


class _MaigretNotify:
    """Duck-typed notifier for maigret(); it calls update(result, is_similar)."""

    def __init__(self, q, username, runner):
        self.q, self.username, self.runner = q, username, runner
        self.result = None

    def start(self, *a, **k):
        pass

    def update(self, result, is_similar=False, *a, **k):
        if self.runner.stop_flag.is_set():
            return
        try:
            raw = getattr(result.status, "name", None) or getattr(result.status, "value", None) or str(result.status)
            status = str(raw).strip().title()
            self.q.put(("row", {
                "engine": "Maigret", "username": self.username, "site": result.site_name,
                "url": result.site_url_user, "status": status, "similar": bool(is_similar),
                "time": getattr(result, "query_time", None), "context": getattr(result, "context", None),
                "http_status": None, "text": "", "ids": dict(getattr(result, "ids_data", None) or {}),
                "tags": list(getattr(result, "tags", None) or []),
            }))
        except Exception as e:
            self.q.put(("log", "Maigret notify error: %r" % e))

    def finish(self, *a, **k):
        pass

    def warning(self, *a, **k):
        pass

    def info(self, *a, **k):
        pass

    def success(self, *a, **k):
        pass


class Runner(threading.Thread):
    """Search each username with every enabled engine; engines run concurrently."""

    def __init__(self, usernames, sherlock_sites, q, timeout=20, proxy=None,
                 use_sherlock=True, use_maigret=True, maigret_top=None):
        super().__init__(daemon=True)
        self.usernames = usernames
        self.sherlock_sites = sherlock_sites
        self.q = q
        self.timeout = timeout
        self.proxy = proxy or None
        self.use_sherlock = use_sherlock
        self.use_maigret = use_maigret and MAIGRET_OK
        self.maigret_top = maigret_top
        self.stop_flag = threading.Event()
        self._loop = None            # Maigret's event loop, so stop() can halt it
        self._executor = None        # built-in checker's pool, so stop() can drop queued work

    def stop(self):
        """Stop as soon as possible: abort Sherlock at its next callback, halt Maigret's
        event loop, and cancel any queued built-in checks.  In-flight HTTP requests
        end when they time out."""
        self.stop_flag.set()
        loop = self._loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(_cancel_all, loop)
            except Exception:
                pass
        ex = self._executor
        if ex is not None:
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    def run(self):
        try:
            for u in self.usernames:
                if self.stop_flag.is_set():
                    break
                m_sites = {}
                if self.use_maigret:
                    try:
                        m_sites = maigret_sites(self.maigret_top)
                    except Exception as e:
                        self.q.put(("log", "Maigret database failed to load: %r" % e))
                        self.use_maigret = False
                total = (len(self.sherlock_sites) if self.use_sherlock else 0) + len(m_sites)
                self.q.put(("start", u, total))
                threads = []
                if self.use_sherlock:
                    if SHERLOCK_FUNC is not None:
                        threads.append(threading.Thread(target=self._run_sherlock, args=(u,), daemon=True))
                    else:
                        threads.append(threading.Thread(target=self._run_own, args=(u,), daemon=True))
                if self.use_maigret and m_sites:
                    threads.append(threading.Thread(target=self._run_maigret, args=(u, m_sites), daemon=True))
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                self.q.put(("done_user", u))
        except Exception as e:
            self.q.put(("log", "Engine error: %r" % e))
        finally:
            self.q.put(("finished", self.stop_flag.is_set()))

    # -- Sherlock ------------------------------------------------------------
    def _run_sherlock(self, username):
        try:
            notify = _SherlockNotify(self.q, username, self)
            try:
                params = inspect.signature(SHERLOCK_FUNC).parameters
            except Exception:
                params = {}
            kwargs = {}
            if "timeout" in params:
                kwargs["timeout"] = self.timeout
            if self.proxy and "proxy" in params:
                kwargs["proxy"] = self.proxy
            for k, v in (("tor", False), ("unique_tor", False), ("dump_response", False)):
                if k in params:
                    kwargs[k] = v
            try:
                results = SHERLOCK_FUNC(username, self.sherlock_sites, notify, **kwargs)
            except RunStopped:
                return
            if self.stop_flag.is_set():
                return
            enrich = {}
            for site, r in (results or {}).items():
                if not isinstance(r, dict):
                    continue
                hs = r.get("http_status")
                try:
                    hs = int(hs) if hs not in ("", None) else None
                except Exception:
                    hs = None
                enrich[site] = {"http_status": hs, "text": (r.get("response_text") or "")[:200000],
                                "url": r.get("url_user")}
            self.q.put(("enrich", "Sherlock", username, enrich))
        except Exception as e:
            self.q.put(("log", "Sherlock engine error: %r" % e))
        finally:
            self.q.put(("engine_done", "Sherlock", username))

    # -- built-in fallback ---------------------------------------------------
    def _run_own(self, username):
        try:
            ex = ThreadPoolExecutor(max_workers=20)
            self._executor = ex
            try:
                futs = {ex.submit(own_check, n, i, username, self.timeout, self.proxy): n
                        for n, i in self.sherlock_sites.items()}
                for f in as_completed(futs):
                    if self.stop_flag.is_set():
                        break
                    try:
                        r = f.result()
                    except Exception as e:
                        r = {"site": futs[f], "username": username, "status": "Unknown",
                             "http_status": None, "url": None, "time": None, "context": repr(e), "text": ""}
                    r["engine"] = "Built-in"
                    self.q.put(("row", r))
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
                self._executor = None
        finally:
            self.q.put(("engine_done", "Built-in", username))

    # -- Maigret -------------------------------------------------------------
    def _run_maigret(self, username, m_sites):
        try:
            from maigret.maigret import maigret as maigret_fn
            logger = logging.getLogger("maigret")
            logger.setLevel(logging.ERROR)
            notify = _MaigretNotify(self.q, username, self)
            try:
                params = inspect.signature(maigret_fn).parameters
            except Exception:
                params = {}
            kwargs = {}
            opts = {
                "query_notify": notify, "timeout": max(3, min(self.timeout, 30)), "id_type": "username",
                "is_parsing_enabled": True, "no_progressbar": True, "proxy": self.proxy,
                "max_connections": 50, "retries": 0, "debug": False, "forced": False,
                "check_domains": False, "cookies": None, "logger": logger,
            }
            for k, v in opts.items():
                if k in params:
                    kwargs[k] = v
            if "logger" not in params:
                kwargs.pop("logger", None)
            loop = asyncio.new_event_loop()
            self._loop = loop
            try:
                asyncio.set_event_loop(loop)
                if "logger" in params:
                    coro = maigret_fn(username, m_sites, **kwargs)
                else:
                    coro = maigret_fn(username, m_sites, logger, **kwargs)
                try:
                    results = loop.run_until_complete(coro)
                except (asyncio.CancelledError, RuntimeError):
                    if not self.stop_flag.is_set():
                        raise
                    results = {}
            finally:
                self._loop = None
                _close_loop(loop)
            if self.stop_flag.is_set():
                return
            enrich = {}
            for site, r in (results or {}).items():
                if not isinstance(r, dict):
                    continue
                st = r.get("status")
                raw = getattr(st, "status", st)
                raw = getattr(raw, "name", None) or getattr(raw, "value", None) or str(raw)
                status = str(raw).strip().title()
                hs = r.get("http_status")
                try:
                    hs = int(hs) if hs not in ("", None) else None
                except Exception:
                    hs = None
                ids = {}
                for key in ("ids_data",):
                    v = r.get(key) or getattr(st, key, None)
                    if isinstance(v, dict):
                        ids.update(v)
                enrich[site] = {
                    "http_status": hs, "text": (r.get("response_text") or r.get("html") or "")[:200000],
                    "url": r.get("url_user"), "status": status, "similar": bool(r.get("is_similar")),
                    "ids": ids, "tags": list(getattr(r.get("site"), "tags", None) or []),
                    "url_main": r.get("url_main") or getattr(r.get("site"), "url_main", None),
                }
            self.q.put(("enrich", "Maigret", username, enrich))
        except Exception as e:
            self.q.put(("log", "Maigret engine error: %r" % e))
        finally:
            self.q.put(("engine_done", "Maigret", username))


class Verifier(threading.Thread):
    def __init__(self, rows, site_data, q, timeout=20, proxy=None):
        super().__init__(daemon=True)
        self.rows, self.site_data, self.q = rows, site_data, q
        self.timeout, self.proxy = timeout, proxy
        self.stop_flag = threading.Event()
        self._executor = None

    def stop(self):
        self.stop_flag.set()
        ex = self._executor
        if ex is not None:
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    def run(self):
        try:
            ex = ThreadPoolExecutor(max_workers=10)
            self._executor = ex
            try:
                futs = {}
                for row in self.rows:
                    info = self.site_data.get(row["site"]) or {}
                    futs[ex.submit(verify_row, row, info, self.timeout, self.proxy)] = row
                for f in as_completed(futs):
                    if self.stop_flag.is_set():
                        break
                    row = futs[f]
                    try:
                        label, res = f.result()
                    except Exception as e:
                        label, res = "Unclear", {"context": repr(e)}
                    self.q.put(("verified", row["key"], label, res))
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
                self._executor = None
        finally:
            self.q.put(("verify_done", self.stop_flag.is_set()))


def _cancel_all(loop):
    """Run inside the loop: cancel every task, then stop the loop."""
    try:
        for t in asyncio.all_tasks(loop):
            t.cancel()
    except Exception:
        pass
    loop.stop()


def _close_loop(loop):
    """Close an event loop that may have been stopped mid-run without leaking tasks."""
    try:
        pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        for t in pending:
            t.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
    except Exception:
        pass
    try:
        loop.run_until_complete(loop.shutdown_asyncgens())
    except Exception:
        pass
    try:
        loop.close()
    except Exception:
        pass


class AvatarFetcher(threading.Thread):
    """Find + download the profile image for each row (rows must have page text);
    posts ("avatar", key, result) per row and ("avatars_done", stopped) at the end."""

    def __init__(self, rows, q, timeout=15, proxy=None):
        super().__init__(daemon=True)
        self.rows, self.q, self.timeout, self.proxy = rows, q, timeout, proxy
        self.stop_flag = threading.Event()
        self._executor = None

    def stop(self):
        self.stop_flag.set()
        ex = self._executor
        if ex is not None:
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    @staticmethod
    def fetch_for_row(row, timeout=15, proxy=None):
        import images
        cands = images.find_avatar_candidates(row.get("text") or "", row.get("url"), row.get("username"))
        if not cands:
            return {"url": None, "error": "no image found in page"}
        last = None
        for u in cands[:3]:
            try:
                data, ct = images.fetch(u, timeout=timeout, proxy=proxy, referer=row.get("url"))
                return {"url": u, "data": data, "ct": ct, "hash": images.dhash(data),
                        "info": images.describe(data, ct), "candidates": cands}
            except Exception as e:
                last = "%s: %s" % (u, e)
        return {"url": cands[0], "error": last or "download failed", "candidates": cands}

    def run(self):
        try:
            ex = ThreadPoolExecutor(max_workers=8)
            self._executor = ex
            try:
                futs = {ex.submit(self.fetch_for_row, r, self.timeout, self.proxy): r for r in self.rows}
                for f in as_completed(futs):
                    if self.stop_flag.is_set():
                        break
                    row = futs[f]
                    try:
                        res = f.result()
                    except Exception as e:
                        res = {"url": None, "error": repr(e)}
                    self.q.put(("avatar", row["key"], res))
            finally:
                ex.shutdown(wait=False, cancel_futures=True)
                self._executor = None
        finally:
            self.q.put(("avatars_done", self.stop_flag.is_set()))


# ----------------------------------------------------------------------------
# Page preview extraction
# ----------------------------------------------------------------------------


def _unescape(s):
    import html
    return html.unescape(re.sub(r"\s+", " ", s or "")).strip()


def page_preview(text, username=None, max_snippets=3):
    """Pull title / description / headline / username snippets out of HTML."""
    out = {}
    if not text:
        return out
    t = _title_of(text)
    if t:
        out["title"] = _unescape(t)
    for pat, key in (
        (r'<meta[^>]+(?:name|property)=["\'](?:og:|twitter:)?description["\'][^>]*content=["\']([^"\']*)', "description"),
        (r'<meta[^>]+content=["\']([^"\']*)["\'][^>]*(?:name|property)=["\'](?:og:|twitter:)?description["\']', "description"),
        (r'<meta[^>]+property=["\']og:title["\'][^>]*content=["\']([^"\']*)', "og_title"),
        (r'<meta[^>]+property=["\']og:image["\'][^>]*content=["\']([^"\']*)', "image"),
        (r'<link[^>]+rel=["\']canonical["\'][^>]*href=["\']([^"\']*)', "canonical"),
    ):
        if key in out:
            continue
        m = re.search(pat, text, re.I)
        if m and m.group(1).strip():
            out[key] = _unescape(m.group(1))
    m = re.search(r"<h1[^>]*>(.*?)</h1>", text, re.I | re.S)
    if m:
        h = _unescape(re.sub(r"<[^>]+>", " ", m.group(1)))
        if h:
            out["h1"] = h[:200]
    if username:
        body = re.sub(r"<script.*?</script>|<style.*?</style>", " ", text, flags=re.I | re.S)
        body = re.sub(r"<[^>]+>", " ", body)
        body = _unescape(body)
        snippets = []
        for m in re.finditer(re.escape(username), body, re.I):
            s = body[max(0, m.start() - 70): m.end() + 70].strip()
            if s and all(s not in x for x in snippets):
                snippets.append("..." + s + "...")
            if len(snippets) >= max_snippets:
                break
        if snippets:
            out["snippets"] = snippets
    return out
