"""Back-ends for the Email, Phone and Domain tabs.

All functions are GUI-free.  Optional libraries (holehe, httpx, phonenumbers,
dnspython, python-whois) are imported lazily with plain fallbacks so the app
still opens - and says what is missing - when one of them is absent.
"""

import asyncio
import hashlib
import inspect
import json
import re
import socket
import threading
import time
from datetime import datetime

import requests

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# ----------------------------------------------------------------------------
# Email (holehe)
# ----------------------------------------------------------------------------

EMAIL_RX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def holehe_status():
    """(available, version_or_error)"""
    try:
        import holehe  # noqa
        import httpx  # noqa
        try:
            from importlib.metadata import version
            return True, version("holehe")
        except Exception:
            return True, "unknown"
    except Exception as e:
        return False, repr(e)


def _holehe_modules():
    """Return the list of holehe site-check coroutine functions."""
    from holehe import core
    modules = core.import_submodules("holehe.modules")
    try:
        params = inspect.signature(core.get_functions).parameters
        if len(params) >= 2:
            return core.get_functions(modules, None)
        return core.get_functions(modules)
    except Exception:
        funcs = []
        for mod in modules.values():
            for name, fn in inspect.getmembers(mod, inspect.iscoroutinefunction):
                if mod.__name__.endswith("." + name):
                    funcs.append(fn)
        return funcs


async def _holehe_run(email, timeout, on_result, stop_flag):
    import httpx
    from holehe import core
    funcs = _holehe_modules()
    out = []
    seen = 0
    async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": UA}) as client:
        async def one(fn):
            nonlocal seen
            if stop_flag.is_set():
                return
            before = len(out)
            try:
                if hasattr(core, "launch_module"):
                    await core.launch_module(fn, email, client, out)
                else:
                    await fn(email, client, out)
            except Exception as e:
                out.append({"name": fn.__name__, "domain": "", "rateLimit": False, "exists": False,
                            "error": repr(e)})
            for r in out[before:]:
                on_result(r)
        await asyncio.gather(*[one(f) for f in funcs])
    return out


class EmailChecker(threading.Thread):
    """Runs holehe plus a couple of cheap extra checks; results -> q."""

    def __init__(self, email, q, timeout=10):
        super().__init__(daemon=True)
        self.email, self.q, self.timeout = email.strip(), q, timeout
        self.stop_flag = threading.Event()
        self._loop = None

    def stop(self):
        self.stop_flag.set()
        loop = self._loop
        if loop is not None:
            try:
                loop.call_soon_threadsafe(_cancel_all, loop)
            except Exception:
                pass

    def run(self):
        try:
            self.q.put(("email_start", self.email))
            # cheap extras first
            self.q.put(("email_row", gravatar_check(self.email)))
            self.q.put(("email_row", mx_check(self.email)))
            ok, ver = holehe_status()
            if not ok:
                self.q.put(("log", "holehe not available (%s) - only the built-in checks ran." % ver))
                return
            loop = asyncio.new_event_loop()
            self._loop = loop
            try:
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(_holehe_run(
                        self.email, self.timeout, lambda r: self.q.put(("email_row", normalise_holehe(r))),
                        self.stop_flag))
                except (asyncio.CancelledError, RuntimeError):
                    if not self.stop_flag.is_set():
                        raise
            finally:
                self._loop = None
                _close_loop(loop)
        except Exception as e:
            self.q.put(("log", "Email check error: %r" % e))
        finally:
            self.q.put(("email_done", self.stop_flag.is_set()))


def normalise_holehe(r):
    exists = r.get("exists")
    rl = r.get("rateLimit")
    if r.get("error"):
        state = "Error"
    elif rl:
        state = "Rate limited"
    elif exists is True:
        state = "Registered"
    elif exists is False:
        state = "Not registered"
    else:
        state = "Unknown"
    others = r.get("others")
    if isinstance(others, dict):
        others = "; ".join("%s: %s" % kv for kv in others.items())
    return {
        "site": r.get("name") or "?", "domain": r.get("domain") or "", "state": state,
        "recovery": r.get("emailrecovery") or "", "phone": r.get("phoneNumber") or "",
        "other": others or r.get("error") or "", "method": r.get("method") or "",
        "flaky": bool(r.get("frequent_rate_limit")),
    }


def gravatar_check(email):
    h = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = "https://www.gravatar.com/avatar/%s?d=404" % h
    row = {"site": "Gravatar", "domain": "gravatar.com", "state": "Unknown", "recovery": "",
           "phone": "", "other": "", "method": "avatar hash", "flaky": False}
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": UA})
        if r.status_code == 200:
            row["state"] = "Registered"
            row["other"] = "avatar: " + url
            try:
                p = requests.get("https://www.gravatar.com/%s.json" % h, timeout=10, headers={"User-Agent": UA})
                if p.status_code == 200:
                    e = (p.json().get("entry") or [{}])[0]
                    bits = [e.get("displayName"), e.get("preferredUsername"), e.get("aboutMe"),
                            e.get("currentLocation")]
                    prof = " | ".join(str(b) for b in bits if b)
                    if prof:
                        row["other"] = prof[:300] + "  " + "https://gravatar.com/" + h
            except Exception:
                pass
        elif r.status_code == 404:
            row["state"] = "Not registered"
        else:
            row["state"] = "HTTP %d" % r.status_code
    except Exception as e:
        row["state"] = "Error"
        row["other"] = type(e).__name__
    return row


def mx_check(email):
    dom = email.rsplit("@", 1)[-1].lower()
    row = {"site": "Mail domain", "domain": dom, "state": "Unknown", "recovery": "", "phone": "",
           "other": "", "method": "MX lookup", "flaky": False}
    recs = dns_lookup(dom, ["MX"]).get("MX") or []
    if recs and not str(recs[0]).startswith("error"):
        row["state"] = "Accepts mail"
        row["other"] = ", ".join(recs[:4])
        low = " ".join(recs).lower()
        for k, v in (("google", "Google Workspace / Gmail"), ("outlook", "Microsoft 365 / Outlook"),
                     ("protection.outlook", "Microsoft 365"), ("icloud", "Apple iCloud Mail"),
                     ("protonmail", "Proton Mail"), ("yahoodns", "Yahoo"), ("zoho", "Zoho"),
                     ("fastmail", "Fastmail"), ("mimecast", "Mimecast (corporate)"),
                     ("pphosted", "Proofpoint (corporate)")):
            if k in low:
                row["other"] = v + " - " + row["other"]
                break
    else:
        row["state"] = "No MX record"
        row["other"] = recs[0] if recs else "domain has no mail servers"
    return row


# ----------------------------------------------------------------------------
# Phone (phonenumbers)
# ----------------------------------------------------------------------------


def phone_lookup(raw, default_region="GB"):
    """Return a list of (label, value) lines describing a phone number."""
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone, PhoneNumberFormat, PhoneNumberType
    except Exception as e:
        return [("Error", "phonenumbers library not available: %r" % e)]
    raw = raw.strip()
    if not raw:
        return [("Error", "Type a number first.")]
    try:
        n = phonenumbers.parse(raw, default_region or None)
    except Exception as e:
        return [("Error", "Could not parse: %s" % e)]
    types = {
        PhoneNumberType.FIXED_LINE: "Fixed line", PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile", PhoneNumberType.TOLL_FREE: "Toll-free",
        PhoneNumberType.PREMIUM_RATE: "Premium rate", PhoneNumberType.SHARED_COST: "Shared cost",
        PhoneNumberType.VOIP: "VoIP", PhoneNumberType.PERSONAL_NUMBER: "Personal number",
        PhoneNumberType.PAGER: "Pager", PhoneNumberType.UAN: "UAN", PhoneNumberType.VOICEMAIL: "Voicemail",
        PhoneNumberType.UNKNOWN: "Unknown",
    }
    valid = phonenumbers.is_valid_number(n)
    possible = phonenumbers.is_possible_number(n)
    out = [
        ("Input", raw),
        ("Valid", "yes" if valid else ("possible but not valid" if possible else "no")),
        ("E.164", phonenumbers.format_number(n, PhoneNumberFormat.E164)),
        ("International", phonenumbers.format_number(n, PhoneNumberFormat.INTERNATIONAL)),
        ("National", phonenumbers.format_number(n, PhoneNumberFormat.NATIONAL)),
        ("Country code", "+%s" % n.country_code),
        ("Region", "%s %s" % (phonenumbers.region_code_for_number(n) or "?",
                              geocoder.description_for_number(n, "en") or "")),
        ("Type", types.get(phonenumbers.number_type(n), "Unknown")),
        ("Carrier (original)", carrier.name_for_number(n, "en") or "unknown / ported / not in database"),
        ("Time zones", ", ".join(timezone.time_zones_for_number(n)) or "unknown"),
    ]
    try:
        out.append(("Dialling from GB", phonenumbers.format_out_of_country_calling_number(n, "GB")))
    except Exception:
        pass
    e164 = phonenumbers.format_number(n, PhoneNumberFormat.E164)
    out.append(("Search links", "https://www.google.com/search?q=%%22%s%%22   |   https://www.google.com/search?q=%%22%s%%22"
                % (e164, phonenumbers.format_number(n, PhoneNumberFormat.NATIONAL).replace(" ", "+"))))
    out.append(("WhatsApp", "https://wa.me/%s" % e164.lstrip("+")))
    out.append(("Telegram", "https://t.me/%s" % e164))
    return out


# ----------------------------------------------------------------------------
# Domain (RDAP / WHOIS / DNS / crt.sh)
# ----------------------------------------------------------------------------

DOMAIN_RX = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$", re.I)


def clean_domain(s):
    s = (s or "").strip().lower()
    s = re.sub(r"^[a-z]+://", "", s)
    s = s.split("/")[0].split("?")[0].split("@")[-1]
    if s.startswith("www."):
        s = s[4:]
    return s


def dns_lookup(domain, types=("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")):
    out = {}
    try:
        import dns.resolver
        res = dns.resolver.Resolver()
        res.lifetime = 6
        for t in types:
            try:
                ans = res.resolve(domain, t)
                vals = []
                for r in ans:
                    if t == "MX":
                        vals.append("%s (pri %s)" % (str(r.exchange).rstrip("."), r.preference))
                    elif t == "TXT":
                        vals.append("".join(s.decode("utf-8", "replace") if isinstance(s, bytes) else str(s)
                                            for s in r.strings))
                    else:
                        vals.append(str(r).rstrip("."))
                out[t] = vals
            except dns.resolver.NoAnswer:
                out[t] = []
            except dns.resolver.NXDOMAIN:
                out[t] = ["error: domain does not exist (NXDOMAIN)"]
                break
            except Exception as e:
                out[t] = ["error: %s" % type(e).__name__]
        return out
    except ImportError:
        pass
    # stdlib fallback: A/AAAA only
    try:
        infos = socket.getaddrinfo(domain, None)
        out["A"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
        out["AAAA"] = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET6})
    except Exception as e:
        out["A"] = ["error: %s" % type(e).__name__]
    out["note"] = ["dnspython not installed - only A/AAAA looked up"]
    return out


def _fmt_date(v):
    if isinstance(v, list):
        v = v[0] if v else None
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d")
    return str(v)[:10] if v else ""


def rdap_lookup(domain):
    """Registration data via RDAP (no library needed). Returns dict or None."""
    try:
        r = requests.get("https://rdap.org/domain/%s" % domain, timeout=12,
                         headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"},
                         allow_redirects=True)
        if r.status_code != 200:
            return {"error": "RDAP HTTP %d" % r.status_code}
        d = r.json()
    except Exception as e:
        return {"error": "RDAP failed: %s" % type(e).__name__}
    out = {"source": "RDAP"}
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", []) if isinstance(e, dict)}
    out["created"] = _fmt_date(events.get("registration"))
    out["updated"] = _fmt_date(events.get("last changed") or events.get("last update of RDAP database"))
    out["expires"] = _fmt_date(events.get("expiration"))
    out["status"] = ", ".join(d.get("status") or [])
    out["nameservers"] = [ns.get("ldhName", "").lower().rstrip(".") for ns in d.get("nameservers", []) if isinstance(ns, dict)]
    out["dnssec"] = "signed" if (d.get("secureDNS") or {}).get("delegationSigned") else "unsigned"
    for ent in d.get("entities", []) or []:
        roles = ent.get("roles") or []
        name = ""
        for item in (ent.get("vcardArray") or [None, []])[1] or []:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                name = item[3]
        if "registrar" in roles:
            out["registrar"] = name or ent.get("handle", "")
            for pe in ent.get("publicIds") or []:
                if pe.get("type", "").lower().startswith("iana"):
                    out["registrar_iana"] = pe.get("identifier")
        if "registrant" in roles and name:
            out["registrant"] = name
    return out


def whois_lookup(domain):
    """Fallback: python-whois if present, else a raw port-43 query."""
    try:
        import whois
        w = whois.whois(domain)
        return {
            "source": "WHOIS (python-whois)",
            "registrar": str(w.get("registrar") or ""),
            "created": _fmt_date(w.get("creation_date")),
            "expires": _fmt_date(w.get("expiration_date")),
            "updated": _fmt_date(w.get("updated_date")),
            "nameservers": sorted({str(n).lower().rstrip(".") for n in (w.get("name_servers") or [])}),
            "status": ", ".join(w.get("status") or []) if isinstance(w.get("status"), list) else str(w.get("status") or ""),
            "registrant": str(w.get("org") or w.get("name") or ""),
            "emails": ", ".join(w.get("emails") or []) if isinstance(w.get("emails"), list) else str(w.get("emails") or ""),
            "country": str(w.get("country") or ""),
        }
    except Exception:
        pass
    try:
        raw = _whois_raw("whois.iana.org", domain)
        m = re.search(r"^whois:\s*(\S+)", raw, re.M | re.I)
        if m:
            raw = _whois_raw(m.group(1), domain)
        return {"source": "WHOIS (raw)", "raw": raw[:6000]}
    except Exception as e:
        return {"error": "WHOIS failed: %s" % type(e).__name__}


def _whois_raw(server, query):
    with socket.create_connection((server, 43), timeout=10) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            c = s.recv(4096)
            if not c:
                break
            chunks.append(c)
    return b"".join(chunks).decode("utf-8", "replace")


def crtsh_subdomains(domain, limit=300):
    try:
        r = requests.get("https://crt.sh/", params={"q": "%." + domain, "output": "json"}, timeout=25,
                         headers={"User-Agent": UA})
        if r.status_code != 200:
            return ["error: crt.sh HTTP %d" % r.status_code]
        data = r.json()
    except Exception as e:
        return ["error: crt.sh %s" % type(e).__name__]
    names = set()
    for row in data:
        for n in str(row.get("name_value", "")).split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain):
                names.add(n)
    return sorted(names)[:limit]


def http_probe(domain):
    out = []
    for scheme in ("https", "http"):
        try:
            r = requests.get("%s://%s/" % (scheme, domain), timeout=10, headers={"User-Agent": UA},
                             allow_redirects=True)
            title = re.search(r"<title[^>]*>(.*?)</title>", r.text or "", re.I | re.S)
            out.append("%s://%s -> %d %s%s" % (
                scheme, domain, r.status_code,
                ("(" + r.url + ") ") if r.url.rstrip("/") != "%s://%s" % (scheme, domain) else "",
                ("title: " + re.sub(r"\s+", " ", title.group(1)).strip()[:120]) if title else ""))
            srv = r.headers.get("Server")
            if srv:
                out.append("   server: %s" % srv)
            break
        except Exception as e:
            out.append("%s://%s -> %s" % (scheme, domain, type(e).__name__))
    return out


def _cancel_all(loop):
    try:
        for t in asyncio.all_tasks(loop):
            t.cancel()
    except Exception:
        pass
    loop.stop()


def _close_loop(loop):
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


class DomainLookup(threading.Thread):
    def __init__(self, domain, q, want_subdomains=True):
        super().__init__(daemon=True)
        self.domain, self.q, self.want_subdomains = clean_domain(domain), q, want_subdomains
        self.stop_flag = threading.Event()

    def stop(self):
        self.stop_flag.set()

    def run(self):
        d = self.domain
        try:
            if not DOMAIN_RX.match(d):
                self.q.put(("domain_section", "Error", ["'%s' does not look like a domain name." % d]))
                return
            self.q.put(("domain_start", d))
            reg = rdap_lookup(d)
            if not reg or reg.get("error") or not any(reg.get(k) for k in ("registrar", "created", "nameservers")):
                w = whois_lookup(d)
                if reg and reg.get("error"):
                    w.setdefault("note", reg["error"])
                reg = w
            lines = []
            if reg.get("raw"):
                lines = ["(no RDAP data - raw WHOIS below)", ""] + reg["raw"].splitlines()
            else:
                for k, lbl in (("registrar", "Registrar"), ("registrar_iana", "Registrar IANA ID"),
                               ("registrant", "Registrant"), ("created", "Created"), ("updated", "Updated"),
                               ("expires", "Expires"), ("status", "Status"), ("dnssec", "DNSSEC"),
                               ("emails", "Emails"), ("country", "Country"), ("note", "Note")):
                    if reg.get(k):
                        lines.append("%-18s %s" % (lbl + ":", reg[k]))
                if reg.get("nameservers"):
                    lines.append("%-18s %s" % ("Name servers:", ", ".join(reg["nameservers"])))
                if reg.get("created"):
                    try:
                        age = (datetime.utcnow() - datetime.strptime(reg["created"], "%Y-%m-%d")).days
                        lines.append("%-18s %d days (%.1f years)" % ("Age:", age, age / 365.25))
                    except Exception:
                        pass
                if reg.get("error"):
                    lines.append(reg["error"])
            self.q.put(("domain_section", "Registration (%s)" % reg.get("source", "?"), lines))
            if self.stop_flag.is_set():
                return

            dns_res = dns_lookup(d)
            lines = []
            for t, vals in dns_res.items():
                if vals:
                    lines.append("%-6s %s" % (t, vals[0]))
                    for v in vals[1:]:
                        lines.append("%-6s %s" % ("", v))
                else:
                    lines.append("%-6s -" % t)
            self.q.put(("domain_section", "DNS", lines))
            if self.stop_flag.is_set():
                return

            self.q.put(("domain_section", "Web", http_probe(d)))
            if self.stop_flag.is_set():
                return

            if self.want_subdomains:
                subs = crtsh_subdomains(d)
                hdr = "Subdomains seen in TLS certificates (crt.sh) - %d" % (
                    0 if (subs and subs[0].startswith("error")) else len(subs))
                self.q.put(("domain_section", hdr, subs or ["none found"]))
        except Exception as e:
            self.q.put(("domain_section", "Error", [repr(e)]))
        finally:
            self.q.put(("domain_done", d))
