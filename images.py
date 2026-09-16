"""Profile images: find the avatar on a profile page, fetch it, hash it, and build
reverse-image-search links.

No API keys.  The reverse search itself happens in the browser: every engine below
accepts an image URL in its query string.  Perceptual hashing (dHash) needs Pillow;
without it the app still shows PNG/GIF avatars through Tk and still opens the
search engines, it just cannot say "same avatar as ..." across sites.
"""
import io
import re
import urllib.parse

try:
    from PIL import Image
    PIL_OK = True
except Exception:
    Image = None
    PIL_OK = False

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
MAX_BYTES = 6 * 1024 * 1024
THUMB = 96
# dHash distance at or below which two images count as "the same picture"
# (0 = identical; re-encoded / resized copies usually land within 6).
MATCH_THRESHOLD = 8

# Reverse image search engines that accept an image URL directly.
ENGINES = [
    ("Google Lens", "https://lens.google.com/uploadbyurl?url={u}"),
    ("Bing Visual Search", "https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{u}"),
    ("Yandex Images", "https://yandex.com/images/search?rpt=imageview&url={u}"),
    ("TinEye", "https://tineye.com/search?url={u}"),
]
# Upload pages for a local file (the engines will not take a file from a URL bar).
UPLOAD_PAGES = [
    ("Google Lens", "https://lens.google.com/"),
    ("Bing Visual Search", "https://www.bing.com/visualsearch"),
    ("Yandex Images", "https://yandex.com/images/"),
    ("TinEye", "https://tineye.com/"),
]

# Site logos, sprites and tracking pixels that og:image / <img> scraping tends to return.
_JUNK = ("logo", "sprite", "pixel", "spacer", "blank", "placeholder", "default_avatar", "default-avatar",
         "avatar_default", "anonymous", "favicon", "badge", "icon-", "/icons/", "emoji", "loading", "1x1")
_AVATAR_HINTS = ("avatar", "profile", "user-image", "userimage", "user_image", "profile-pic", "profilepic",
                 "photo", "portrait", "headshot", "pfp")


def search_urls(image_url):
    """[(engine, url)] for an image reachable by URL."""
    q = urllib.parse.quote(image_url, safe="")
    return [(n, t.format(u=q)) for n, t in ENGINES]


def _clean(u):
    return (u or "").strip().replace("&amp;", "&")


def _junk(u):
    low = u.lower()
    return any(j in low for j in _JUNK) or low.endswith(".svg") or low.startswith("data:")


def find_avatar_candidates(html, page_url=None, username=None):
    """Ordered list of likely avatar URLs found in a profile page (best first)."""
    if not html:
        return []
    found = []

    def add(u, score):
        u = _clean(u)
        if not u or _junk(u):
            return
        if page_url:
            u = urllib.parse.urljoin(page_url, u)
        if not u.lower().startswith(("http://", "https://")):
            return
        if username and username.lower() in u.lower():
            score += 3
        found.append((score, u))

    for pat, sc in (
        (r'<meta[^>]+property=["\']og:image(?::secure_url)?["\'][^>]*content=["\']([^"\']+)', 10),
        (r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*property=["\']og:image(?::secure_url)?["\']', 10),
        (r'<meta[^>]+name=["\']twitter:image(?::src)?["\'][^>]*content=["\']([^"\']+)', 9),
        (r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']twitter:image(?::src)?["\']', 9),
        (r'<link[^>]+rel=["\']image_src["\'][^>]*href=["\']([^"\']+)', 8),
        (r'"(?:avatar_url|avatarUrl|profile_image_url_https|profile_image_url|profileImageUrl|avatar|image_url)"\s*:\s*"([^"]+)"', 7),
    ):
        for m in re.finditer(pat, html, re.I):
            add(m.group(1).replace("\\/", "/"), sc)
    # <img ...> whose class / id / alt / src mentions an avatar
    for m in re.finditer(r"<img\b[^>]*>", html, re.I):
        tag = m.group(0)
        low = tag.lower()
        if not any(h in low for h in _AVATAR_HINTS):
            continue
        src = re.search(r'(?:data-src|data-lazy-src|src)=["\']([^"\']+)', tag, re.I)
        if src:
            add(src.group(1), 6 if "avatar" in low or "profile" in low else 4)
    # de-duplicate keeping best score, sort best first
    best = {}
    for sc, u in found:
        if u not in best or sc > best[u]:
            best[u] = sc
    return [u for u, _ in sorted(best.items(), key=lambda kv: -kv[1])]


def fetch(url, timeout=15, proxy=None, referer=None):
    """Download an image.  Returns (bytes, content_type) or raises."""
    import requests
    headers = {"User-Agent": UA, "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"}
    if referer:
        headers["Referer"] = referer
    proxies = {"http": proxy, "https": proxy} if proxy else None
    r = requests.get(url, headers=headers, timeout=timeout, proxies=proxies, stream=True, allow_redirects=True)
    r.raise_for_status()
    ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    buf = io.BytesIO()
    for chunk in r.iter_content(65536):
        buf.write(chunk)
        if buf.tell() > MAX_BYTES:
            raise ValueError("image larger than %d MB" % (MAX_BYTES // (1024 * 1024)))
    data = buf.getvalue()
    if not data:
        raise ValueError("empty response")
    if ct and not ct.startswith("image/") and not _looks_like_image(data):
        raise ValueError("not an image (%s)" % ct)
    return data, ct


def _looks_like_image(data):
    return data[:8].startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"BM", b"II*\x00", b"MM\x00*")) \
        or data[4:12] in (b"ftypavif", b"ftypheic")


def dhash(data, size=8):
    """64-bit difference hash as a hex string, or None without Pillow / on failure."""
    if not PIL_OK:
        return None
    try:
        im = Image.open(io.BytesIO(data))
        im = im.convert("L").resize((size + 1, size), Image.Resampling.LANCZOS)
        px = list(im.getdata())
        bits = 0
        for row in range(size):
            for col in range(size):
                left = px[row * (size + 1) + col]
                right = px[row * (size + 1) + col + 1]
                bits = (bits << 1) | (1 if left > right else 0)
        return "%016x" % bits
    except Exception:
        return None


def distance(h1, h2):
    """Hamming distance between two dhash hex strings (64 = completely different)."""
    if not h1 or not h2:
        return 64
    return bin(int(h1, 16) ^ int(h2, 16)).count("1")


def same_picture(h1, h2, threshold=MATCH_THRESHOLD):
    return distance(h1, h2) <= threshold


def describe(data, ct=""):
    """'PNG 400x400' style label for the preview pane."""
    if PIL_OK:
        try:
            im = Image.open(io.BytesIO(data))
            return "%s %dx%d, %d KB" % (im.format or ct or "image", im.width, im.height, max(1, len(data) // 1024))
        except Exception:
            pass
    return "%s, %d KB" % (ct or "image", max(1, len(data) // 1024))


def thumbnail_photo(data, tk_module, size=THUMB):
    """A Tk PhotoImage for the preview pane (Pillow for JPEG/WebP; Tk alone handles PNG/GIF)."""
    if PIL_OK:
        try:
            from PIL import ImageTk
            im = Image.open(io.BytesIO(data))
            im = im.convert("RGBA")
            im.thumbnail((size, size), Image.Resampling.LANCZOS)
            return ImageTk.PhotoImage(im)
        except Exception:
            pass
    try:
        import base64
        photo = tk_module.PhotoImage(data=base64.b64encode(data))
        f = max(1, max(photo.width(), photo.height()) // size)
        return photo.subsample(f, f) if f > 1 else photo
    except Exception:
        return None
