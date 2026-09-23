import re
import socket

import httpx


UA = {"User-Agent": "Mozilla/5.0 (SecureVision Recon Scanner)"}

# بصمات الكوكيز -> التقنية
COOKIE_TECH = {
    "phpsessid": ("PHP", "لغة"),
    "laravel_session": ("Laravel (PHP)", "إطار عمل"),
    "ci_session": ("CodeIgniter (PHP)", "إطار عمل"),
    "jsessionid": ("Java / JSP", "لغة"),
    "asp.net_sessionid": ("ASP.NET", "إطار عمل"),
    "connect.sid": ("Node.js / Express", "لغة/إطار"),
    "csrftoken": ("Django (Python)", "إطار عمل"),
    "_rails_session": ("Ruby on Rails", "إطار عمل"),
}

# بصمات محتوى HTML/JS -> التقنية
HTML_TECH = [
    (r"wp-content|wp-includes", "WordPress", "نظام إدارة محتوى"),
    (r"Drupal\.settings|sites/all/", "Drupal", "نظام إدارة محتوى"),
    (r"/media/jui/|Joomla!", "Joomla", "نظام إدارة محتوى"),
    (r"__NEXT_DATA__|/_next/static", "Next.js", "إطار عمل"),
    (r"<app-root|ng-version=|runtime\.[0-9a-f]+\.js|polyfills\.[0-9a-f]+\.js",
     "Angular", "إطار واجهة"),
    (r"data-reactroot|react(\.production|\.development)?\.min\.js|<div id=[\"']root[\"']",
     "React", "إطار واجهة"),
    (r"data-v-[0-9a-f]{6,}|vue(\.min)?\.js|<div id=[\"']app[\"']",
     "Vue.js", "إطار واجهة"),
    (r"jquery(\.min)?\.js", "jQuery", "مكتبة"),
    (r"bootstrap(\.min)?\.(css|js)", "Bootstrap", "مكتبة تصميم"),
    (r"webpackJsonp|/webpack", "Webpack", "أداة بناء"),
]


def _clean_url(target: str) -> str:
    t = (target or "").strip()
    if "://" not in t:
        t = "http://" + t
    return t


def fingerprint(target: str) -> dict:
    """يجمع بصمة كاملة عن الموقع الهدف."""
    url = _clean_url(target)

    result = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "title": "",
        "server": "",
        "powered_by": "",
        "generator": "",
        "ip": "",
        "technologies": [],
        "security_headers": {},
        "cookies": [],
        "error": "",
    }

    # حل عنوان IP
    try:
        host = url.split("://")[1].split("/")[0].split(":")[0]
        result["ip"] = socket.gethostbyname(host)
    except Exception:
        pass

    try:
        resp = httpx.get(
            url, headers=UA, timeout=12, follow_redirects=True, verify=False
        )
    except Exception as e:
        result["error"] = f"تعذّر الوصول للهدف: {e}"
        return result

    result["reachable"] = True
    result["status_code"] = resp.status_code
    headers = {k.lower(): v for k, v in resp.headers.items()}
    html = resp.text or ""

    result["server"] = headers.get("server", "")
    result["powered_by"] = headers.get("x-powered-by", "")

    # العنوان
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        result["title"] = m.group(1).strip()[:200]

    # meta generator
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html, re.I
    )
    if m:
        result["generator"] = m.group(1).strip()

    techs = {}

    def add_tech(name, category):
        if name not in techs:
            techs[name] = category

    # من الترويسات
    server = result["server"].lower()
    if "nginx" in server: add_tech("Nginx", "خادم ويب")
    if "apache" in server: add_tech("Apache", "خادم ويب")
    if "iis" in server or "microsoft-iis" in server: add_tech("Microsoft IIS", "خادم ويب")
    if "uvicorn" in server: add_tech("Uvicorn (Python)", "خادم ويب")
    if "werkzeug" in server: add_tech("Flask (Python)", "إطار عمل")
    if "express" in server: add_tech("Express (Node.js)", "إطار عمل")

    pb = result["powered_by"].lower()
    if "php" in pb: add_tech("PHP", "لغة")
    if "asp.net" in pb: add_tech("ASP.NET", "إطار عمل")
    if "express" in pb: add_tech("Express (Node.js)", "إطار عمل")

    if "x-aspnet-version" in headers: add_tech("ASP.NET", "إطار عمل")
    if "x-drupal-cache" in headers: add_tech("Drupal", "نظام إدارة محتوى")

    # من الكوكيز
    cookie_names = list(resp.cookies.keys())
    result["cookies"] = cookie_names
    cookies_str = (headers.get("set-cookie", "") + " " + " ".join(cookie_names)).lower()
    for key, (name, cat) in COOKIE_TECH.items():
        if key in cookies_str:
            add_tech(name, cat)

    # من المحتوى
    for pattern, name, cat in HTML_TECH:
        if re.search(pattern, html, re.I):
            add_tech(name, cat)

    # generator -> تقنية
    if result["generator"]:
        add_tech(result["generator"], "مولّد")

    result["technologies"] = [{"name": n, "category": c} for n, c in techs.items()]

    # ترويسات الأمان
    sec = [
        "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
        "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
    ]
    for h in sec:
        result["security_headers"][h] = h.lower() in headers

    return result