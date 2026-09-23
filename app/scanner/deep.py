import socket
import ssl
import re
import random
import string
from datetime import datetime
from urllib.parse import (
    urlparse, urljoin, parse_qsl, urlencode, urlunparse
)

import httpx

UA = {"User-Agent": "Mozilla/5.0 (SecureVision Scanner)"}

SQL_ERRORS = [
    "sql syntax", "mysql_fetch", "you have an error in your sql",
    "ora-01756", "ora-00933", "postgresql", "sqlite3::", "sqlite error",
    "unclosed quotation mark", "microsoft odbc", "sqlstate",
    "warning: mysql", "supplied argument is not a valid mysql",
    "syntax error", "mysql_num_rows", "mysql_query",
    "sqlite_error", "sequelizedatabaseerror", "sequelize",
    "unterminated quoted string", "quoted string not properly terminated",
]

SENSITIVE_PATHS = [
    (".env", "critical", "ملف بيئة مكشوف — قد يحتوي مفاتيح وكلمات مرور!"),
    (".git/HEAD", "high", "مستودع Git مكشوف — قد يسرّب الكود المصدري كاملاً."),
    ("wp-config.php", "critical", "ملف إعدادات ووردبريس مكشوف."),
    ("config.php.bak", "high", "نسخة احتياطية من ملف الإعدادات مكشوفة."),
    ("backup.zip", "high", "أرشيف نسخ احتياطي مكشوف."),
    (".htaccess", "medium", "ملف .htaccess مكشوف."),
    ("phpinfo.php", "medium", "صفحة phpinfo تكشف تفاصيل الخادم."),
    ("server-status", "medium", "صفحة server-status مكشوفة."),
    ("admin", "low", "لوحة إدارة مكشوفة — تأكد من حمايتها."),
]


def _host(target: str) -> str:
    t = target.strip()
    if "://" in t:
        return urlparse(t).hostname or ""
    return t.split("/")[0]


    # نقاط إدخال شائعة تُختبر مباشرة (API + بحث)
PROBE_ENDPOINTS = [
    "/rest/products/search?q=test",
    "/search?q=test",
    "/?q=test",
    "/?search=test",
    "/product?id=1",
    "/products?id=1",
    "/api/products?id=1",
    "/?id=1",
]


def _resolve_base(target, log):
    """يحدّد الرابط العامل: يجرّب HTTPS ثم HTTP."""
    t = target.strip()
    if "://" in t:
        return t.rstrip("/")

    for scheme in ("https", "http"):
        url = f"{scheme}://{t}"
        try:
            httpx.get(url, timeout=5, verify=False, follow_redirects=True)
            log(f"[+] الاتصال ناجح عبر {scheme.upper()}", "ok")
            return url.rstrip("/")
        except Exception:
            log(f"[*] {scheme.upper()} غير متاح — تجربة التالي...", "mut")
            continue

    log("[!] تعذّر الاتصال عبر HTTP/HTTPS", "warn")
    return f"http://{t}".rstrip("/")


# ==========================
# فحص SSL / TLS
# ==========================

def check_ssl(host, log, add):
    log(f"[*] فحص شهادة SSL/TLS على {host}...", "acc")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                proto = ss.version()
                cert = ss.getpeercert()
                try:
                    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days = (exp - datetime.utcnow()).days
                    if days < 0:
                        log("[CRIT] شهادة SSL منتهية الصلاحية!", "crit")
                        add({"title": "شهادة SSL منتهية", "severity": "critical",
                             "description": f"انتهت الشهادة منذ {abs(days)} يوم.",
                             "location": f"{host}:443", "recommendation": "جدّد شهادة SSL فوراً."})
                    elif days <= 15:
                        log(f"[!] شهادة SSL تنتهي خلال {days} يوم", "warn")
                        add({"title": "شهادة SSL قريبة الانتهاء", "severity": "medium",
                             "description": f"تنتهي خلال {days} يوم.",
                             "location": f"{host}:443", "recommendation": "جدّد الشهادة."})
                    else:
                        log(f"[+] شهادة SSL صالحة ({days} يوم متبقٍ)", "ok")
                except Exception:
                    pass
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    log(f"[!] بروتوكول تشفير قديم: {proto}", "warn")
                    add({"title": f"بروتوكول تشفير قديم: {proto}", "severity": "medium",
                         "description": f"الخادم يقبل {proto} وهو غير آمن.",
                         "location": f"{host}:443", "recommendation": "استخدم TLS 1.2 أو 1.3 فقط."})
                else:
                    log(f"[+] بروتوكول التشفير: {proto}", "ok")
    except ssl.SSLCertVerificationError as e:
        log("[!] فشل التحقق من الشهادة (منتهية/موقّعة ذاتياً)", "warn")
        add({"title": "شهادة SSL غير موثوقة", "severity": "high",
             "description": f"فشل التحقق: {str(e)}",
             "location": f"{host}:443", "recommendation": "استخدم شهادة موثوقة."})
    except Exception:
        log("[*] المنفذ 443 غير متاح — تخطّي فحص SSL", "mut")


# ==========================
# فحص استجابة HTTP
# ==========================

def check_http(base_url, log, add):
    log("[*] تحليل استجابة HTTP...", "acc")
    try:
        r = httpx.get(base_url, timeout=10, follow_redirects=True,
                      verify=False, headers=UA)
    except Exception as e:
        log(f"[!] تعذّر الاتصال: {str(e)}", "warn")
        return

    headers_lower = {k.lower(): v for k, v in r.headers.items()}

    # ترويسات الأمان المطلوبة
    sec_headers = {
        "strict-transport-security": ("medium", "أضف ترويسة HSTS لإجبار HTTPS."),
        "content-security-policy": ("medium", "أضف CSP للحماية من هجمات XSS."),
        "x-frame-options": ("low", "أضف X-Frame-Options للحماية من Clickjacking."),
        "x-content-type-options": ("low", "أضف X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "أضف Referrer-Policy لضبط تسريب الروابط."),
    }

    for h, (sev, rec) in sec_headers.items():
        if h not in headers_lower:
            log(f"[!] ترويسة أمان مفقودة: {h}", "warn")
            add({
                "title": f"ترويسة أمان مفقودة: {h}",
                "severity": sev,
                "description": f"الموقع لا يرسل ترويسة {h}.",
                "location": base_url,
                "recommendation": rec,
            })

    # الخادم يفصح عن نوعه
    if "server" in headers_lower:
        log(f"[!] الخادم يفصح عن نوعه: {headers_lower['server']}", "warn")
        add({
            "title": "الخادم يفصح عن نوعه",
            "severity": "low",
            "description": f"ترويسة Server تكشف: {headers_lower['server']}",
            "location": base_url,
            "recommendation": "أخفِ أو عمّم ترويسة Server.",
        })

    # فحص الكوكيز
    try:
        cookies = r.headers.get_list("set-cookie")
    except Exception:
        cookies = []
    for c in cookies:
        cl = c.lower()
        name = c.split("=")[0]
        if "secure" not in cl:
            log(f"[!] كوكي بدون Secure: {name}", "warn")
            add({
                "title": f"كوكي بدون علم Secure: {name}",
                "severity": "low",
                "description": "الكوكي يُرسل عبر اتصال غير مشفّر.",
                "location": base_url,
                "recommendation": "أضف علم Secure للكوكيز.",
            })
        if "httponly" not in cl:
            log(f"[!] كوكي بدون HttpOnly: {name}", "warn")
            add({
                "title": f"كوكي بدون HttpOnly: {name}",
                "severity": "medium",
                "description": "الكوكي قابل للقراءة عبر JavaScript (خطر XSS).",
                "location": base_url,
                "recommendation": "أضف علم HttpOnly لكوكيز الجلسات.",
            })

    # قائمة المجلدات
    if "index of /" in r.text.lower():
        log("[!] قائمة مجلدات مكشوفة (Directory Listing)", "warn")
        add({
            "title": "قائمة المجلدات مكشوفة",
            "severity": "medium",
            "description": "الخادم يعرض محتويات المجلدات.",
            "location": base_url,
            "recommendation": "عطّل Directory Listing.",
        })


# ==========================
# المسارات الحساسة
# ==========================

def check_paths(base_url, log, add):
    log("[*] فحص المسارات الحساسة المكشوفة...", "acc")
    rnd = "/" + "".join(random.choices(string.ascii_lowercase, k=12))
    try:
        base = httpx.get(base_url + rnd, timeout=6, verify=False, follow_redirects=False)
        baseline = base.status_code
    except Exception:
        baseline = 404

    for path, sev, rec in SENSITIVE_PATHS:
        url = base_url + "/" + path
        try:
            resp = httpx.get(url, timeout=6, verify=False, follow_redirects=False)
        except Exception:
            continue
        if resp.status_code == 200 and resp.status_code != baseline:
            level = "crit" if sev == "critical" else "warn"
            log(f"[!] مسار حساس مكشوف: /{path}", level)
            add({"title": f"مسار حساس مكشوف: /{path}", "severity": sev,
                 "description": f"المسار /{path} متاح للعامة (HTTP 200).",
                 "location": url, "recommendation": rec})
        else:
            log(f"[*] /{path} -> {resp.status_code}", "mut")


# ==========================
# استخراج روابط فيها وسائط (params)
# ==========================

def _find_param_links(base_url, html):
    host = urlparse(base_url).hostname or ""
    links = []
    seen = set()
    for m in re.findall(r'''(?:href|src)\s*=\s*["']([^"']+)["']''', html, re.I):
        if "?" in m and "=" in m:
            full = urljoin(base_url + "/", m)
            if host in (urlparse(full).hostname or "") and full not in seen:
                seen.add(full)
                links.append(full)
    return links[:6]


def _inject(url, suffix=None, replace=None):
    parts = urlparse(url)
    qs = parse_qsl(parts.query)
    if not qs:
        return None
    newqs = []
    for i, (k, v) in enumerate(qs):
        if i == 0:
            if replace is not None:
                v = replace
            elif suffix:
                v = v + suffix
        newqs.append((k, v))
    return urlunparse(parts._replace(query=urlencode(newqs)))





# نقاط تسجيل دخول شائعة لاختبار SQLi
LOGIN_ENDPOINTS = [
    "/rest/user/login",
    "/api/login",
    "/login",
    "/api/auth/login",
]

# حمولات SQL Injection للمصادقة
AUTH_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "admin'--",
    "' OR 1=1#",
]


def check_auth_bypass(base_url, log, add):
    """اختبار تجاوز المصادقة عبر SQL Injection في تسجيل الدخول."""
    log("[*] اختبار SQL Injection في تسجيل الدخول...", "acc")

    for endpoint in LOGIN_ENDPOINTS:
        url = base_url + endpoint
        for payload in AUTH_PAYLOADS:
            body = {"email": payload, "password": payload}
            try:
                r = httpx.post(url, json=body, timeout=8,
                               verify=False, follow_redirects=True, headers=UA)
            except Exception:
                continue

            low = r.text.lower()

            # مؤشّر 1: ظهور خطأ SQL في الرد
            if any(sig in low for sig in SQL_ERRORS):
                log(f"[CRIT] SQLi في تسجيل الدخول: {endpoint}", "crit")
                add({
                    "title": "SQL Injection في تسجيل الدخول",
                    "severity": "critical",
                    "description": f"نقطة تسجيل الدخول {endpoint} تُظهر خطأ SQL "
                                   "عند الحقن، مما قد يسمح بتجاوز المصادقة.",
                    "location": url,
                    "recommendation": "استخدم Parameterized Queries في استعلام "
                                      "تسجيل الدخول ولا تبنِ الاستعلام من نص المستخدم.",
                })
                return  # وجدنا الثغرة، نكتفي

            # مؤشّر 2: نجاح الدخول (استلام توكن) رغم بيانات وهمية
            if r.status_code == 200 and ("token" in low or "authentication" in low):
                log(f"[CRIT] تجاوز مصادقة عبر SQLi: {endpoint}", "crit")
                add({
                    "title": "تجاوز المصادقة عبر SQL Injection",
                    "severity": "critical",
                    "description": f"تمكّن الحقن من تسجيل الدخول عبر {endpoint} "
                                   "ببيانات وهمية — اختراق كامل للحسابات!",
                    "location": url,
                    "recommendation": "استخدم Parameterized Queries وفعّل قفل "
                                      "المحاولات، ولا تكشف رسائل الخطأ التفصيلية.",
                })
                return

    log("[+] لا مؤشّر SQLi واضح في تسجيل الدخول", "ok")





def crawl_site(base_url, log, max_pages=15):
    """يزحف على الموقع ويجمع روابط الصفحات الداخلية التي بها وسائط."""
    log("[*] بدء الزحف على الموقع...", "acc")

    host = urlparse(base_url).hostname or ""
    to_visit = [base_url]
    visited = set()
    param_links = set()

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            r = httpx.get(url, timeout=6, verify=False,
                          follow_redirects=True, headers=UA)
        except Exception:
            continue

        # استخراج كل الروابط الداخلية
        for m in re.findall(r'''(?:href|src)\s*=\s*["']([^"']+)["']''', r.text, re.I):
            full = urljoin(url + "/", m)
            p = urlparse(full)

            # فقط روابط نفس الموقع
            if host not in (p.hostname or ""):
                continue

            # رابط به وسائط للحقن
            if "?" in full and "=" in full:
                param_links.add(full)

            # صفحة جديدة للزيارة
            clean = full.split("#")[0]
            if (clean not in visited and clean not in to_visit
                    and len(to_visit) < max_pages):
                to_visit.append(clean)

    log(f"[+] تم زحف {len(visited)} صفحة — وجد {len(param_links)} نقطة إدخال", "ok")
    return list(param_links)



# ==========================
# اختبار SQL Injection و XSS
# ==========================
def check_injection(base_url, log, add):
    log("[*] اختبار حقن SQL و XSS (كشف فقط)...", "acc")

    # الزحف على الموقع لجمع نقاط الإدخال من كل الصفحات
    candidates = crawl_site(base_url, log)

    # إضافة نقاط الإدخال الشائعة (API + بحث)
    for p in PROBE_ENDPOINTS:
        candidates.append(base_url + p)

    # إزالة التكرار
    seen = set()
    uniq = []
    for u in candidates:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    candidates = uniq[:20]

    log(f"[*] اختبار {len(candidates)} نقطة إدخال...", "mut")

    found = set()  # لتفادي تكرار نفس نوع الثغرة
    tested = 0

    for url in candidates:
        tested += 1

        # SQL Injection
        if "sqli" not in found:
            sqli_url = _inject(url, suffix="'")
            if sqli_url:
                try:
                    r = httpx.get(sqli_url, timeout=8, verify=False,
                                  follow_redirects=True, headers=UA)
                    low = r.text.lower()
                    if any(sig in low for sig in SQL_ERRORS):
                        found.add("sqli")
                        log(f"[CRIT] SQL Injection: {sqli_url}", "crit")
                        add({
                            "title": "ثغرة SQL Injection",
                            "severity": "critical",
                            "description": "ظهرت رسالة خطأ قاعدة بيانات عند حقن "
                                           "علامة اقتباس، مما يدل على عدم تعقيم المدخلات.",
                            "location": sqli_url,
                            "recommendation": "استخدم Parameterized Queries وعقّم المدخلات.",
                        })
                except Exception:
                    pass

        # XSS المنعكس
        if "xss" not in found:
            marker = "svxss7391"
            payload = f"<{marker}>"
            xss_url = _inject(url, replace=payload)
            if xss_url:
                try:
                    r = httpx.get(xss_url, timeout=8, verify=False,
                                  follow_redirects=True, headers=UA)
                    if payload in r.text:
                        found.add("xss")
                        log(f"[CRIT] XSS منعكس: {xss_url}", "crit")
                        add({
                            "title": "ثغرة XSS منعكس",
                            "severity": "high",
                            "description": "انعكس المدخل في الصفحة دون تعقيم.",
                            "location": xss_url,
                            "recommendation": "عقّم واهرب (escape) المدخلات قبل عرضها.",
                        })
                except Exception:
                    pass

    log(f"[+] تم اختبار {tested} نقطة إدخال", "ok")

# ==========================
# المنسّق العام
# ==========================


# قاعدة مبسّطة لثغرات إصدارات معروفة (CVE)
CVE_DB = {
    "apache": [
        ("2.4.49", "critical", "CVE-2021-41773",
         "ثغرة Path Traversal و RCE في Apache 2.4.49."),
        ("2.4.50", "critical", "CVE-2021-42013",
         "ثغرة Path Traversal و RCE في Apache 2.4.50."),
        ("2.2", "high", "متعدد",
         "Apache 2.2 قديم جداً وبه ثغرات متعددة معروفة."),
    ],
    "nginx": [
        ("1.3", "high", "CVE-2013-2028",
         "ثغرة Stack Overflow في نسخ nginx القديمة."),
    ],
    "openssh": [
        ("7.2", "medium", "CVE-2016-6210",
         "ثغرة كشف المستخدمين (User Enumeration) في OpenSSH < 7.3."),
    ],
    "php": [
        ("5.", "high", "متعدد",
         "PHP 5.x انتهى دعمه وبه ثغرات متعددة — رقّ إلى PHP 8."),
    ],
    "openssl": [
        ("1.0.1", "critical", "CVE-2014-0160",
         "ثغرة Heartbleed الشهيرة في OpenSSL 1.0.1."),
    ],
}


def check_cve(base_url, log, add):
    """يقرأ إصدارات البرمجيات من الترويسات ويطابقها مع ثغرات معروفة."""
    log("[*] فحص إصدارات البرمجيات (CVE)...", "acc")

    try:
        r = httpx.get(base_url, timeout=8, verify=False,
                      follow_redirects=True, headers=UA)
    except Exception as e:
        log(f"[!] تعذّر جلب الترويسات: {str(e)}", "warn")
        return

    # جمع نصوص الترويسات التي قد تحوي إصدارات
    banners = []
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        val = r.headers.get(h)
        if val:
            banners.append(val.lower())
            log(f"[*] {h}: {val}", "mut")

    if not banners:
        log("[+] لا ترويسات تكشف إصدارات", "ok")
        return

    banner_text = " ".join(banners)

    for product, entries in CVE_DB.items():
        if product in banner_text:
            for version, sev, cve, desc in entries:
                if version in banner_text:
                    level = "crit" if sev == "critical" else "warn"
                    log(f"[!] إصدار مصاب: {product} {version} ({cve})", level)
                    add({
                        "title": f"إصدار برمجي مصاب: {product} ({cve})",
                        "severity": sev,
                        "description": desc,
                        "location": base_url,
                        "recommendation": f"حدّث {product} إلى أحدث إصدار فوراً.",
                    })


def run_deep_checks(target, log, add, prog):
    host = _host(target)
    base = _resolve_base(target, log)

    prog(68)
    check_ssl(host, log, add)
    prog(75)
    check_http(base, log, add)
    prog(80)
    check_cve(base, log, add)
    prog(86)
    check_paths(base, log, add)
    prog(92)
    check_injection(base, log, add)
    prog(97)
    check_auth_bypass(base, log, add)