import re
import socket
import ipaddress
from urllib.parse import urlparse

import httpx

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "work",
                   "click", "link", "country", "science", "party", "zip", "mov"}

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "adf.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}

PHISH_KEYWORDS = ["login", "signin", "verify", "account", "secure", "update",
                  "confirm", "password", "wallet", "bonus", "gift", "webscr", "banking"]

BRAND_WORDS = ["paypal", "apple", "microsoft", "google", "amazon",
               "facebook", "instagram", "netflix", "whatsapp", "binance"]

SEV_POINTS = {"critical": 40, "high": 25, "medium": 15, "low": 8}


def _is_private(host: str) -> bool:
    """يمنع فحص العناوين الداخلية (حماية من SSRF)."""
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except Exception:
        return False


def _base_domain(h: str) -> str:
    """النطاق الأساسي (آخر جزأين) — لتجاهل www والنطاقات الفرعية لنفس الموقع."""
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def analyze_url(raw: str) -> dict:
    checks = []
    score = 0

    url = raw.strip()
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    after_scheme = url.split("://", 1)[1] if "://" in url else url

    def add(name, ok, sev, detail):
        nonlocal score
        if not ok:
            score += SEV_POINTS.get(sev, 0)
        checks.append({
            "name": name,
            "ok": ok,
            "severity": sev if not ok else "info",
            "detail": detail,
        })

    # ========== فحوصات بنية الرابط ==========

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        add("استخدام IP بدل اسم نطاق", False, "high", f"يستخدم IP مباشر: {host}")
    else:
        add("استخدام IP بدل اسم نطاق", True, "high", "يستخدم اسم نطاق عادي")

    if "@" in after_scheme:
        add("وجود رمز @ في الرابط", False, "high", "@ يُستخدم لإخفاء الوجهة الحقيقية")
    else:
        add("وجود رمز @ في الرابط", True, "high", "لا يوجد @")

    if p.scheme != "https":
        add("الاتصال مشفّر (HTTPS)", False, "medium", "يستخدم HTTP غير المشفّر")
    else:
        add("الاتصال مشفّر (HTTPS)", True, "medium", "يستخدم HTTPS")

    tld = host.split(".")[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        add("امتداد نطاق مشبوه", False, "medium", f".{tld} شائع في المواقع المزيفة")
    else:
        add("امتداد نطاق مشبوه", True, "medium", f"امتداد .{tld} عادي")

    if host in SHORTENERS:
        add("مختصِر روابط", False, "medium", f"{host} يخفي الوجهة الحقيقية")
    else:
        add("مختصِر روابط", True, "medium", "ليس مختصِر روابط")

    if "xn--" in host:
        add("نطاق بحروف محاكية (Punycode)", False, "high", "قد يحاكي علامة تجارية بأحرف مشابهة")
    else:
        add("نطاق بحروف محاكية (Punycode)", True, "high", "لا يوجد ترميز مشبوه")

    if len(url) > 75:
        add("طول الرابط", False, "low", f"طويل ({len(url)} حرف) — أسلوب تمويه")
    else:
        add("طول الرابط", True, "low", "طول طبيعي")

    dots = host.count(".")
    if dots >= 4:
        add("كثرة النطاقات الفرعية", False, "medium", f"{dots} نطاقات فرعية — تمويه")
    else:
        add("كثرة النطاقات الفرعية", True, "medium", "عدد طبيعي")

    hits = [k for k in PHISH_KEYWORDS if k in host]
    if hits:
        add("كلمات تصيّد في النطاق", False, "medium", "كلمات: " + ", ".join(hits))
    else:
        add("كلمات تصيّد في النطاق", True, "medium", "لا كلمات مشبوهة")

    brand_hits = [b for b in BRAND_WORDS if b in host]
    legit = any(host == b + ".com" or host.endswith("." + b + ".com") for b in brand_hits)
    if brand_hits and not legit:
        add("انتحال علامة تجارية", False, "high", "اسم علامة (" + ", ".join(brand_hits) + ") في نطاق غير رسمي")
    else:
        add("انتحال علامة تجارية", True, "high", "لا انتحال واضح")

    digits = sum(c.isdigit() for c in host)
    if host.count("-") >= 3 or digits >= 5:
        add("شرطات/أرقام كثيرة في النطاق", False, "low", "مؤشّر تمويه")
    else:
        add("شرطات/أرقام في النطاق", True, "low", "طبيعي")

    if "%" in url:
        add("رموز مُرمّزة في الرابط", False, "low", "قد تُستخدم لإخفاء محتوى")
    else:
        add("رموز مُرمّزة في الرابط", True, "low", "لا ترميز مشبوه")

    # ========== فحوصات حيّة (اتصال فعلي) ==========
    if _is_private(host) or not host:
        add("الفحص الحيّ", True, "low", "عنوان داخلي/غير صالح — تم تخطّي الاتصال الفعلي")
    else:
        try:
            with httpx.Client(follow_redirects=True, timeout=8.0, verify=True) as client:
                resp = client.get(url, headers={"User-Agent": "SecureVision-LinkScanner/1.0"})
            final_host = (urlparse(str(resp.url)).hostname or "").lower()

            add("الموقع يستجيب فعلياً", True, "low", f"رمز الحالة: {resp.status_code}")

            if final_host and _base_domain(final_host) != _base_domain(host):
                add("إعادة التوجيه لنطاق مختلف", False, "medium", f"يحوّلك إلى: {final_host}")
            else:
                add("إعادة التوجيه", True, "low", "لا يحوّلك لنطاق خارجي مختلف")

            # نوع الخادم: معلومة فقط (لا تُحتسب كخطر)
            server = resp.headers.get("server")
            add("نوع خادم الموقع", True, "info", f"Server: {server}" if server else "غير معلن")

        except Exception as e:
            msg = str(e).lower()
            if "certificate" in msg or "ssl" in msg or "verify" in msg:
                add("شهادة SSL صالحة", False, "high", "شهادة HTTPS غير صالحة أو منتهية — خطر انتحال")
            elif "timeout" in msg:
                add("الموقع يستجيب فعلياً", False, "low", "انتهت مهلة الاتصال")
            else:
                add("الموقع يستجيب فعلياً", False, "medium", "تعذّر الاتصال — قد يكون معطّلاً أو محجوباً")

    # ========== الحكم النهائي ==========
    risk = min(100, score)
    if risk >= 60:
        verdict, level = "🔴 خطير — على الأرجح رابط تصيّد/ملغّم", "critical"
    elif risk >= 30:
        verdict, level = "🟠 مشبوه — توخَّ الحذر الشديد", "high"
    elif risk >= 12:
        verdict, level = "🟡 مشكوك فيه قليلاً", "medium"
    else:
        verdict, level = "🟢 يبدو آمناً", "low"

    return {
        "url": raw,
        "host": host,
        "risk": risk,
        "verdict": verdict,
        "level": level,
        "checks": checks,
    }