"""فحص التطبيقات عبر الرابط: Play Store / App Store / رابط مباشر."""
import ipaddress
import os
import re
import socket
import tempfile
from urllib.parse import urlparse

import httpx

from . import appscan


PLAY_STORE_RE = re.compile(r"^https?://play\.google\.com/store/apps/details\?[^\s]*id=([a-zA-Z0-9._]+)")
APP_STORE_RE = re.compile(r"^https?://apps\.apple\.com/(?:[a-z]{2}/)?app/[^/]+/id(\d+)")

MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024
ALLOWED_EXTS = {
    ".apk", ".aab", ".xapk", ".ipa",
    ".exe", ".dll", ".msi",
    ".elf", ".deb", ".rpm", ".appimage",
    ".dmg", ".pkg", ".app", ".jar",
}


def scan_url(url: str) -> dict:
    url = (url or "").strip()
    if not url:
        return {"error": "رابط فارغ"}

    m = PLAY_STORE_RE.match(url)
    if m:
        return scan_play_store(m.group(1), url)

    m = APP_STORE_RE.match(url)
    if m:
        return scan_app_store(m.group(1), url)

    if url.startswith(("http://", "https://")):
        return scan_direct_url(url)

    return {"error": "رابط غير معروف (يجب أن يبدأ بـ http/https)"}


# ---------------- Google Play ----------------
def scan_play_store(package: str, url: str) -> dict:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SecureVision/1.0)"}
        r = httpx.get(url, headers=headers, timeout=15, follow_redirects=True)
        html = r.text

        info = {
            "source": "Google Play Store",
            "package": package,
            "url": url,
        }

        def grab(pattern, flags=0):
            m = re.search(pattern, html, flags)
            return m.group(1).strip() if m else ""

        title = grab(r"<title[^>]*>([^<]+?)(?:\s*[-–—]\s*Apps on Google Play)?</title>")
        if title:
            info["app_name"] = title

        dev = grab(r'"developer":\s*{\s*"name":\s*"([^"]+)"') or \
              grab(r'itemprop="author"[^>]*>[^<]*<a[^>]*>([^<]+)</a>')
        if dev:
            info["developer"] = dev

        desc = grab(r'<meta name="description" content="([^"]+)"')
        if desc:
            info["description"] = desc[:500]

        rating = grab(r'"ratingValue":\s*"?([\d.]+)"?')
        if rating:
            try:
                info["rating"] = float(rating)
            except Exception:
                pass

        installs = grab(r"([\d,]+\+)\s*(?:downloads|installs)", re.I)
        if installs:
            info["installs"] = installs

        icon = grab(r'<meta property="og:image" content="([^"]+)"')
        if icon:
            info["icon_url"] = icon

        return {
            "source_type": "play_store",
            "metadata": info,
            "note": "للتحليل الأمني العميق (الصلاحيات + الشهادة + المفاتيح المسرّبة)، حمّل الـ APK محلّياً ثمّ ارفعه عبر تبويب 'رفع ملفّ'.",
        }
    except Exception as e:
        return {"error": f"فشل جلب معلومات Play Store: {e}"}


# ---------------- Apple App Store ----------------
def scan_app_store(app_id: str, url: str) -> dict:
    try:
        api = f"https://itunes.apple.com/lookup?id={app_id}"
        r = httpx.get(api, timeout=15)
        data = r.json()
        if not data.get("results"):
            return {"error": "لم يُعثر على التطبيق في App Store"}

        app = data["results"][0]
        info = {
            "source": "Apple App Store",
            "app_id": app_id,
            "url": url,
            "app_name": app.get("trackName", ""),
            "developer": app.get("artistName", ""),
            "seller": app.get("sellerName", ""),
            "bundle_id": app.get("bundleId", ""),
            "version": app.get("version", ""),
            "price": app.get("formattedPrice", ""),
            "size_bytes": app.get("fileSizeBytes", ""),
            "rating": app.get("averageUserRating", ""),
            "rating_count": app.get("userRatingCount", ""),
            "min_ios": app.get("minimumOsVersion", ""),
            "release_date": app.get("releaseDate", ""),
            "current_version_date": app.get("currentVersionReleaseDate", ""),
            "genre": app.get("primaryGenreName", ""),
            "icon_url": app.get("artworkUrl512") or app.get("artworkUrl100", ""),
            "description": (app.get("description") or "")[:500],
        }
        return {
            "source_type": "app_store",
            "metadata": info,
            "note": "ملفّات IPA غير قابلة للتنزيل من App Store مباشرة (Apple تُشفّرها) — البيانات أعلاه رسمية من Apple.",
        }
    except Exception as e:
        return {"error": f"فشل جلب معلومات App Store: {e}"}


# ---------------- رابط مباشر ----------------
def scan_direct_url(url: str) -> dict:
    # SSRF guard
    try:
        host = urlparse(url).hostname
        if not host:
            return {"error": "رابط غير صالح"}
        ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(ip)
        if (ip_obj.is_private or ip_obj.is_loopback or
                ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved):
            return {"error": "الرابط يشير إلى عنوان داخلي/محجوز — مرفوض لأسباب أمنية (SSRF)"}
    except Exception as e:
        return {"error": f"تعذّر التحقّق من عنوان الخادم: {e}"}

    # Guess extension from URL path
    path = urlparse(url).path
    ext = os.path.splitext(path)[1].lower()
    if ext not in ALLOWED_EXTS:
        ext = ".bin"

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    total = 0
    try:
        with httpx.stream("GET", url, timeout=120, follow_redirects=True) as r:
            r.raise_for_status()
            for chunk in r.iter_bytes(1024 * 64):
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise Exception("الملفّ أكبر من 200 MB")
                tmp.write(chunk)
        tmp.close()

        original = os.path.basename(path) or "downloaded"
        result = appscan.analyze_file(tmp.name, original_name=original)
        result["source_type"] = "direct_url"
        result["source_url"] = url
        return result
    except httpx.HTTPStatusError as e:
        return {"error": f"الخادم البعيد رفض التنزيل (HTTP {e.response.status_code})"}
    except Exception as e:
        return {"error": f"فشل تنزيل/تحليل الملفّ: {e}"}
    finally:
        try:
            if os.path.exists(tmp.name):
                os.unlink(tmp.name)
        except Exception:
            pass