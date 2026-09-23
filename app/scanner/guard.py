import ipaddress
from urllib.parse import urlparse


# نطاقات مشهورة ممنوع فحصها إطلاقاً (لا تملكها)
BLOCKED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "facebook.com",
    "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    "microsoft.com", "apple.com", "amazon.com", "aws.amazon.com",
    "cloudflare.com", "github.com", "gitlab.com", "netflix.com",
    "tiktok.com", "linkedin.com", "reddit.com", "wikipedia.org",
    "paypal.com", "visa.com", "mastercard.com", "stripe.com",
    "openai.com", "anthropic.com",
}

# لواحق حساسة ممنوعة (حكومية / عسكرية / بنوك)
BLOCKED_SUFFIXES = (".gov", ".mil", ".gov.sa", ".bank")


def extract_host(target: str) -> str:
    """يستخرج اسم المضيف من الهدف (مع أو بدون http)."""
    t = (target or "").strip()
    if "://" not in t:
        t = "http://" + t
    host = urlparse(t).hostname or ""
    return host.lower()


def is_local_host(host: str) -> bool:
    """هل الهدف جهاز محلي/شبكة داخلية (أجهزتك الخاصة)؟"""
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def validate_target(target: str, consent: bool = False) -> str:
    """يتحقق أن الهدف قانوني للفحص.
    يُعيد اسم المضيف إذا كان مسموحاً، أو يرفع ValueError إذا ممنوع."""

    host = extract_host(target)

    if not host:
        raise ValueError("الهدف غير صالح — أدخل رابطاً أو عنواناً صحيحاً")

    # 1) نطاقات مشهورة ممنوعة
    for bad in BLOCKED_DOMAINS:
        if host == bad or host.endswith("." + bad):
            raise ValueError(
                f"⛔ غير مسموح بفحص «{host}» — أنت لا تملك هذا الموقع. "
                "افحص فقط الأنظمة التي تملكها أو لديك إذن صريح بفحصها."
            )

    # 2) لواحق حساسة ممنوعة
    for suf in BLOCKED_SUFFIXES:
        if host.endswith(suf):
            raise ValueError(
                f"⛔ غير مسموح بفحص النطاقات الحساسة ({suf}) — "
                "جهات حكومية/عسكرية/بنكية ممنوعة نهائياً."
            )

    # 3) هدف خارجي بدون تأكيد ملكية
    if not is_local_host(host) and not consent:
        raise ValueError(
            "⚠️ يجب تأكيد أنك تملك هذا الهدف أو لديك إذن صريح بفحصه "
            "قبل بدء الفحص."
        )

    return host