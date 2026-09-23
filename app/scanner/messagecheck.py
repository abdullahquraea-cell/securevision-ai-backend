import re

SEV_POINTS = {"critical": 40, "high": 25, "medium": 15, "low": 8}

# كلمات الإلحاح والطوارئ المصطنعة
URGENCY_WORDS = ["عاجل", "فوري", "الآن", "خلال 24 ساعة", "ينتهي", "سينتهي",
                 "احذر", "تحذير", "موقوف", "معلّق", "urgent", "immediately",
                 "suspended", "expire", "act now", "verify now"]

# طلب بيانات حساسة
SENSITIVE_REQUESTS = ["كلمة المرور", "الرقم السري", "رمز التحقق", "otp",
                      "بيانات البطاقة", "رقم البطاقة", "cvv", "pin",
                      "الهوية", "password", "credit card", "ssn", "login"]

# إغراءات ووعود احتيالية
BAIT_WORDS = ["مبروك", "ربحت", "فزت", "جائزة", "مجاني", "هدية", "مليون",
              "won", "winner", "prize", "free", "congratulations", "claim",
              "قرض", "استرداد", "تعويض"]

# انتحال جهات
IMPERSONATION = ["البنك", "الجمارك", "أبشر", "وزارة", "الشرطة", "بريد",
                 "paypal", "apple", "microsoft", "amazon", "netflix",
                 "شركة الكهرباء", "المرور", "الضرائب"]


def _find_urls(text):
    return re.findall(r"(https?://[^\s]+|www\.[^\s]+|[a-z0-9\-]+\.(?:tk|ml|ga|xyz|top|click|link)[^\s]*)",
                      text, re.I)


def analyze_message(text: str) -> dict:
    checks = []
    score = 0
    low = text.lower()

    def add(name, ok, sev, detail):
        nonlocal score
        if not ok:
            score += SEV_POINTS.get(sev, 0)
        checks.append({
            "name": name, "ok": ok,
            "severity": sev if not ok else "info", "detail": detail,
        })

    # 1) روابط داخل الرسالة
    urls = _find_urls(text)
    if urls:
        add("وجود روابط", False, "medium",
            f"تحتوي الرسالة على {len(urls)} رابط: {urls[0][:50]}")
    else:
        add("وجود روابط", True, "medium", "لا روابط في الرسالة")

    # 2) روابط مشبوهة (امتدادات/مختصِرات)
    bad_url = [u for u in urls if re.search(r"\.(tk|ml|ga|xyz|top|click|link)", u, re.I)
               or re.search(r"(bit\.ly|tinyurl|cutt\.ly|t\.co)", u, re.I)]
    if bad_url:
        add("روابط خطيرة", False, "high", f"رابط مشبوه: {bad_url[0][:50]}")
    else:
        add("روابط خطيرة", True, "high", "لا روابط خطيرة واضحة")

    # 3) طلب بيانات حساسة
    sens = [w for w in SENSITIVE_REQUESTS if w in low]
    if sens:
        add("طلب بيانات حساسة", False, "critical",
            "تطلب: " + ", ".join(sens[:3]))
    else:
        add("طلب بيانات حساسة", True, "critical", "لا تطلب بيانات حساسة")

    # 4) إلحاح وطوارئ مصطنعة
    urg = [w for w in URGENCY_WORDS if w in low]
    if urg:
        add("إلحاح مصطنع", False, "high", "كلمات ضغط: " + ", ".join(urg[:3]))
    else:
        add("إلحاح مصطنع", True, "high", "لا ضغط زمني مشبوه")

    # 5) إغراءات ووعود
    bait = [w for w in BAIT_WORDS if w in low]
    if bait:
        add("إغراءات احتيالية", False, "high", "وعود: " + ", ".join(bait[:3]))
    else:
        add("إغراءات احتيالية", True, "high", "لا إغراءات مشبوهة")

    # 6) انتحال جهة رسمية
    imp = [w for w in IMPERSONATION if w in low]
    if imp and (urls or sens or urg):
        add("انتحال جهة رسمية", False, "high",
            "تنتحل: " + ", ".join(imp[:2]) + " مع طلب إجراء")
    else:
        add("انتحال جهة رسمية", True, "high", "لا انتحال واضح")

    # 7) أرقام هواتف غريبة
    if re.search(r"\+?\d{10,15}", text) and (bait or urg):
        add("رقم اتصال مشبوه", False, "low", "طلب اتصال مع إغراء/إلحاح")
    else:
        add("رقم اتصال مشبوه", True, "low", "لا مؤشّر واضح")

    risk = min(100, score)
    if risk >= 60:
        verdict, level = "🔴 خطيرة — رسالة احتيال/تصيّد على الأرجح", "critical"
    elif risk >= 30:
        verdict, level = "🟠 مشبوهة — لا تتفاعل معها", "high"
    elif risk >= 12:
        verdict, level = "🟡 مشكوك فيها قليلاً", "medium"
    else:
        verdict, level = "🟢 تبدو آمنة", "low"

    return {
        "risk": risk,
        "verdict": verdict,
        "level": level,
        "urls": urls,
        "checks": checks,
    }