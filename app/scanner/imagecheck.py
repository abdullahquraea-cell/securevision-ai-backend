import re

SEV_POINTS = {"critical": 40, "high": 25, "medium": 15, "low": 8}

# التواقيع السحرية لأنواع الصور الحقيقية
SIGNATURES = {
    b"\xff\xd8\xff": "JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"BM": "BMP",
    b"RIFF": "WEBP",
}

# أنماط مشبوهة قد تدل على كود مدسوس داخل الصورة
SUSPICIOUS_PATTERNS = [
    (rb"<\?php", "critical", "كود PHP مدسوس داخل الصورة"),
    (rb"<script", "critical", "سكربت JavaScript مدسوس"),
    (rb"eval\s*\(", "high", "استدعاء eval() — تنفيذ كود مشبوه"),
    (rb"base64_decode", "high", "فك تشفير Base64 — إخفاء محتوى"),
    (rb"powershell", "high", "أمر PowerShell مدسوس"),
    (rb"cmd\.exe", "high", "استدعاء cmd.exe"),
    (rb"/bin/sh", "medium", "استدعاء صدفة نظام (shell)"),
    (rb"system\s*\(", "medium", "استدعاء system() لتنفيذ أوامر"),
    (rb"<%", "medium", "كود سكربت خادم (ASP/JSP)"),
]

# تواقيع ملفات مخفية داخل الصورة (polyglot)
EMBEDDED_FILES = [
    (b"PK\x03\x04", "high", "أرشيف ZIP مخفي داخل الصورة"),
    (b"Rar!", "high", "أرشيف RAR مخفي"),
    (b"MZ", "critical", "ملف تنفيذي Windows (EXE) مخفي"),
    (b"\x7fELF", "critical", "ملف تنفيذي Linux (ELF) مخفي"),
]


def analyze_image(filename: str, data: bytes) -> dict:
    checks = []
    score = 0
    size = len(data)

    def add(name, ok, sev, detail):
        nonlocal score
        if not ok:
            score += SEV_POINTS.get(sev, 0)
        checks.append({
            "name": name, "ok": ok,
            "severity": sev if not ok else "info", "detail": detail,
        })

    # 1) التحقق من التوقيع الحقيقي (هل هي صورة فعلاً؟)
    real_type = None
    for sig, typ in SIGNATURES.items():
        if data.startswith(sig):
            real_type = typ
            break

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if real_type is None:
        add("نوع الملف الحقيقي", False, "critical",
            f"الملف يحمل امتداد .{ext} لكنه ليس صورة حقيقية! (نوع مزيّف)")
    else:
        add("نوع الملف الحقيقي", True, "critical", f"صورة حقيقية من نوع {real_type}")

    # 2) تطابق الامتداد مع النوع الحقيقي
    if real_type:
        type_ext = {"JPEG": ["jpg", "jpeg"], "PNG": ["png"], "GIF": ["gif"],
                    "BMP": ["bmp"], "WEBP": ["webp"]}.get(real_type, [])
        if ext and ext not in type_ext:
            add("تطابق الامتداد", False, "high",
                f"الامتداد .{ext} لا يطابق النوع الحقيقي ({real_type})")
        else:
            add("تطابق الامتداد", True, "high", "الامتداد يطابق النوع")

    # 3) كود مدسوس داخل الصورة
    lowered = data.lower()
    found_code = False
    for pattern, sev, desc in SUSPICIOUS_PATTERNS:
        if re.search(pattern, lowered):
            add(f"محتوى مشبوه: {desc}", False, sev, "عُثر على نمط خبيث داخل بيانات الصورة")
            found_code = True
    if not found_code:
        add("كود مدسوس", True, "high", "لا يوجد كود مشبوه داخل الصورة")

    # 4) ملفات مخفية (polyglot) — نتخطّى أول 4 بايت (توقيع الصورة نفسه)
    found_embed = False
    for sig, sev, desc in EMBEDDED_FILES:
        idx = data.find(sig, 20)  # نبحث بعد بداية الصورة
        if idx != -1:
            add(f"ملف مخفي: {desc}", False, sev, f"عُثر على توقيع ملف في الموضع {idx}")
            found_embed = True
    if not found_embed:
        add("ملفات مخفية", True, "high", "لا توجد ملفات مدسوسة")

    # 5) بيانات بعد نهاية الصورة (JPEG ينتهي بـ FFD9)
    if real_type == "JPEG":
        end = data.rfind(b"\xff\xd9")
        if end != -1 and end < size - 10:
            trailing = size - end - 2
            add("بيانات بعد نهاية الصورة", False, "medium",
                f"يوجد {trailing} بايت مخفية بعد نهاية الصورة الفعلية")
        else:
            add("بيانات بعد نهاية الصورة", True, "medium", "لا بيانات زائدة")

    # 6) حجم غير طبيعي
    if size < 100:
        add("حجم الملف", False, "low", f"صغير جداً ({size} بايت) — قد لا يكون صورة حقيقية")
    elif size > 15 * 1024 * 1024:
        add("حجم الملف", False, "low", f"كبير جداً ({size // (1024*1024)} MB) — قد يخفي محتوى")
    else:
        add("حجم الملف", True, "low", f"حجم طبيعي ({size // 1024} KB)")

    risk = min(100, score)
    if risk >= 60:
        verdict, level = "🔴 خطير — الصورة ملغّمة على الأرجح", "critical"
    elif risk >= 30:
        verdict, level = "🟠 مشبوهة — لا تفتحها بلا فحص", "high"
    elif risk >= 12:
        verdict, level = "🟡 مشكوك فيها قليلاً", "medium"
    else:
        verdict, level = "🟢 تبدو آمنة", "low"

    return {
        "filename": filename,
        "size_kb": round(size / 1024, 1),
        "real_type": real_type or "غير معروف",
        "risk": risk,
        "verdict": verdict,
        "level": level,
        "checks": checks,
    }