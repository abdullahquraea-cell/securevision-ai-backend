import re

SEV_POINTS = {"critical": 40, "high": 25, "medium": 15, "low": 8}

# التواقيع السحرية لأنواع الفيديو الحقيقية
VIDEO_SIGNATURES = [
    (b"\x00\x00\x00\x18ftyp", "MP4"),
    (b"\x00\x00\x00\x1cftyp", "MP4"),
    (b"\x00\x00\x00\x20ftyp", "MP4"),
    (b"ftyp", "MP4/MOV"),
    (b"\x1aE\xdf\xa3", "MKV/WebM"),
    (b"RIFF", "AVI"),
    (b"FLV", "FLV"),
    (b"OggS", "OGG"),
    (b"\x30\x26\xb2\x75", "WMV/ASF"),
]

# امتدادات فيديو معروفة
VIDEO_EXTS = ["mp4", "mkv", "avi", "mov", "webm", "flv", "wmv", "ogg", "m4v", "3gp"]

# أنماط كود مشبوه
SUSPICIOUS_PATTERNS = [
    (rb"<\?php", "critical", "كود PHP مدسوس داخل الفيديو"),
    (rb"<script", "critical", "سكربت JavaScript مدسوس"),
    (rb"powershell", "high", "أمر PowerShell مدسوس"),
    (rb"cmd\.exe", "high", "استدعاء cmd.exe"),
    (rb"eval\s*\(", "high", "استدعاء eval() مشبوه"),
    (rb"base64_decode", "medium", "فك تشفير Base64 مخفي"),
    (rb"/bin/sh", "medium", "استدعاء صدفة نظام (shell)"),
]

# ملفات تنفيذية مخفية
EMBEDDED_FILES = [
    (b"MZ", "critical", "ملف تنفيذي Windows (EXE) مخفي"),
    (b"\x7fELF", "critical", "ملف تنفيذي Linux (ELF) مخفي"),
    (b"PK\x03\x04", "high", "أرشيف ZIP مخفي"),
    (b"Rar!", "high", "أرشيف RAR مخفي"),
]

# امتدادات مزدوجة خطيرة (خدعة شائعة)
DANGEROUS_DOUBLE = ["exe", "scr", "bat", "cmd", "com", "vbs", "js", "jar", "ps1"]


def analyze_video(filename: str, data: bytes) -> dict:
    checks = []
    score = 0
    size = len(data)
    header = data[:64]

    def add(name, ok, sev, detail):
        nonlocal score
        if not ok:
            score += SEV_POINTS.get(sev, 0)
        checks.append({
            "name": name, "ok": ok,
            "severity": sev if not ok else "info", "detail": detail,
        })

    # 1) النوع الحقيقي (هل هو فيديو فعلاً؟)
    real_type = None
    for sig, typ in VIDEO_SIGNATURES:
        if sig in header:
            real_type = typ
            break

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if real_type is None:
        add("نوع الملف الحقيقي", False, "critical",
            f"الملف يحمل امتداد .{ext} لكنه ليس فيديو حقيقياً! (نوع مزيّف)")
    else:
        add("نوع الملف الحقيقي", True, "critical", f"فيديو حقيقي من نوع {real_type}")

    # 2) الامتداد المزدوج الخطير (مثل video.mp4.exe)
    parts = filename.lower().split(".")
    double_ext = None
    if len(parts) >= 3:
        for p in parts[1:-1]:
            if p in VIDEO_EXTS and parts[-1] in DANGEROUS_DOUBLE:
                double_ext = parts[-1]
    if double_ext:
        add("امتداد مزدوج خطير", False, "critical",
            f"الملف ينتهي بـ .{double_ext} (تنفيذي) متخفياً كفيديو!")
    else:
        add("امتداد مزدوج خطير", True, "critical", "لا امتداد مزدوج خطير")

    # 3) هل الامتداد امتداد فيديو أصلاً؟
    if ext and ext not in VIDEO_EXTS:
        add("امتداد فيديو صحيح", False, "high",
            f"الامتداد .{ext} ليس امتداد فيديو معروف")
    else:
        add("امتداد فيديو صحيح", True, "high", f"امتداد .{ext} فيديو معروف")

    # 4) كود مدسوس
    lowered = data.lower()
    found_code = False
    for pattern, sev, desc in SUSPICIOUS_PATTERNS:
        if re.search(pattern, lowered):
            add(f"محتوى مشبوه: {desc}", False, sev, "عُثر على نمط خبيث داخل الملف")
            found_code = True
    if not found_code:
        add("كود مدسوس", True, "high", "لا يوجد كود مشبوه داخل الفيديو")

    # 5) ملفات تنفيذية مخفية
    found_embed = False
    for sig, sev, desc in EMBEDDED_FILES:
        idx = data.find(sig, 32)
        if idx != -1:
            add(f"ملف مخفي: {desc}", False, sev, f"توقيع ملف في الموضع {idx}")
            found_embed = True
    if not found_embed:
        add("ملفات مخفية", True, "high", "لا توجد ملفات تنفيذية مدسوسة")

    # 6) حجم غير طبيعي
    if size < 1000:
        add("حجم الملف", False, "medium",
            f"صغير جداً ({size} بايت) — الفيديوهات الحقيقية أكبر بكثير")
    elif size > 500 * 1024 * 1024:
        add("حجم الملف", False, "low", f"كبير جداً ({size // (1024*1024)} MB)")
    else:
        add("حجم الملف", True, "low", f"حجم طبيعي ({size // 1024} KB)")

    risk = min(100, score)
    if risk >= 60:
        verdict, level = "🔴 خطير — الفيديو ملغّم على الأرجح", "critical"
    elif risk >= 30:
        verdict, level = "🟠 مشبوه — لا تشغّله بلا فحص", "high"
    elif risk >= 12:
        verdict, level = "🟡 مشكوك فيه قليلاً", "medium"
    else:
        verdict, level = "🟢 يبدو آمناً", "low"

    return {
        "filename": filename,
        "size_kb": round(size / 1024, 1),
        "real_type": real_type or "غير معروف",
        "risk": risk,
        "verdict": verdict,
        "level": level,
        "checks": checks,
    }