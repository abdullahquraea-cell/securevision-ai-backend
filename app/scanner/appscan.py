"""
فاحص التطبيقات — المرحلة 1:
- كشف نوع التطبيق تلقائياً عبر magic bytes
- حساب البصمات (MD5/SHA1/SHA256)
- حساب الـ Entropy (كشف التعبئة/التشفير)
- معلومات الملفّ الأساسية
"""
import hashlib
import math
import os
from collections import Counter
from pathlib import Path


# ---------- كشف نوع الملفّ ----------
def detect_file_type(file_path: str) -> dict:
    """يكشف نوع التطبيق من magic bytes + الامتداد."""
    with open(file_path, "rb") as f:
        header = f.read(64)

    ext = Path(file_path).suffix.lower()
    result = {
        "type": "unknown",
        "platform": "غير معروف",
        "description": "ملفّ غير معروف",
        "icon": "❓",
        "supported": False,
    }

    # ZIP-based (APK, IPA, AAB, JAR)
    if header.startswith(b"PK\x03\x04"):
        if ext in (".apk", ".aab", ".xapk"):
            return {
                "type": "android_app",
                "platform": "Android",
                "description": "تطبيق أندرويد",
                "icon": "🤖",
                "supported": True,
            }
        if ext == ".ipa":
            return {
                "type": "ios_app",
                "platform": "iOS",
                "description": "تطبيق iOS (آيفون/آيباد)",
                "icon": "🍎",
                "supported": True,
            }
        if ext == ".jar":
            return {
                "type": "java_jar",
                "platform": "Java",
                "description": "أرشيف Java",
                "icon": "☕",
                "supported": True,
            }
        return {
            "type": "zip_archive",
            "platform": "أرشيف",
            "description": "ملفّ ZIP",
            "icon": "🗜️",
            "supported": False,
        }

    # PE (Windows EXE/DLL)
    if header.startswith(b"MZ"):
        return {
            "type": "windows_pe",
            "platform": "Windows",
            "description": "تطبيق ويندوز تنفيذي",
            "icon": "🪟",
            "supported": True,
        }

    # ELF (Linux)
    if header.startswith(b"\x7fELF"):
        return {
            "type": "linux_elf",
            "platform": "Linux",
            "description": "تطبيق لينكس تنفيذي (ELF)",
            "icon": "🐧",
            "supported": True,
        }

    # Mach-O (macOS)
    macho_magics = (
        b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    )
    if any(header.startswith(m) for m in macho_magics):
        return {
            "type": "macos_macho",
            "platform": "macOS",
            "description": "تطبيق macOS تنفيذي (Mach-O)",
            "icon": "🍏",
            "supported": True,
        }

    # MSI (Windows installer / Compound Document)
    if header.startswith(b"\xd0\xcf\x11\xe0"):
        return {
            "type": "windows_msi",
            "platform": "Windows",
            "description": "مثبِّت ويندوز MSI",
            "icon": "📦",
            "supported": True,
        }

    # DEB (Debian package)
    if header.startswith(b"!<arch>\n"):
        return {
            "type": "linux_deb",
            "platform": "Linux",
            "description": "حزمة Debian",
            "icon": "📦",
            "supported": True,
        }

    # DMG — يُكشف بالامتداد + توقيع في نهاية الملفّ (يكفينا الامتداد الآن)
    if ext == ".dmg":
        return {
            "type": "macos_dmg",
            "platform": "macOS",
            "description": "حاوية قرص macOS",
            "icon": "💽",
            "supported": True,
        }

    return result


# ---------- البصمات ----------
def compute_hashes(file_path: str) -> dict:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# ---------- Entropy ----------
def compute_entropy(file_path: str) -> float:
    """Shannon entropy (0-8). > 7.5 = مرجّح أن يكون مضغوطاً/مشفَّراً."""
    with open(file_path, "rb") as f:
        data = f.read(1024 * 1024)  # أوّل 1MB يكفي
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 3)


# ---------- الحجم ----------
def _human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ---------- التحليل الكامل (المرحلة 1) ----------
def analyze_file(file_path: str, original_name: str = "") -> dict:
    size = os.path.getsize(file_path)
    type_info = detect_file_type(file_path)
    entropy = compute_entropy(file_path)

    entropy_note = "عادي"
    if entropy >= 7.5:
        entropy_note = "مرتفع جداً (مرجّح أنّه مضغوط/مشفَّر)"
    elif entropy >= 7.0:
        entropy_note = "مرتفع"

    hashes = compute_hashes(file_path)

    # التحليل العميق حسب النوع
    deep = None
    t = type_info.get("type")
    try:
        if t == "android_app":
            from . import apk_analyzer
            deep = apk_analyzer.analyze_apk(file_path)
        elif t == "windows_pe":
            from . import pe_analyzer
            deep = pe_analyzer.analyze_pe(file_path)
    except Exception as e:
        deep = {"error": f"فشل التحليل العميق: {e}"}

    # VirusTotal
    vt_result = None
    try:
        from . import virustotal
        vt_result = virustotal.check_file_hash(hashes["sha256"])
    except Exception as e:
        vt_result = {"error": f"فشل VirusTotal: {e}"}

    result = {
        "file_name": original_name or os.path.basename(file_path),
        "size_bytes": size,
        "size_readable": _human_size(size),
        "type_info": type_info,
        "hashes": hashes,
        "entropy": {"value": entropy, "note": entropy_note},
        "deep": deep,
        "virustotal": vt_result,
        "phase": 5,
        "message": "التحليل الكامل + VirusTotal + AI اكتمل بنجاح.",
    }

    # AI Summary
    ai_result = None
    try:
        from . import ai_summary
        ai_result = ai_summary.summarize_scan(result)
    except Exception as e:
        ai_result = {"error": f"فشل AI: {e}"}

    result["ai_analysis"] = ai_result
    return result