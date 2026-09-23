"""تحليل تطبيقات أندرويد (APK) — احترافي بمستوى MobSF."""
import re

try:
    from androguard.core.apk import APK
    ANDROGUARD_OK = True
except Exception:
    try:
        from androguard.core.bytecodes.apk import APK  # androguard الأقدم
        ANDROGUARD_OK = True
    except Exception:
        ANDROGUARD_OK = False


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "قراءة الرسائل النصّية",
    "android.permission.SEND_SMS": "إرسال الرسائل النصّية",
    "android.permission.RECEIVE_SMS": "استقبال الرسائل النصّية",
    "android.permission.READ_CONTACTS": "قراءة جهات الاتّصال",
    "android.permission.WRITE_CONTACTS": "تعديل جهات الاتّصال",
    "android.permission.READ_CALL_LOG": "قراءة سجلّ المكالمات",
    "android.permission.WRITE_CALL_LOG": "تعديل سجلّ المكالمات",
    "android.permission.CALL_PHONE": "إجراء مكالمات هاتفية",
    "android.permission.RECORD_AUDIO": "تسجيل الصوت من الميكروفون",
    "android.permission.CAMERA": "استخدام الكاميرا",
    "android.permission.ACCESS_FINE_LOCATION": "الموقع الدقيق (GPS)",
    "android.permission.ACCESS_COARSE_LOCATION": "الموقع التقريبي",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "الموقع في الخلفية",
    "android.permission.READ_EXTERNAL_STORAGE": "قراءة التخزين الخارجي",
    "android.permission.WRITE_EXTERNAL_STORAGE": "الكتابة على التخزين الخارجي",
    "android.permission.SYSTEM_ALERT_WINDOW": "الرسم فوق التطبيقات الأخرى",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "خدمة إمكانيّة الوصول (خطر جداً)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "تثبيت تطبيقات أخرى",
    "android.permission.PACKAGE_USAGE_STATS": "مراقبة استخدام التطبيقات",
    "android.permission.READ_PHONE_STATE": "قراءة حالة الهاتف/IMEI",
    "android.permission.PROCESS_OUTGOING_CALLS": "اعتراض المكالمات الصادرة",
    "android.permission.BODY_SENSORS": "استخدام حسّاسات الجسم",
    "android.permission.READ_CALENDAR": "قراءة التقويم",
    "android.permission.WRITE_CALENDAR": "تعديل التقويم",
}

SECRET_PATTERNS = {
    "Google API Key": rb"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": rb"AKIA[0-9A-Z]{16}",
    "Firebase URL": rb"https?://[a-zA-Z0-9\-]+\.firebaseio\.com",
    "Slack Token": rb"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
    "GitHub Token": rb"gh[pousr]_[A-Za-z0-9]{36,}",
    "JWT Token": rb"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
    "Stripe Key": rb"sk_(live|test)_[0-9a-zA-Z]{24,}",
}


def analyze_apk(file_path: str) -> dict:
    if not ANDROGUARD_OK:
        return {"error": "مكتبة androguard غير مثبّتة على الخادم"}

    try:
        apk = APK(file_path)
    except Exception as e:
        return {"error": f"فشل قراءة ملفّ APK: {e}"}

    # ---- معلومات التطبيق ----
    info = {
        "app_name": apk.get_app_name() or "غير معروف",
        "package": apk.get_package() or "",
        "version_name": apk.get_androidversion_name() or "",
        "version_code": apk.get_androidversion_code() or "",
        "min_sdk": apk.get_min_sdk_version() or "",
        "target_sdk": apk.get_target_sdk_version() or "",
    }

    # ---- الرايات الأمنية من Manifest ----
    flags = {
        "debuggable": _safe_bool(apk, "debuggable", False),
        "allow_backup": _safe_bool(apk, "allowBackup", True),
    }

    # ---- الصلاحيات ----
    all_perms = apk.get_permissions() or []
    dangerous, normal = [], []
    for p in all_perms:
        if p in DANGEROUS_PERMISSIONS:
            dangerous.append({"name": p, "description": DANGEROUS_PERMISSIONS[p]})
        else:
            normal.append(p)

    # ---- المكوّنات ----
    components = {
        "activities": len(apk.get_activities() or []),
        "services": len(apk.get_services() or []),
        "receivers": len(apk.get_receivers() or []),
        "providers": len(apk.get_providers() or []),
    }

    # ---- الشهادات ----
    certs = []
    try:
        for cert in (apk.get_certificates() or []):
            try:
                certs.append({
                    "issuer": _cert_field(cert, "issuer"),
                    "subject": _cert_field(cert, "subject"),
                    "serial": str(getattr(cert, "serial_number", "")),
                    "sha256": cert.sha256.hex() if hasattr(cert, "sha256") else "",
                })
            except Exception:
                continue
    except Exception:
        pass

    # ---- كشف المفاتيح المسرّبة ----
    secrets = _find_secrets(apk)

    # ---- درجة المخاطرة ----
    risk = _risk_score(dangerous, flags, secrets, certs)

    return {
        "info": info,
        "flags": flags,
        "permissions": {
            "total": len(all_perms),
            "dangerous": dangerous,
            "normal_count": len(normal),
        },
        "components": components,
        "certificates": certs,
        "secrets": secrets,
        "risk_score": risk,
    }


def _safe_bool(apk, attr: str, default: bool) -> bool:
    try:
        val = apk.get_element("application", attr)
        return str(val).lower() == "true" if val is not None else default
    except Exception:
        return default


def _cert_field(cert, name: str) -> str:
    try:
        field = getattr(cert, name)
        if hasattr(field, "human_friendly"):
            return str(field.human_friendly)
        return str(field)
    except Exception:
        return "غير معروف"


def _find_secrets(apk, max_files: int = 400) -> list:
    found = []
    scan_ext = (".xml", ".json", ".txt", ".properties", ".js", ".html", ".yaml", ".yml")
    try:
        files = list(apk.get_files())[:max_files]
        for name in files:
            if not name.endswith(scan_ext):
                continue
            try:
                data = apk.get_file(name)
                if not data or len(data) > 3 * 1024 * 1024:
                    continue
                for kind, pat in SECRET_PATTERNS.items():
                    for m in re.findall(pat, data):
                        val = m.decode(errors="ignore") if isinstance(m, bytes) else m
                        shown = val if len(val) <= 60 else val[:40] + "..." + val[-10:]
                        found.append({"type": kind, "value": shown, "file": name})
                        if len(found) >= 40:
                            return found
            except Exception:
                continue
    except Exception:
        pass
    return found


def _risk_score(dangerous, flags, secrets, certs) -> dict:
    score = 0
    reasons = []

    n = len(dangerous)
    if n >= 10:
        score += 30
        reasons.append(f"عدد كبير من الصلاحيات الخطرة ({n})")
    elif n >= 5:
        score += 20
        reasons.append(f"صلاحيات خطرة متعدّدة ({n})")
    elif n > 0:
        score += 10
        reasons.append(f"يوجد {n} صلاحية خطرة")

    if flags.get("debuggable"):
        score += 25
        reasons.append("⚠️ التطبيق يعمل بوضع Debug (خطر أمني كبير)")
    if flags.get("allow_backup"):
        score += 10
        reasons.append("النسخ الاحتياطي مفعّل (قد يسرّب بيانات)")

    if secrets:
        score += 25
        reasons.append(f"مفاتيح/رموز حسّاسة مسرّبة داخل التطبيق ({len(secrets)})")

    if not certs:
        score += 15
        reasons.append("التطبيق بلا توقيع رقمي")

    score = min(score, 100)
    if score >= 70:
        level = "خطير جداً"
    elif score >= 40:
        level = "خطير"
    elif score >= 20:
        level = "متوسّط"
    else:
        level = "منخفض"

    return {"score": score, "level": level, "reasons": reasons}