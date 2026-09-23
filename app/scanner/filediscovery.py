import uuid

import httpx


UA = {"User-Agent": "Mozilla/5.0 (SecureVision FileDiscovery)"}

# مسارات حساسة عالية القيمة: (المسار، الوصف، الخطورة)
SENSITIVE_PATHS = [
    ("/.env", "ملف بيئة يحتوي أسراراً (كلمات مرور/مفاتيح API)", "critical"),
    ("/.env.local", "ملف بيئة محلي", "critical"),
    ("/.env.production", "ملف بيئة إنتاج", "critical"),
    ("/.git/config", "مستودع Git مكشوف — يمكن سحب الكود المصدري", "critical"),
    ("/.git/HEAD", "مستودع Git مكشوف", "critical"),
    ("/.svn/entries", "مستودع SVN مكشوف", "high"),
    ("/.htpasswd", "كلمات مرور Apache", "critical"),
    ("/.htaccess", "ملف إعداد Apache", "medium"),
    ("/config.php.bak", "نسخة احتياطية من ملف الإعداد", "critical"),
    ("/wp-config.php.bak", "نسخة احتياطية من إعداد ووردبريس", "critical"),
    ("/wp-config.php", "إعداد ووردبريس", "high"),
    ("/backup.zip", "أرشيف نسخة احتياطية", "high"),
    ("/backup.tar.gz", "أرشيف نسخة احتياطية", "high"),
    ("/backup.sql", "نسخة قاعدة بيانات", "critical"),
    ("/database.sql", "نسخة قاعدة بيانات", "critical"),
    ("/dump.sql", "نسخة قاعدة بيانات", "critical"),
    ("/phpinfo.php", "معلومات PHP حساسة", "high"),
    ("/info.php", "معلومات PHP حساسة", "high"),
    ("/server-status", "حالة خادم Apache مكشوفة", "medium"),
    ("/.DS_Store", "ملف ماك يكشف أسماء الملفات", "low"),
    ("/composer.json", "تبعيات PHP", "low"),
    ("/composer.lock", "تبعيات PHP بإصداراتها", "low"),
    ("/package.json", "تبعيات Node.js", "low"),
    ("/.npmrc", "إعداد npm قد يحوي رموزاً سرية", "high"),
    ("/docker-compose.yml", "إعداد Docker قد يحوي أسراراً", "medium"),
    ("/Dockerfile", "إعداد Docker", "low"),
    ("/.aws/credentials", "بيانات اعتماد AWS", "critical"),
    ("/.ssh/id_rsa", "مفتاح SSH خاص", "critical"),
    ("/id_rsa", "مفتاح SSH خاص", "critical"),
    ("/web.config", "إعداد IIS/.NET", "medium"),
    ("/settings.py", "إعدادات Django (قد تحوي SECRET_KEY)", "high"),
    ("/config.json", "ملف إعداد", "medium"),
    ("/phpmyadmin", "إدارة قاعدة بيانات مكشوفة", "high"),
    ("/admin", "لوحة تحكم", "medium"),
    ("/administrator", "لوحة تحكم", "medium"),
    ("/swagger.json", "توثيق API مكشوف", "medium"),
    ("/api-docs", "توثيق API مكشوف", "medium"),
    ("/error.log", "سجل أخطاء", "medium"),
    ("/debug.log", "سجل تصحيح", "medium"),
    ("/.gitlab-ci.yml", "إعداد CI", "low"),
    ("/robots.txt", "قد يكشف مسارات مخفية", "info"),
    ("/sitemap.xml", "خريطة الموقع", "info"),
    ("/.well-known/security.txt", "سياسة أمنية (معلوماتي)", "info"),
]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _norm(url: str) -> str:
    t = (url or "").strip().rstrip("/")
    if "://" not in t:
        t = "http://" + t
    return t


def discover_files(target: str) -> dict:
    base = _norm(target)
    result = {
        "base": base,
        "reachable": False,
        "baseline_200": False,
        "found": [],
        "error": "",
    }

    baseline_len = None
    rand_path = "/" + uuid.uuid4().hex + "_notexist"

    try:
        with httpx.Client(headers=UA, timeout=8, follow_redirects=False, verify=False) as client:
            # معايرة: هل الموقع يرجّع 200 لكل شيء؟
            r0 = client.get(base + rand_path)
            result["reachable"] = True
            if r0.status_code == 200:
                result["baseline_200"] = True
                baseline_len = len(r0.content)

            # فحص كل مسار حساس
            for path, desc, sev in SENSITIVE_PATHS:
                try:
                    r = client.get(base + path)
                except Exception:
                    continue

                code = r.status_code
                size = len(r.content)
                is_hit = False

                if code == 200:
                    if result["baseline_200"]:
                        # الموقع يرجّع 200 لكل شيء — نقبل فقط إن اختلف الحجم بوضوح
                        if baseline_len is None or abs(size - baseline_len) > 60:
                            is_hit = True
                    else:
                        is_hit = True
                elif code in (401, 403):
                    # موجود لكنه محمي — مفيد معرفته
                    is_hit = True

                if is_hit:
                    result["found"].append({
                        "path": path,
                        "description": desc,
                        "severity": sev,
                        "status": code,
                        "size": size,
                    })
    except Exception as e:
        result["error"] = f"تعذّر الوصول للهدف: {e}"
        return result

    result["found"].sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
    return result