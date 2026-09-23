import re

# (العنوان، الخطورة، النمط، الوصف، التوصية)
RULES = [
    ("مفتاح AWS مكشوف", "critical", r"AKIA[0-9A-Z]{16}",
     "مفتاح وصول AWS مكتوب مباشرة في الكود.", "انقله لمتغيّر بيئة وألغِ المفتاح المكشوف فوراً."),
    ("مفتاح خاص مكشوف (Private Key)", "critical", r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
     "مفتاح تشفير خاص مكتوب في الكود.", "لا تضع المفاتيح الخاصة في الكود؛ استخدم خزنة أسرار."),
    ("مفتاح Google API مكشوف", "high", r"AIza[0-9A-Za-z_\-]{35}",
     "مفتاح Google API مكتوب في الكود.", "انقله لمتغيّر بيئة وقيّد صلاحياته."),
    ("رمز Slack مكشوف", "high", r"xox[baprs]-[0-9A-Za-z\-]{10,}",
     "رمز Slack مكتوب في الكود.", "ألغِ الرمز وانقله لمتغيّر بيئة."),
    ("سر مكتوب في الكود", "high",
     r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\s*[:=]\s*[\"'][^\"']{5,}[\"']",
     "بيانات حساسة (كلمة مرور/مفتاح) مكتوبة مباشرة في الكود.",
     "انقل كل الأسرار لمتغيّرات بيئة (.env) ولا تضعها في الكود."),
    ("استخدام eval الخطير", "high", r"\beval\s*\(",
     "دالة eval تنفّذ نصاً كبرمجة — قد تؤدي لتنفيذ كود خبيث.", "تجنّب eval؛ استخدم بدائل آمنة."),
    ("استخدام exec الخطير", "high", r"\bexec\s*\(",
     "تنفيذ ديناميكي للكود — خطر تنفيذ أوامر.", "تجنّب exec مع مدخلات المستخدم."),
    ("تنفيذ أوامر نظام (os.system)", "high", r"os\.system\s*\(",
     "تنفيذ أوامر نظام مباشرة.", "استخدم subprocess مع قائمة وسائط بدون shell=True."),
    ("subprocess بـ shell=True", "high", r"subprocess\.[a-zA-Z_]+\([^)]*shell\s*=\s*True",
     "تشغيل أوامر عبر الصدفة — عرضة لحقن الأوامر.", "استخدم قائمة وسائط بدل shell=True."),
    ("دوال تنفيذ أوامر (PHP)", "high", r"(?<![\w.])(system|shell_exec|passthru|popen|proc_open)\s*\(",
     "دوال تنفيذ أوامر نظام في PHP.", "تجنّبها أو طهّر المدخلات بصرامة."),
    ("تحميل pickle غير آمن", "medium", r"pickle\.loads?\s*\(",
     "إلغاء تسلسل pickle قد ينفّذ كوداً عند بيانات خبيثة.", "لا تستخدم pickle مع بيانات غير موثوقة."),
    ("yaml.load غير آمن", "medium", r"yaml\.load\s*\((?![^)]*Safe)",
     "yaml.load بدون SafeLoader قد ينفّذ كوداً.", "استخدم yaml.safe_load."),
    ("حقن SQL محتمل (دمج نصوص)", "high", r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*[\"'].*\+",
     "بناء استعلام SQL بدمج نصوص — عرضة لحقن SQL.", "استخدم استعلامات معاملة (parameterized)."),
    ("حقن SQL محتمل (f-string)", "high", r"(?i)(execute|query)\s*\(\s*f[\"']",
     "استعلام SQL يستخدم f-string — عرضة لحقن SQL.", "استخدم معاملات الاستعلام بدل التنسيق."),
    ("XSS محتمل (innerHTML)", "medium", r"\.innerHTML\s*=",
     "الكتابة في innerHTML بمدخلات المستخدم تسبب XSS.", "استخدم textContent أو طهّر المدخلات."),
    ("XSS محتمل (document.write)", "medium", r"document\.write\s*\(",
     "document.write بمدخلات المستخدم يسبب XSS.", "تجنّبها واستخدم DOM آمن."),
    ("XSS محتمل (dangerouslySetInnerHTML)", "medium", r"dangerouslySetInnerHTML",
     "إدراج HTML خام في React قد يسبب XSS.", "طهّر المحتوى قبل الإدراج."),
    ("مدخلات مستخدم غير مطهّرة (PHP)", "medium", r"\$_(GET|POST|REQUEST|COOKIE)\[",
     "استخدام مدخلات المستخدم مباشرة قد يؤدي لثغرات حقن.", "طهّر وتحقّق من كل المدخلات."),
    ("تجزئة ضعيفة (MD5)", "medium", r"\bmd5\s*\(",
     "MD5 ضعيفة ولا تصلح لكلمات المرور.", "استخدم bcrypt/argon2 لكلمات المرور."),
    ("تجزئة ضعيفة (SHA1)", "low", r"\bsha1\s*\(",
     "SHA1 قديمة وضعيفة.", "استخدم SHA-256 أو أقوى."),
    ("تعطيل التحقق من SSL", "high", r"verify\s*=\s*False",
     "تعطيل التحقق من SSL يعرّضك لهجمات الوسيط.", "فعّل التحقق من الشهادات دائماً."),
    ("تعطيل فحص الشهادة (Node)", "high", r"rejectUnauthorized\s*:\s*false",
     "تعطيل فحص الشهادة في Node.js.", "لا تعطّل rejectUnauthorized في الإنتاج."),
    ("وضع التصحيح مفعّل (DEBUG=True)", "medium", r"(?i)debug\s*=\s*true",
     "وضع التصحيح يكشف معلومات حساسة في الإنتاج.", "عطّل DEBUG في الإنتاج."),
    ("CORS مفتوح للجميع في الكود", "medium", r"Access-Control-Allow-Origin[\"'\s:,]+\*",
     "السماح لأي نطاق بالوصول (CORS *).", "حدّد نطاقات موثوقة."),
]

_COMPILED = [(n, s, re.compile(p), d, r) for (n, s, p, d, r) in RULES]


def scan_code(code: str, filename: str = "") -> dict:
    findings = []
    lines = code.split("\n")

    for idx, line in enumerate(lines, 1):
        for name, sev, rx, desc, rec in _COMPILED:
            if rx.search(line):
                findings.append({
                    "title": name,
                    "severity": sev,
                    "line": idx,
                    "code": line.strip()[:200],
                    "description": desc,
                    "recommendation": rec,
                })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: (order.get(x["severity"], 9), x["line"]))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1

    return {
        "filename": filename,
        "lines": len(lines),
        "total": len(findings),
        "counts": counts,
        "findings": findings,
    }