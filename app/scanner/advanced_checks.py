import re

import httpx


UA = {"User-Agent": "Mozilla/5.0 (SecureVision AdvancedChecks)"}

LFI_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../../../windows/win.ini",
]
LFI_SIGNS = ["root:x:0:0", "root:.*:0:0", "\\[extensions\\]", "for 16-bit app support"]
LFI_PARAMS = ["file", "page", "path", "doc", "document", "download", "read", "template", "view", "load"]


def _norm(target: str) -> str:
    t = (target or "").strip().rstrip("/")
    if "://" not in t:
        t = "http://" + t
    return t


def check_cors(base, log, add):
    """كشف إعداد CORS خاطئ (يعكس أي Origin)."""
    try:
        evil = "https://evil-securevision-test.com"
        r = httpx.get(base, headers={**UA, "Origin": evil}, timeout=8,
                      verify=False, follow_redirects=True)
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == "*":
            log("[!] إعداد CORS مفتوح للجميع (*)", "warn")
            add({
                "title": "إعداد CORS متساهل (*)",
                "severity": "medium",
                "description": "الموقع يرسل Access-Control-Allow-Origin: * — قد يسمح بقراءة البيانات من نطاقات أخرى.",
                "location": base,
                "recommendation": "حدّد نطاقات موثوقة بدل * خاصة مع البيانات الحساسة.",
            })
        elif evil in acao:
            sev = "high" if acac.lower() == "true" else "medium"
            log("[!] إعداد CORS يعكس أي Origin", "crit" if sev == "high" else "warn")
            add({
                "title": "إعداد CORS خطير (يعكس أي Origin)",
                "severity": sev,
                "description": f"الموقع يعكس Origin المهاجم. مع Allow-Credentials={acac or 'false'} — قد يسمح بسرقة بيانات المستخدمين.",
                "location": base,
                "recommendation": "لا تعكس Origin ديناميكياً؛ استخدم قائمة نطاقات موثوقة ثابتة.",
            })
    except Exception:
        pass


def check_cookie_flags(base, log, add):
    """كشف الكوكيز بدون خصائص الأمان."""
    try:
        r = httpx.get(base, headers=UA, timeout=8, verify=False, follow_redirects=True)
        try:
            raw = r.headers.get_list("set-cookie")
        except Exception:
            sc = r.headers.get("set-cookie", "")
            raw = [sc] if sc else []
        for cookie in raw:
            if not cookie:
                continue
            name = cookie.split("=")[0].strip()
            low = cookie.lower()
            missing = []
            if "httponly" not in low: missing.append("HttpOnly")
            if "secure" not in low: missing.append("Secure")
            if "samesite" not in low: missing.append("SameSite")
            if missing:
                log(f"[!] كوكي '{name}' بدون: {', '.join(missing)}", "warn")
                add({
                    "title": f"كوكي غير آمن: {name}",
                    "severity": "low",
                    "description": f"الكوكي '{name}' ينقصه: {', '.join(missing)} — قد يُعرّضه لسرقة الجلسة (XSS) أو CSRF.",
                    "location": base,
                    "recommendation": "أضف HttpOnly و Secure و SameSite لكل كوكيز الجلسة.",
                })
    except Exception:
        pass


def check_http_methods(base, log, add):
    """كشف طرق HTTP الخطيرة عبر OPTIONS."""
    try:
        r = httpx.request("OPTIONS", base, headers=UA, timeout=8,
                          verify=False, follow_redirects=True)
        allow = r.headers.get("allow", "")
        dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
        if dangerous:
            log(f"[!] طرق HTTP خطيرة مفعّلة: {', '.join(dangerous)}", "warn")
            add({
                "title": f"طرق HTTP خطيرة مفعّلة: {', '.join(dangerous)}",
                "severity": "medium",
                "description": f"الخادم يسمح بـ {', '.join(dangerous)} (ترويسة Allow: {allow}).",
                "location": base,
                "recommendation": "عطّل الطرق غير المستخدمة (خاصة PUT/DELETE/TRACE).",
            })
    except Exception:
        pass


def check_lfi(base, log, add):
    """اختبار اجتياز المسارات (LFI) على معاملات شائعة."""
    for param in LFI_PARAMS:
        for payload in LFI_PAYLOADS:
            url = f"{base}/?{param}={payload}"
            try:
                r = httpx.get(url, headers=UA, timeout=8, verify=False, follow_redirects=True)
            except Exception:
                continue
            body = r.text or ""
            for sign in LFI_SIGNS:
                if re.search(sign, body, re.I):
                    log(f"[CRIT] اجتياز مسارات (LFI) عبر المعامل '{param}'", "crit")
                    add({
                        "title": f"اجتياز مسارات (LFI) — المعامل '{param}'",
                        "severity": "critical",
                        "description": f"يمكن قراءة ملفات النظام عبر المعامل '{param}' بالحمولة: {payload}",
                        "location": url,
                        "recommendation": "امنع إدخال المسارات، استخدم قوائم بيضاء للملفات، وطهّر '../'.",
                    })
                    return


DIR_PATHS = ["/ftp", "/uploads", "/files", "/backup", "/backups", "/images",
             "/assets", "/static", "/logs", "/data", "/tmp", "/db"]
LISTING_SIGNS = ["index of /", "directory listing for", "[to parent directory]",
                 "parent directory", "listing directory"]


def check_directory_listing(base, log, add):
    """كشف المجلدات التي تعرض قائمة ملفاتها."""
    for path in DIR_PATHS:
        try:
            r = httpx.get(base + path, headers=UA, timeout=8, verify=False, follow_redirects=True)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        low = (r.text or "").lower()
        if any(sign in low for sign in LISTING_SIGNS):
            log(f"[!] سرد مجلد مكشوف: {path}", "warn")
            add({
                "title": f"سرد محتويات مجلد مكشوف: {path}",
                "severity": "medium",
                "description": f"المجلد {path} يعرض قائمة ملفاته للعامة — قد يكشف ملفات حساسة.",
                "location": base + path,
                "recommendation": "عطّل سرد المجلدات (Directory Listing) في إعداد الخادم.",
            })


REDIRECT_PARAMS = ["url", "redirect", "next", "to", "return", "returnUrl",
                   "redirect_uri", "dest", "destination", "continue"]
REDIRECT_TEST = "https://evil-securevision-test.com"


def check_open_redirect(base, log, add):
    """كشف إعادة التوجيه المفتوح."""
    for param in REDIRECT_PARAMS:
        url = f"{base}/?{param}={REDIRECT_TEST}"
        try:
            r = httpx.get(url, headers=UA, timeout=8, verify=False, follow_redirects=False)
        except Exception:
            continue
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and REDIRECT_TEST in loc:
            log(f"[!] إعادة توجيه مفتوح عبر المعامل '{param}'", "warn")
            add({
                "title": f"إعادة توجيه مفتوح (Open Redirect) — '{param}'",
                "severity": "medium",
                "description": f"المعامل '{param}' يعيد التوجيه لأي رابط خارجي (تصيّد). الوجهة: {loc}",
                "location": url,
                "recommendation": "اقبل وجهات إعادة التوجيه ضمن قائمة نطاقات موثوقة فقط.",
            })
            return


CMD_PARAMS = ["cmd", "exec", "command", "ping", "host", "ip", "query", "search", "name"]
CMD_MARKER = "SV_CMDI_9137"
CMD_PAYLOADS = [f"; echo {CMD_MARKER}", f"| echo {CMD_MARKER}", f"& echo {CMD_MARKER}",
                f"`echo {CMD_MARKER}`", f"$(echo {CMD_MARKER})"]


def check_command_injection(base, log, add):
    """كشف حقن الأوامر عبر معاملات شائعة."""
    for param in CMD_PARAMS:
        for payload in CMD_PAYLOADS:
            url = f"{base}/?{param}={payload}"
            try:
                r = httpx.get(url, headers=UA, timeout=8, verify=False, follow_redirects=True)
            except Exception:
                continue
            body = r.text or ""
            # علامة التنفيذ موجودة، لكن الأمر الحرفي (echo ...) غير منعكس = تنفيذ فعلي
            if CMD_MARKER in body and ("echo " + CMD_MARKER) not in body:
                log(f"[CRIT] حقن أوامر عبر المعامل '{param}'", "crit")
                add({
                    "title": f"حقن أوامر النظام (Command Injection) — '{param}'",
                    "severity": "critical",
                    "description": f"المعامل '{param}' ينفّذ أوامر النظام. الحمولة: {payload}",
                    "location": url,
                    "recommendation": "لا تمرّر مدخلات المستخدم لأوامر النظام؛ استخدم واجهات آمنة وقوائم بيضاء.",
                })
                return


def run_advanced_checks(target, log, add):
    base = _norm(target)
    log("[*] فحوصات متقدمة (CORS / كوكيز / HTTP / LFI / سرد / تحويل / أوامر)...", "acc")
    check_cors(base, log, add)
    check_cookie_flags(base, log, add)
    check_http_methods(base, log, add)
    check_lfi(base, log, add)
    check_directory_listing(base, log, add)
    check_open_redirect(base, log, add)
    check_command_injection(base, log, add)
    log("[+] اكتملت الفحوصات المتقدمة", "ok")