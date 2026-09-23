"""تحليل ملفّات Windows PE (EXE/DLL) — احترافي بمستوى PE-Studio."""
import datetime
import re

try:
    import pefile
    PEFILE_OK = True
except Exception:
    PEFILE_OK = False


SUSPICIOUS_APIS = {
    "VirtualAllocEx": "حجز ذاكرة في عملية أخرى",
    "WriteProcessMemory": "الكتابة في ذاكرة عملية أخرى (حقن كود)",
    "CreateRemoteThread": "إنشاء خيط في عملية أخرى (حقن)",
    "NtCreateThreadEx": "إنشاء خيط منخفض المستوى",
    "SetWindowsHookEx": "التقاط لوحة المفاتيح (Keylogger)",
    "GetAsyncKeyState": "قراءة ضغطات المفاتيح",
    "GetForegroundWindow": "معرفة النافذة النشطة",
    "InternetOpenUrl": "الاتّصال بالإنترنت",
    "URLDownloadToFile": "تنزيل ملفّ من الإنترنت",
    "WinExec": "تنفيذ أوامر خارجية",
    "ShellExecute": "تنفيذ أوامر خارجية",
    "CreateProcess": "إنشاء عمليّة جديدة",
    "RegOpenKey": "قراءة السجلّ",
    "RegSetValue": "الكتابة في السجلّ",
    "CryptEncrypt": "تشفير بيانات",
    "IsDebuggerPresent": "كشف بيئة التصحيح (تخفّي)",
    "CheckRemoteDebuggerPresent": "كشف بيئة التصحيح (تخفّي)",
    "GetTickCount": "قياس الوقت (تكتيك مضاد للتحليل)",
}

SECRET_PATTERNS = {
    "Google API Key": rb"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": rb"AKIA[0-9A-Z]{16}",
    "Stripe Key": rb"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "JWT Token": rb"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
}

URL_PATTERN = rb"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{5,80}"
IP_PATTERN = rb"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])"


def analyze_pe(file_path: str) -> dict:
    if not PEFILE_OK:
        return {"error": "مكتبة pefile غير مثبّتة على الخادم"}

    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories()
    except Exception as e:
        return {"error": f"فشل قراءة ملفّ PE: {e}"}

    # ---- الوقت والمعمارية ----
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        compile_time = datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        compile_time = "غير معروف"

    is_64 = pe.FILE_HEADER.Machine == 0x8664
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)

    # ---- معلومات النسخة ----
    version_info = _get_version_info(pe)

    # ---- الاستيرادات ----
    imports = _get_imports(pe)

    # ---- APIs مشبوهة ----
    suspicious = []
    for dll_name, funcs in imports.items():
        for f in funcs:
            for api, desc in SUSPICIOUS_APIS.items():
                if api.lower() in f.lower():
                    suspicious.append({"api": f, "dll": dll_name, "description": desc})

    # ---- المقاطع ----
    sections = []
    for s in pe.sections:
        try:
            entropy = s.get_entropy()
            sections.append({
                "name": s.Name.decode(errors="ignore").rstrip("\x00"),
                "size": int(s.SizeOfRawData),
                "entropy": round(entropy, 3),
                "suspicious": bool(entropy > 7.5),
            })
        except Exception:
            continue

    # ---- التوقيع الرقمي ----
    signed = _check_signature(pe)

    # ---- سلاسل نصّية: روابط + IPs + مفاتيح ----
    strings = _scan_strings(file_path)

    # ---- درجة المخاطرة ----
    risk = _risk_pe(suspicious, sections, signed, strings)

    try:
        pe.close()
    except Exception:
        pass

    return {
        "info": {
            "type": "DLL" if is_dll else "EXE",
            "architecture": "64-bit" if is_64 else "32-bit",
            "compile_time": compile_time,
            **version_info,
        },
        "signed": signed,
        "imports": {
            "total_dlls": len(imports),
            "dlls": list(imports.keys())[:30],
        },
        "suspicious_apis": suspicious[:30],
        "sections": sections,
        "strings": strings,
        "risk_score": risk,
    }


def _get_version_info(pe) -> dict:
    out = {
        "product_name": "",
        "company": "",
        "file_version": "",
        "file_description": "",
        "copyright": "",
        "original_filename": "",
    }
    mapping = {
        "ProductName": "product_name",
        "CompanyName": "company",
        "FileVersion": "file_version",
        "FileDescription": "file_description",
        "LegalCopyright": "copyright",
        "OriginalFilename": "original_filename",
    }
    try:
        for fileinfo in getattr(pe, "FileInfo", []) or []:
            for entry in fileinfo:
                if not hasattr(entry, "StringTable"):
                    continue
                for st in entry.StringTable:
                    for k, v in st.entries.items():
                        key = k.decode(errors="ignore")
                        val = v.decode(errors="ignore")
                        if key in mapping:
                            out[mapping[key]] = val
    except Exception:
        pass
    return out


def _get_imports(pe) -> dict:
    imports = {}
    try:
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode(errors="ignore"))
            imports[dll_name] = funcs
    except Exception:
        pass
    return imports


def _check_signature(pe) -> dict:
    try:
        idx = pefile.DIRECTORY_ENTRY.get('IMAGE_DIRECTORY_ENTRY_SECURITY', 4)
        entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        if entry.VirtualAddress and entry.Size:
            return {"signed": True, "size_bytes": int(entry.Size)}
    except Exception:
        pass
    return {"signed": False}


def _scan_strings(file_path: str, max_bytes: int = 2 * 1024 * 1024) -> dict:
    urls, ips, secrets = [], [], []
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)

        for m in re.findall(URL_PATTERN, data)[:200]:
            u = m.decode(errors="ignore")
            if u not in urls:
                urls.append(u)
            if len(urls) >= 20:
                break

        for m in re.findall(IP_PATTERN, data)[:200]:
            ip = m.decode(errors="ignore") if isinstance(m, bytes) else m
            if ip.startswith(("0.", "127.", "255.", "1.0", "0.0")):
                continue
            if ip not in ips:
                ips.append(ip)
            if len(ips) >= 20:
                break

        for kind, pat in SECRET_PATTERNS.items():
            for m in re.findall(pat, data)[:10]:
                val = m.decode(errors="ignore") if isinstance(m, bytes) else m
                secrets.append({"type": kind, "value": val[:60]})
    except Exception:
        pass
    return {"urls": urls, "ips": ips, "secrets": secrets}


def _risk_pe(suspicious, sections, signed, strings) -> dict:
    score = 0
    reasons = []

    n = len(suspicious)
    if n >= 5:
        score += 30
        reasons.append(f"عدد كبير من واجهات API المشبوهة ({n})")
    elif n > 0:
        score += 15
        reasons.append(f"يوجد {n} واجهات API مشبوهة")

    packed = [s for s in sections if s.get("suspicious")]
    if packed:
        score += 20
        reasons.append(f"مقاطع مضغوطة/مشفَّرة ({len(packed)})")

    if not signed.get("signed"):
        score += 15
        reasons.append("الملفّ غير موقّع رقميّاً")

    if strings.get("secrets"):
        score += 20
        reasons.append(f"مفاتيح حسّاسة مسرّبة داخل الملفّ ({len(strings['secrets'])})")

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