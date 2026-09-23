import os
import re
import shutil
import subprocess
import sys


def _resolve_sqlmap() -> list:
    """يحدّد طريقة تشغيل SQLMap تلقائياً على أي نظام (لينكس/ويندوز)."""
    # 1) أولوية لمتغيّر البيئة SQLMAP_PATH إن كان مضبوطاً ويشير لملف موجود
    env_path = os.getenv("SQLMAP_PATH")
    if env_path and os.path.isfile(env_path):
        if env_path.endswith(".py"):
            return [sys.executable, env_path]
        return [env_path]

    # 2) البحث عن أمر sqlmap المثبَّت في النظام (الخادم: /usr/bin/sqlmap)
    found = shutil.which("sqlmap")
    if found:
        return [found]

    # 3) البحث عن سكربت sqlmap.py في PATH (بعض التثبيتات)
    found_py = shutil.which("sqlmap.py")
    if found_py:
        return [sys.executable, found_py]

    return []


def is_available() -> bool:
    """هل SQLMap متاح على هذا النظام؟"""
    return bool(_resolve_sqlmap())


def run_sqlmap(url: str, get_dbs: bool = True, timeout: int = 180) -> dict:
    """يشغّل SQLMap على رابط ويُعيد نتيجة منظّمة."""

    result = {
        "injectable": False,
        "parameter": "",
        "type": "",
        "title": "",
        "payload": "",
        "dbms": "",
        "databases": [],
        "raw_tail": "",
    }

    base = _resolve_sqlmap()
    if not base:
        result["raw_tail"] = "SQLMap غير مثبّت على الخادم."
        return result

    cmd = base + [
        "-u", url,
        "--batch",               # تلقائي بلا أسئلة
        "--level=2",
        "--risk=1",
        "--technique=BEU",       # أنواع سريعة فقط (Boolean/Error/Union) — نتجنّب time-based البطيء
        "--flush-session",       # نتائج نظيفة كل مرة
        "--disable-coloring",
    ]
    if get_dbs:
        cmd.append("--dbs")

    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
        )
        out = proc.stdout or ""
    except subprocess.TimeoutExpired:
        result["raw_tail"] = "انتهت مهلة SQLMap (الهدف بطيء أو غير مستجيب)."
        return result
    except Exception as e:
        result["raw_tail"] = f"تعذّر تشغيل SQLMap: {e}"
        return result

    # هل الهدف قابل للحقن؟
    if "identified the following injection point" in out or "is vulnerable" in out:
        result["injectable"] = True

    # استخراج التفاصيل من المخرجات
    def grab(pattern):
        m = re.search(pattern, out)
        return m.group(1).strip() if m else ""

    result["parameter"] = grab(r"Parameter:\s*(.+)")
    result["type"] = grab(r"Type:\s*(.+)")
    result["title"] = grab(r"Title:\s*(.+)")
    result["payload"] = grab(r"Payload:\s*(.+)")
    result["dbms"] = grab(r"back-end DBMS:\s*(.+)")

    # قواعد البيانات المكتشفة
    dbs_block = re.search(
        r"available databases \[\d+\]:(.+?)(?:\n\n|\[\*\] ending)", out, re.S
    )
    if dbs_block:
        for line in dbs_block.group(1).splitlines():
            line = line.strip()
            if line.startswith("[*]"):
                result["databases"].append(line[3:].strip())

    # آخر جزء من المخرجات الخام (للعرض عند عدم وجود حقن)
    result["raw_tail"] = "\n".join(out.strip().splitlines()[-15:])

    return result