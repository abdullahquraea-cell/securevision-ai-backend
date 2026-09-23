import json
import os
import subprocess
import threading


# مسارات أداة Nuclei والقوالب
NUCLEI_PATH = os.getenv(
    "NUCLEI_PATH",
    r"D:\Projects\SecureVision-AI\tools\nuclei.exe",
)
NUCLEI_TEMPLATES = os.getenv(
    "NUCLEI_TEMPLATES",
    r"D:\Projects\SecureVision-AI\tools\nuclei-templates-main",
)


def _normalize_target(target):
    """Nuclei على هذا الجهاز لا يحلّل الاسم localhost — نستبدله بـ 127.0.0.1."""
    t = (target or "").strip()
    if not t:
        return t
    if "://" not in t:
        t = "http://" + t
    return t.replace("localhost", "127.0.0.1")


def is_available():
    """هل ملف nuclei.exe موجود فعلاً؟"""
    return os.path.isfile(NUCLEI_PATH)


def _read_stats(pipe, on_progress):
    """يقرأ إحصائيات Nuclei (من stderr) لتحديث نسبة التقدّم الحقيقية."""
    if not pipe:
        return
    for line in pipe:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue  # سطور عادية (بانر/INF) نتجاهلها
        try:
            total = float(data.get("total") or 0)
            reqs = float(data.get("requests") or 0)
        except (ValueError, TypeError):
            continue
        if total and on_progress:
            pct = int(reqs / total * 100)
            on_progress(min(100, pct))


def run_nuclei(target, on_log=None, on_finding=None, on_progress=None,
               severities="low,medium,high,critical"):
    """يشغّل Nuclei على الهدف ويُعيد قائمة الثغرات المكتشفة."""

    findings = []
    url = _normalize_target(target)

    if not is_available():
        if on_log:
            on_log("crit", f"[Nuclei] لم يتم العثور على الأداة في: {NUCLEI_PATH}")
        return findings

    cmd = [
        NUCLEI_PATH,
        "-t", NUCLEI_TEMPLATES,
        "-u", url,
        "-jsonl",                 # النتائج: سطر JSON لكل ثغرة (stdout)
        "-severity", severities,
        "-timeout", "8",
        "-retries", "1",
        "-rate-limit", "150",
        "-no-color",
        "-disable-update-check",
        "-stats",                 # تفعيل الإحصائيات
        "-stats-json",            # الإحصائيات بصيغة JSON (stderr)
        "-stats-interval", "3",   # تحديث كل 3 ثوانٍ
    ]

    if on_log:
        on_log("acc", f"[Nuclei] بدء الفحص الاحترافي على {url}")

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
    except Exception as e:
        if on_log:
            on_log("crit", f"[Nuclei] تعذّر التشغيل: {e}")
        return findings

    # خيط منفصل يقرأ الإحصائيات (نسبة التقدّم) من stderr
    stats_thread = threading.Thread(
        target=_read_stats, args=(process.stderr, on_progress), daemon=True
    )
    stats_thread.start()

    # القراءة الرئيسية: النتائج من stdout
    for line in process.stdout:
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info", {}) or {}
        sev = (info.get("severity") or "info").lower()
        name = info.get("name") or data.get("template-id") or "Nuclei finding"
        matched = data.get("matched-at") or data.get("host") or url
        desc = info.get("description") or ""
        template_id = data.get("template-id", "")

        refs = info.get("reference") or []
        ref_text = "\n".join(refs[:3]) if isinstance(refs, list) and refs else ""

        description = desc or name
        if template_id:
            description += f"\n\nقالب Nuclei: {template_id}"
        if ref_text:
            description += f"\n\nمراجع:\n{ref_text}"

        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "info"

        finding = {
            "title": f"[Nuclei] {name}",
            "severity": sev,
            "description": description,
            "location": matched,
            "recommendation": info.get("remediation")
            or "راجع مرجع القالب للتحقق من الثغرة ومعالجتها.",
        }
        findings.append(finding)

        if on_finding:
            on_finding(finding)

        if on_log:
            lvl = (
                "crit" if sev in ("critical", "high")
                else "warn" if sev == "medium"
                else "info"
            )
            on_log(lvl, f"[Nuclei][{sev}] {name} @ {matched}")

    process.wait()
    stats_thread.join(timeout=2)

    if on_log:
        on_log("ok", f"[Nuclei] اكتمل الفحص الاحترافي — {len(findings)} نتيجة")

    return findings