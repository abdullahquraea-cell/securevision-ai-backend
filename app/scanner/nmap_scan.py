import os
import shutil
import subprocess
import xml.etree.ElementTree as ET

from app.scanner.engine import RISKY_PORTS


# المسار الاحتياطي الكامل لـ Nmap (إن لم يكن في PATH)
NMAP_FALLBACK = r"C:\Program Files (x86)\Nmap\nmap.exe"


def _resolve_bin():
    """يجد مسار nmap: الاسم المختصر أولاً، ثم المسار الكامل."""
    if shutil.which("nmap"):
        return "nmap"
    if os.path.isfile(NMAP_FALLBACK):
        return NMAP_FALLBACK
    return None


def is_available():
    """هل nmap متاح؟"""
    return _resolve_bin() is not None


def _clean_host(target):
    """يستخرج اسم المضيف فقط (بدون http أو مسار أو منفذ)."""
    t = (target or "").strip()
    t = t.replace("http://", "").replace("https://", "")
    t = t.split("/")[0]     # أزل المسار
    t = t.split(":")[0]     # أزل المنفذ
    return t.strip()


def run_nmap(target, on_log=None, on_finding=None, top_ports=200):
    """يشغّل Nmap (كشف الخدمات والإصدارات) ويُعيد قائمة الثغرات/المنافذ."""

    findings = []
    binary = _resolve_bin()
    host = _clean_host(target)

    if not binary:
        if on_log:
            on_log("crit", "[Nmap] الأداة غير مثبّتة")
        return findings

    if on_log:
        on_log("acc", f"[Nmap] بدء فحص المنافذ والإصدارات على {host}...")

    cmd = [
        binary,
        "-sV",                          # كشف الخدمة والإصدار
        "-Pn",                          # تخطّي فحص "هل المضيف حي"
        "--top-ports", str(top_ports),  # أشهر N منفذ
        "-T4",                          # سرعة معقولة
        "-oX", "-",                     # مخرجات XML إلى stdout
        host,
    ]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        if on_log:
            on_log("warn", "[Nmap] انتهت مهلة الفحص")
        return findings
    except Exception as e:
        if on_log:
            on_log("crit", f"[Nmap] تعذّر التشغيل: {e}")
        return findings

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError:
        if on_log:
            on_log("warn", "[Nmap] تعذّر قراءة نتائج الفحص")
        return findings

    open_count = 0
    for host_el in root.findall("host"):
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            open_count += 1
            portid = int(port_el.get("portid"))
            proto = port_el.get("protocol", "tcp")

            svc_el = port_el.find("service")
            service = product = version = ""
            if svc_el is not None:
                service = svc_el.get("name", "") or ""
                product = svc_el.get("product", "") or ""
                version = svc_el.get("version", "") or ""

            ver_str = " ".join(x for x in (product, version) if x).strip()
            svc_label = service or "unknown"

            # الخطورة حسب المنفذ (نستخدم نفس قائمة المنافذ الخطيرة)
            if portid in RISKY_PORTS:
                severity, rec = RISKY_PORTS[portid]
            else:
                severity = "info"
                rec = "تأكد أن هذه الخدمة مقصودة، محدّثة، ومحمية بجدار ناري."

            desc = f"المنفذ {portid}/{proto} مفتوح — الخدمة: {svc_label}"
            if ver_str:
                desc += f" | الإصدار المكتشف: {ver_str}"

            finding = {
                "title": f"[Nmap] منفذ مفتوح: {portid}/{proto} ({svc_label})",
                "severity": severity,
                "description": desc,
                "location": f"{host}:{portid}",
                "recommendation": rec,
            }
            findings.append(finding)

            if on_finding:
                on_finding(finding)

            if on_log:
                lvl = (
                    "crit" if severity in ("critical", "high")
                    else "warn" if severity in ("medium", "low")
                    else "ok"
                )
                extra = f" [{ver_str}]" if ver_str else ""
                on_log(lvl, f"[Nmap] {portid}/{proto} {svc_label}{extra}")

    if on_log:
        on_log("ok", f"[Nmap] اكتمل فحص المنافذ — {open_count} منفذ مفتوح")

    return findings