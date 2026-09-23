import socket
import time

import httpx

from app.database import SessionLocal
from app.models.scan import Scan
from app.models.finding import Finding
from app.scanner.engine import (
    COMMON_PORTS,
    RISKY_PORTS,
    SECURITY_HEADERS,
    _clean_host,
)
from app.scanner.deep import run_deep_checks
from app.scanner.nuclei_scan import run_nuclei, is_available as nuclei_available
from app.scanner.nmap_scan import run_nmap, is_available as nmap_available
from app.scanner.recon import fingerprint
from app.scanner.filediscovery import discover_files
from app.scanner.advanced_checks import run_advanced_checks


SCANS: dict = {}


def _log(scan_id: int, text: str, level: str = "info") -> None:
    SCANS[scan_id]["logs"].append({"text": text, "level": level})


def _add_finding(scan_id: int, findings: list, item: dict) -> None:
    findings.append(item)
    sev = item["severity"]
    if sev in SCANS[scan_id]["severity"]:
        SCANS[scan_id]["severity"][sev] += 1
    SCANS[scan_id]["findings_count"] = len(findings)


def _run_live_scan_impl(
    scan_id: int,
    project_id: int,
    target: str,
    scan_type: str,
    owner_id: int,
) -> None:
    """يشغّل الفحص: منافذ + بصمة + ملفات + ترويسات + عميق + Nuclei."""

    SCANS[scan_id] = {
        "status": "running",
        "progress": 0,
        "logs": [],
        "findings_count": 0,
        "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "ports_scanned": 0,
    }

    findings = []
    host = _clean_host(target)

    def log(text, level="info"):
        _log(scan_id, text, level)

    seen_keys = set()

    def _engine_of(title):
        if title.startswith("[Nmap]"):
            return "Nmap"
        if title.startswith("[Nuclei]"):
            return "Nuclei"
        return "SecureVision"

    def _dedup_key(item):
        title = item.get("title", "").lower()
        for tag in ("[nmap]", "[nuclei]"):
            title = title.replace(tag, "")
        loc = (item.get("location") or "").lower()
        loc = loc.replace("https://", "").replace("http://", "").rstrip("/")
        return (title.strip(), loc)

    def add(item):
        item["engine"] = _engine_of(item.get("title", ""))
        key = _dedup_key(item)
        if key in seen_keys:
            return
        seen_keys.add(key)
        _add_finding(scan_id, findings, item)

    def prog(value):
        v = min(99, int(value))
        if v > SCANS[scan_id]["progress"]:
            SCANS[scan_id]["progress"] = v

    log("[*] تهيئة محرك الفحص...", "acc")
    time.sleep(0.4)
    log(f"[*] الهدف: {host}", "acc")

    port_ceiling = 55 if scan_type == "full" else 95

    # ===== فحص المنافذ =====
    if scan_type in ("full", "ports"):
        if nmap_available():
            log("[*] فحص المنافذ الاحترافي بـ Nmap (خدمات + إصدارات)...", "acc")
            try:
                run_nmap(
                    target,
                    on_log=lambda lvl, txt: log(txt, lvl),
                    on_finding=lambda item: add(item),
                )
                SCANS[scan_id]["ports_scanned"] = 200
            except Exception as e:
                log(f"[!] خطأ في فحص Nmap: {str(e)}", "warn")
            prog(port_ceiling)
        else:
            log("[!] Nmap غير مثبّت — استخدام فحص المنافذ البسيط", "warn")
            try:
                ip = socket.gethostbyname(host)
                log(f"[+] تم ترجمة العنوان -> {ip}", "ok")
            except socket.gaierror:
                log(f"[!] تعذّر الوصول للمضيف: {host}", "warn")
                ip = None

            if ip:
                ports = list(COMMON_PORTS.items())
                total = len(ports)
                for i, (port, service) in enumerate(ports):
                    log(f"[*] فحص المنفذ {port} ({service})...", "mut")

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.7)
                    result = sock.connect_ex((ip, port))
                    sock.close()

                    SCANS[scan_id]["ports_scanned"] = i + 1

                    if result == 0:
                        if port in RISKY_PORTS:
                            severity, rec = RISKY_PORTS[port]
                            level = "crit" if severity == "critical" else "warn"
                            log(f"[!] منفذ خطير مفتوح: {port} ({service}) [{severity.upper()}]", level)
                        else:
                            severity, rec = ("info", "منفذ مفتوح - تأكد أن الخدمة مقصودة ومحدّثة.")
                            log(f"[+] منفذ مفتوح: {port} ({service})", "ok")

                        add({
                            "title": f"منفذ مفتوح: {port} ({service})",
                            "severity": severity,
                            "description": f"الخدمة {service} تعمل على المنفذ {port}.",
                            "location": f"{host}:{port}",
                            "recommendation": rec,
                        })

                    prog((i + 1) / total * port_ceiling)

    # ===== بصمة الموقع (التقنيات) =====
    if scan_type == "full":
        log("[*] استخراج بصمة الموقع...", "acc")
        try:
            fp = fingerprint(target)
            techs = ", ".join(t["name"] for t in fp.get("technologies", []))
            if techs:
                log(f"[+] التقنيات المكتشفة: {techs}", "ok")
                add({
                    "title": "بصمة الموقع (التقنيات المكتشفة)",
                    "severity": "info",
                    "description": f"التقنيات: {techs}. الخادم: {fp.get('server') or 'غير معلن'}.",
                    "location": fp.get("url", target),
                    "recommendation": "أخفِ التقنيات والإصدارات قدر الإمكان لتقليل سطح الهجوم.",
                })
        except Exception as e:
            log(f"[!] تعذّر استخراج البصمة: {str(e)}", "warn")

    # ===== كشف الملفات الحساسة المكشوفة =====
    if scan_type == "full":
        log("[*] البحث عن الملفات الحساسة المكشوفة...", "acc")
        try:
            fd = discover_files(target)
            for item in fd.get("found", []):
                s = item["severity"]
                lvl = "crit" if s in ("critical", "high") else "warn"
                log(f"[!] ملف مكشوف: {item['path']} [{s}]", lvl)
                add({
                    "title": f"ملف حساس مكشوف: {item['path']}",
                    "severity": s,
                    "description": f"{item['description']} (حالة الاستجابة {item['status']}).",
                    "location": fd.get("base", "") + item["path"],
                    "recommendation": "احذف الملف أو امنع الوصول إليه فوراً — قد يسرّب أسراراً أو كوداً.",
                })
        except Exception as e:
            log(f"[!] تعذّر فحص الملفات: {str(e)}", "warn")

    # ===== فحوصات متقدمة (CORS / كوكيز / طرق HTTP / LFI) =====
    if scan_type == "full":
        try:
            run_advanced_checks(target, log, add)
        except Exception as e:
            log(f"[!] خطأ في الفحوصات المتقدمة: {str(e)}", "warn")

    # ===== فحص ترويسات الأمان =====
    if scan_type in ("full", "headers"):
        log("[*] فحص ترويسات الأمان (HTTP headers)...", "acc")
        prog(63 if scan_type == "full" else 90)

        url = target.strip()
        if "://" not in url:
            url = "https://" + url

        try:
            resp = httpx.get(url, timeout=8.0, follow_redirects=True, verify=False)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, (severity, rec) in SECURITY_HEADERS.items():
                if header.lower() not in headers:
                    log(f"[!] ترويسة أمان مفقودة: {header}", "warn")
                    add({
                        "title": f"ترويسة أمان مفقودة: {header}",
                        "severity": severity,
                        "description": f"الموقع لا يرسل ترويسة {header}.",
                        "location": url,
                        "recommendation": rec,
                    })

            if "server" in headers:
                log(f"[!] الخادم يفصح عن نوعه: {headers['server']}", "warn")
                add({
                    "title": "الخادم يفصح عن نوعه",
                    "severity": "low",
                    "description": f"ترويسة Server تكشف: {headers['server']}",
                    "location": url,
                    "recommendation": "أخفِ أو عمّم ترويسة Server.",
                })
        except Exception as e:
            log(f"[!] تعذّر الاتصال بالموقع: {str(e)}", "warn")

    # ===== الفحص العميق =====
    if scan_type in ("full", "deep"):
        log("[*] بدء الفحص العميق...", "acc")
        if scan_type == "deep":
            prog(10)
        try:
            run_deep_checks(target, log, add, prog)
        except Exception as e:
            log(f"[!] خطأ في الفحص العميق: {str(e)}", "warn")

    # ===== الفحص الاحترافي بـ Nuclei =====
    if scan_type in ("full", "nuclei"):
        if nuclei_available():
            log("[*] بدء الفحص الاحترافي بـ Nuclei (6774+ قالب)...", "acc")
            log("[*] قد يستغرق 1-3 دقائق حسب الهدف — النتائج تظهر فور اكتشافها...", "mut")
            if scan_type == "nuclei":
                prog(20)
            try:
                run_nuclei(
                    target,
                    on_log=lambda lvl, txt: log(txt, lvl),
                    on_finding=lambda item: add(item),
                    on_progress=lambda pct: prog(20 + int(pct * 0.75)),
                )
            except Exception as e:
                log(f"[!] خطأ في فحص Nuclei: {str(e)}", "warn")
            prog(98)
        else:
            log("[!] Nuclei غير مثبّت — تم تخطّي الفحص الاحترافي", "warn")

    # ===== حفظ النتائج =====
    log("[*] حفظ النتائج...", "acc")
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            for r in findings:
                db.add(Finding(
                    scan_id=scan_id,
                    project_id=project_id,
                    title=r["title"],
                    severity=r["severity"],
                    description=r["description"],
                    location=r["location"],
                    recommendation=r["recommendation"],
                ))
            scan.findings_count = len(findings)
            scan.status = "completed"
            db.commit()
    finally:
        db.close()

    SCANS[scan_id]["findings_count"] = len(findings)
    SCANS[scan_id]["progress"] = 100
    SCANS[scan_id]["status"] = "completed"
    log(f"[+] اكتمل الفحص - تم العثور على {len(findings)} نتيجة", "ok")


def run_live_scan(
    scan_id: int,
    project_id: int,
    target: str,
    scan_type: str,
    owner_id: int,
) -> None:
    """غلاف واقٍ: إن انهار الفحص لأي سبب، يُعلَّم كـ failed بدل أن يبقى عالقاً."""
    try:
        _run_live_scan_impl(scan_id, project_id, target, scan_type, owner_id)
    except Exception as e:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.status == "running":
                scan.status = "failed"
                db.commit()
        finally:
            db.close()
        if scan_id in SCANS:
            SCANS[scan_id]["status"] = "failed"
            SCANS[scan_id]["logs"].append(
                {"text": f"[!] فشل الفحص: {e}", "level": "warn"}
            )