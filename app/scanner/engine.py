import socket
import ssl
from urllib.parse import urlparse

import httpx


# المنافذ الشائعة وأسماء خدماتها
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    27017: "MongoDB",
}

# منافذ تُعتبر خطيرة إذا كانت مفتوحة للعالم
RISKY_PORTS = {
    23: ("critical", "Telnet يرسل البيانات بدون تشفير — يجب تعطيله واستخدام SSH."),
    3306: ("high", "قاعدة بيانات MySQL مكشوفة — يجب تقييد الوصول بجدار حماية."),
    5432: ("high", "قاعدة بيانات PostgreSQL مكشوفة — يجب تقييد الوصول بجدار حماية."),
    6379: ("critical", "Redis مكشوف وغالباً بدون كلمة مرور — خطر كبير."),
    27017: ("critical", "MongoDB مكشوف — يجب تفعيل المصادقة وتقييد الوصول."),
    3389: ("high", "RDP مكشوف — هدف شائع لهجمات القوة الغاشمة."),
    21: ("medium", "FTP قديم وغير آمن — يُفضّل SFTP."),
}

# ترويسات الأمان المطلوبة في المواقع
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "medium",
        "أضف ترويسة HSTS لإجبار المتصفح على استخدام HTTPS.",
    ),
    "Content-Security-Policy": (
        "medium",
        "أضف CSP للحماية من هجمات XSS وحقن المحتوى.",
    ),
    "X-Frame-Options": (
        "low",
        "أضف X-Frame-Options للحماية من هجمات Clickjacking.",
    ),
    "X-Content-Type-Options": (
        "low",
        "أضف X-Content-Type-Options: nosniff لمنع تخمين نوع المحتوى.",
    ),
}


def _clean_host(target: str) -> str:
    """استخراج اسم المضيف من رابط أو عنوان."""
    target = target.strip()

    if "://" in target:
        return urlparse(target).hostname or ""

    # إزالة أي مسار بعد اسم المضيف
    return target.split("/")[0]


def scan_ports(target: str) -> list[dict]:
    """فحص المنافذ الشائعة المفتوحة."""
    findings = []
    host = _clean_host(target)

    if not host:
        return findings

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        findings.append({
            "title": "تعذّر الوصول إلى الهدف",
            "severity": "info",
            "description": f"لا يمكن ترجمة اسم المضيف: {host}",
            "location": host,
            "recommendation": "تأكد من صحة العنوان واتصال الشبكة.",
        })
        return findings

    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)

        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:  # المنفذ مفتوح
            if port in RISKY_PORTS:
                severity, recommendation = RISKY_PORTS[port]
            else:
                severity, recommendation = (
                    "info",
                    "منفذ مفتوح — تأكد أن الخدمة مقصودة ومحدّثة.",
                )

            findings.append({
                "title": f"منفذ مفتوح: {port} ({service})",
                "severity": severity,
                "description": f"الخدمة {service} تعمل على المنفذ {port}.",
                "location": f"{host}:{port}",
                "recommendation": recommendation,
            })

    return findings


def scan_headers(target: str) -> list[dict]:
    """فحص ترويسات الأمان في موقع ويب."""
    findings = []

    url = target.strip()
    if "://" not in url:
        url = "https://" + url

    try:
        response = httpx.get(
            url,
            timeout=8.0,
            follow_redirects=True,
            verify=False,
        )
    except Exception as e:
        findings.append({
            "title": "تعذّر الاتصال بالموقع",
            "severity": "info",
            "description": str(e),
            "location": url,
            "recommendation": "تأكد من أن الموقع يعمل ويقبل الاتصال.",
        })
        return findings

    headers = {k.lower(): v for k, v in response.headers.items()}

    for header, (severity, recommendation) in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append({
                "title": f"ترويسة أمان مفقودة: {header}",
                "severity": severity,
                "description": f"الموقع لا يرسل ترويسة {header}.",
                "location": url,
                "recommendation": recommendation,
            })

    # كشف ترويسة تفصح عن الخادم
    if "server" in headers:
        findings.append({
            "title": "الخادم يفصح عن نوعه",
            "severity": "low",
            "description": f"ترويسة Server تكشف: {headers['server']}",
            "location": url,
            "recommendation": "أخفِ أو عمّم ترويسة Server لتقليل المعلومات المكشوفة.",
        })

    return findings


def run_scan(scan_type: str, target: str) -> list[dict]:
    """تشغيل الفحص حسب النوع."""
    if scan_type == "headers":
        return scan_headers(target)

    if scan_type == "ports":
        return scan_ports(target)

    # فحص كامل: منافذ + ترويسات
    if scan_type == "full":
        return scan_ports(target) + scan_headers(target)

    return []