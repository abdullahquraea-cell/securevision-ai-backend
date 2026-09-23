import socket
from concurrent.futures import ThreadPoolExecutor


COMMON_SUBS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "dns",
    "ftp", "sftp", "admin", "administrator", "api", "api-dev", "dev",
    "staging", "stage", "test", "testing", "qa", "uat", "demo", "beta",
    "portal", "dashboard", "panel", "cpanel", "whm", "webdisk", "vpn",
    "remote", "secure", "login", "auth", "sso", "shop", "store", "blog",
    "app", "apps", "m", "mobile", "cdn", "static", "assets", "media",
    "img", "images", "files", "download", "docs", "support", "help",
    "status", "git", "gitlab", "jenkins", "ci", "db", "database", "mysql",
    "phpmyadmin", "pma", "backup", "old", "new", "internal", "intranet",
    "cloud", "mx", "email", "ns", "gateway", "proxy", "monitor",
]


def _clean_domain(target: str) -> str:
    t = (target or "").strip().lower()
    t = t.replace("https://", "").replace("http://", "")
    t = t.split("/")[0].split(":")[0]
    if t.startswith("www."):
        t = t[4:]
    return t


def _resolve(host):
    try:
        return host, socket.gethostbyname(host)
    except Exception:
        return host, None


def enum_subdomains(domain: str) -> dict:
    domain = _clean_domain(domain)
    result = {"domain": domain, "found": [], "error": ""}

    if not domain or "." not in domain:
        result["error"] = "أدخل نطاقاً صحيحاً (مثل example.com)"
        return result

    hosts = [f"{sub}.{domain}" for sub in COMMON_SUBS]

    with ThreadPoolExecutor(max_workers=25) as ex:
        for host, ip in ex.map(_resolve, hosts):
            if ip:
                result["found"].append({"subdomain": host, "ip": ip})

    result["found"].sort(key=lambda x: x["subdomain"])
    return result