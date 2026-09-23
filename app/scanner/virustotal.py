"""فحص الملفّات عبر VirusTotal API (70+ محرّك مضاد فيروسات)."""
import os
import httpx

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE = "https://www.virustotal.com/api/v3"


def check_file_hash(sha256: str) -> dict:
    """يبحث عن hash الملفّ في قاعدة بيانات VirusTotal."""
    if not VT_API_KEY:
        return {"enabled": False, "note": "مفتاح VirusTotal غير مضبوط"}

    try:
        headers = {"x-apikey": VT_API_KEY}
        r = httpx.get(f"{VT_BASE}/files/{sha256}", headers=headers, timeout=20)

        if r.status_code == 404:
            return {
                "enabled": True,
                "found": False,
                "note": "الملفّ لم يُفحص من قبل على VirusTotal.",
            }
        if r.status_code == 401:
            return {"enabled": False, "note": "مفتاح VirusTotal غير صحيح"}
        if r.status_code == 429:
            return {"enabled": True, "error": "تجاوزت حدّ الاستخدام (500 طلب/يوم)"}

        r.raise_for_status()
        data = r.json()["data"]["attributes"]
        stats = data.get("last_analysis_stats", {})
        results = data.get("last_analysis_results", {})

        flagged = []
        for engine, res in results.items():
            if res.get("category") in ("malicious", "suspicious"):
                flagged.append({
                    "engine": engine,
                    "category": res.get("category"),
                    "result": res.get("result", ""),
                })

        total = sum(stats.values())
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 5:
            verdict = "خطير جداً"
        elif malicious >= 2:
            verdict = "خطير"
        elif malicious == 1 or suspicious > 0:
            verdict = "مشبوه"
        else:
            verdict = "نظيف"

        return {
            "enabled": True,
            "found": True,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": total,
            "flagged_engines": flagged[:20],
            "names": (data.get("names") or [])[:10],
            "type_description": data.get("type_description", ""),
            "meaningful_name": data.get("meaningful_name", ""),
            "reputation": data.get("reputation", 0),
            "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
        }
    except Exception as e:
        return {"enabled": True, "error": f"فشل الاتّصال بـ VirusTotal: {e}"}