"""تحليل ذكيّ لنتائج الفحص باستخدام Claude AI."""
import json
import os

try:
    from anthropic import Anthropic
    HAS_ANTHROPIC = True
except Exception:
    HAS_ANTHROPIC = False


ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY", "")


def summarize_scan(result: dict) -> dict:
    if not HAS_ANTHROPIC or not ANTHROPIC_KEY:
        return {"enabled": False, "note": "مفتاح Anthropic غير مضبوط"}

    try:
        client = Anthropic(api_key=ANTHROPIC_KEY)
        scan_text = _build_input(result)

        prompt = f"""أنت خبير أمن سيبراني محترف. حلّل نتائج فحص التطبيق التالي واكتب تقييماً باللغة العربية.

نتائج الفحص:
{scan_text}

أرجع JSON فقط بهذه البنية بالضبط (بلا أيّ نصّ إضافي، بلا markdown، بلا ```):
{{
  "verdict": "نظيف|مشبوه|خطير|خطير جداً",
  "verdict_score": رقم من 0 إلى 100,
  "one_liner": "جملة واحدة قصيرة جداً (< 15 كلمة) للحكم النهائي",
  "summary": "فقرة من 3-4 جمل تلخّص الوضع للمستخدم غير المتخصّص",
  "risks": ["مخاطرة 1", "مخاطرة 2", "مخاطرة 3"],
  "recommendations": ["توصية 1", "توصية 2", "توصية 3"]
}}"""

        message = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )

        text = message.content[0].text.strip()
        # remove code fences if present
        if text.startswith("```"):
            text = text.strip("`")
            if text.lstrip().startswith("json"):
                text = text.lstrip()[4:]
        text = text.strip()

        try:
            data = json.loads(text)
            return {"enabled": True, **data}
        except Exception:
            return {"enabled": True, "raw": text[:2000]}

    except Exception as e:
        return {"enabled": False, "error": f"فشل تحليل AI: {e}"}


def _build_input(result: dict) -> str:
    parts = []
    ti = result.get("type_info", {}) or {}
    parts.append(f"نوع التطبيق: {ti.get('description', '?')} ({ti.get('platform', '')})")
    parts.append(f"الحجم: {result.get('size_readable', '')}")
    ent = result.get("entropy", {}) or {}
    parts.append(f"Entropy: {ent.get('value', '')} ({ent.get('note', '')})")

    deep = result.get("deep") or {}
    if deep and not deep.get("error"):
        risk = deep.get("risk_score", {}) or {}
        parts.append(f"\nدرجة المخاطرة الداخلية: {risk.get('score')}/100 ({risk.get('level')})")
        for r in risk.get("reasons", []) or []:
            parts.append(f"  - {r}")

        info = deep.get("info") or {}
        if info:
            parts.append(f"\nمعلومات التطبيق: {info}")

        perms = deep.get("permissions") or {}
        dangerous = perms.get("dangerous") or []
        if dangerous:
            parts.append(f"\nصلاحيات خطرة ({len(dangerous)}):")
            for p in dangerous[:15]:
                parts.append(f"  - {p.get('description', '')} [{p.get('name', '')}]")

        apis = deep.get("suspicious_apis") or []
        if apis:
            parts.append(f"\nAPIs مشبوهة ({len(apis)}):")
            for a in apis[:10]:
                parts.append(f"  - {a.get('api', '')}: {a.get('description', '')}")

        signed = deep.get("signed") or {}
        if signed:
            parts.append(f"\nموقّع رقمياً: {signed.get('signed')}")

        certs = deep.get("certificates") or []
        if certs:
            parts.append(f"مُصدر الشهادة: {certs[0].get('issuer', '')[:200]}")

        secrets = deep.get("secrets") or []
        strings = deep.get("strings") or {}
        secrets += strings.get("secrets", []) or []
        if secrets:
            parts.append(f"\nمفاتيح مسرّبة عُثر عليها: {len(secrets)}")

    vt = result.get("virustotal") or {}
    if vt.get("found"):
        parts.append(f"\n=== نتائج VirusTotal ===")
        parts.append(f"حكم VT: {vt.get('verdict')}")
        parts.append(f"محرّكات كشفت خطراً: {vt.get('malicious', 0)} من {vt.get('total_engines', 0)}")
        if vt.get("flagged_engines"):
            parts.append("محرّكات صنّفته خطراً:")
            for e in (vt["flagged_engines"] or [])[:8]:
                parts.append(f"  - {e.get('engine', '')}: {e.get('result', '')}")
    elif vt.get("enabled") and not vt.get("found"):
        parts.append(f"\nVirusTotal: الملفّ لم يُفحص من قبل (سمعة غير معروفة).")

    return "\n".join(parts)