import time
from collections import defaultdict

from fastapi import Request, HTTPException

# مخزن بسيط في الذاكرة: { مفتاح: [أوقات الطلبات] }
_hits = defaultdict(list)


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "unknown"


def rate_limit(request: Request, name: str, limit: int, window: int = 60):
    """يسمح بـ (limit) طلبات خلال (window) ثانية لكل IP.
    إذا تجاوز الحد يرفع خطأ 429."""
    ip = _client_ip(request)
    key = f"{name}:{ip}"
    now = time.time()

    # احتفظ فقط بالطلبات داخل النافذة الزمنية
    recent = [t for t in _hits[key] if now - t < window]

    if len(recent) >= limit:
        raise HTTPException(
            status_code=429,
            detail="طلبات كثيرة جداً — انتظر قليلاً ثم أعد المحاولة",
        )

    recent.append(now)
    _hits[key] = recent