import time
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import Base, engine

from app.models.activity import Activity
from app.models.user import User
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding

from app.routers import (
    auth, projects, scans, findings, ai, reports,
    users, activity, settings as settings_router, stats,
    urlcheck, contact,
    sqlmaptest,recon,filediscovery,subdomains,codescan,subscription,organizations,appscan,admin,
)


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="SecureVision AI",
    version="1.0.0",
    description="AI Vulnerability Management Platform"
)


# ===== حد عام: 200 طلب/دقيقة لكل IP =====
_global_hits = defaultdict(list)


@app.middleware("http")
async def global_rate_limit(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    now = time.time()

    recent = [t for t in _global_hits[ip] if now - t < 60]

    if len(recent) >= 200:
        return JSONResponse(
            status_code=429,
            content={"detail": "طلبات كثيرة جداً — انتظر قليلاً ثم أعد المحاولة"},
        )

    recent.append(now)
    _global_hits[ip] = recent

    return await call_next(request)


# ===== CORS محصور بالنطاقات المسموحة =====
origins = [o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(ai.router)
app.include_router(reports.router)
app.include_router(users.router)
app.include_router(activity.router)
app.include_router(settings_router.router)
app.include_router(stats.router)
app.include_router(urlcheck.router)
app.include_router(contact.router)
app.include_router(sqlmaptest.router)
app.include_router(recon.router)
app.include_router(filediscovery.router)
app.include_router(subdomains.router)
app.include_router(codescan.router)
app.include_router(subscription.router)
app.include_router(organizations.router)
app.include_router(appscan.router)
app.include_router(admin.router)



@app.on_event("startup")
def _cleanup_stuck_scans():
    """عند تشغيل الخادم، أي فحص بقي 'running' من جلسة سابقة يُعلَّم كـ failed."""
    from app.database import SessionLocal
    from app.models.scan import Scan
    db = SessionLocal()
    try:
        stuck = db.query(Scan).filter(Scan.status == "running").all()
        for s in stuck:
            s.status = "failed"
        if stuck:
            db.commit()
            print(f"[STARTUP] تم تعليم {len(stuck)} فحصاً عالقاً كـ failed")
    finally:
        db.close()


@app.get("/")
def root():
    return {
        "message": "SecureVision AI Running",
        "version": "1.0.0"
    }