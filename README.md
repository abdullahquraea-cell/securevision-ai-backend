# SecureVision AI — Backend

<div dir="rtl">

منصة **SecureVision AI** لإدارة الثغرات الأمنية مدعومة بالذكاء الاصطناعي. هذا المستودع يحتوي على الباك-إند المبني بـ **FastAPI + SQLAlchemy + Alembic**.

</div>

---

## 📦 Table of Contents
- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Installation (Local)](#installation-local)
- [Environment Variables](#environment-variables)
- [Database Migrations](#database-migrations)
- [Running](#running)
- [API Endpoints](#api-endpoints)
- [Deployment](#deployment)
  - [Vercel](#vercel)
  - [Docker](#docker)
  - [Render / Heroku](#render--heroku)
- [Security Notes](#security-notes)

---

## Overview

<div dir="rtl">

باك-إند **SecureVision AI** مسؤول عن:

- 🔐 **المصادقة**: تسجيل/دخول/استعادة كلمة المرور (يدعم أيضاً Firebase ID Token)
- 🏢 **المنظمات والمشاريع**: نموذج متعدد المنظمات (multi-tenant)
- 🛡️ **الفحص الأمني**: روابط، تطبيقات (APK/PE)، كود، صور، فيديو، رسائل
- 🤖 **تحليل الذكاء الاصطناعي**: تحليل الثغرات عبر Claude (Anthropic)
- 📄 **التقارير**: توليد PDF عربي عبر ReportLab
- 💳 **الاشتراكات**: تكامل مع Stripe
- 📜 **سجل النشاط**: متابعة كل عملية حساسة

</div>

---

## Tech Stack

- **Framework**: FastAPI 0.139
- **ORM**: SQLAlchemy 2.0
- **Migrations**: Alembic 1.18
- **Auth**: python-jose (JWT) + bcrypt + Firebase Admin SDK (optional)
- **Database**: PostgreSQL (production) / SQLite (dev)
- **AI**: Anthropic Claude SDK
- **Reports**: ReportLab + arabic-reshaper + python-bidi
- **Security scanners**: nmap, nuclei, sqlmap, androguard, pefile
- **Payments**: Stripe

---

## Project Structure

```
backend/
├── app/
│   ├── main.py              # نقطة الدخول + إعداد FastAPI + CORS
│   ├── config.py            # إعدادات من .env
│   ├── database.py          # تهيئة SQLAlchemy
│   ├── activity_log.py      # تسجيل الأنشطة
│   ├── ai/                  # محرك الذكاء الاصطناعي
│   ├── models/              # نماذج قاعدة البيانات (User, Project, Scan, ...)
│   ├── schemas/             # Pydantic schemas
│   ├── routers/             # مسارات API (auth, scans, users, ...)
│   ├── reports/             # توليد PDF
│   ├── scanner/             # محركات الفحص الأمني
│   └── security/            # JWT + password hashing + rate limiting
├── alembic/                 # ترحيلات قاعدة البيانات
├── alembic.ini
├── requirements.txt
├── Dockerfile
├── vercel.json              # تكوين النشر على Vercel
├── Procfile                # تكوين Render/Heroku
├── runtime.txt             # نسخة Python المطلوبة
├── .env.example            # قالب متغيرات البيئة (انسخه إلى .env)
└── .gitignore
```

---

## Installation (Local)

```bash
# 1) استنساخ المستودع
git clone https://github.com/abdullahquraea-cell/securevision-ai-backend.git
cd securevision-ai-backend

# 2) إنشاء بيئة افتراضية
python -m venv .venv
source .venv/bin/activate   # على Windows: .venv\Scripts\activate

# 3) تثبيت الاعتماديات
pip install -r requirements.txt

# 4) إعداد متغيرات البيئة
cp .env.example .env
# عدّل .env وضع قيمك الحقيقية

# 5) تطبيق ترحيلات قاعدة البيانات
alembic upgrade head

# 6) تشغيل الخادم
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

سيكون الخادم متاحاً على: <http://localhost:8000>
توثيق API: <http://localhost:8000/docs>

---

## Environment Variables

انسخ `.env.example` إلى `.env` واملأ القيم:

| المتغير | الوصف | مطلوب؟ |
|---------|------|--------|
| `DATABASE_URL` | رابط قاعدة البيانات (PostgreSQL أو SQLite) | ✅ |
| `JWT_SECRET_KEY` | مفتاح JWT (نص عشوائي طويل) | ✅ |
| `ANTHROPIC_API_KEY` | مفتاح Claude AI من <https://console.anthropic.com> | ✅ |
| `ALLOWED_ORIGINS` | نطاقات الفرونت-إند (مفصولة بفواصل) | ✅ |
| `FRONTEND_URL` | نطاق الفرونت-إند (لروابط البريد والدفع) | ✅ |
| `EMAIL_ENABLED` | تفعيل إرسال البريد (`true`/`false`) | اختياري |
| `BREVO_API_KEY` | مفتاح Brevo API للبريد | اختياري |
| `SMTP_HOST/PORT/USER/PASSWORD` | إعدادات SMTP للبريد | اختياري |
| `STRIPE_SECRET_KEY` | مفتاح Stripe السري | اختياري |
| `STRIPE_PUBLISHABLE_KEY` | مفتاح Stripe العام | اختياري |

> ⚠️ **أمان**: لا ترفع ملف `.env` إلى GitHub. تم استثناؤه في `.gitignore`.

---

## Database Migrations

استخدام Alembic لتطبيق/إنشاء ترحيلات:

```bash
# تطبيق كل الترحيلات
alembic upgrade head

# العودة لترحيل سابق
alembic downgrade -1

# إنشاء ترحيل جديد بعد تعديل النماذج
alembic revision --autogenerate -m "add new table"

# عرض الحالة الحالية
alembic current
```

---

## Running

### Development
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Production
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

أو عبر Gunicorn:
```bash
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
```

---

## API Endpoints

أهم نقاط النهاية:

| المسار | الوصف |
|--------|------|
| `GET /` | فحص حالة الخادم |
| `GET /docs` | توثيق Swagger التفاعلي |
| `POST /auth/register` | تسجيل مستخدم جديد |
| `POST /auth/login` | تسجيل الدخول (OAuth2 form) |
| `GET /auth/me` | معلومات المستخدم الحالي |
| `POST /auth/forgot-password` | طلب رابط استعادة كلمة المرور |
| `POST /auth/reset-password` | تعيين كلمة مرور جديدة |
| `GET /auth/verify/{token}` | تأكيد البريد الإلكتروني |
| `GET /projects` | قائمة المشاريع |
| `POST /scans/` | بدء فحص جديد |
| `GET /findings/` | قائمة الثغرات المكتشفة |
| `POST /ai/analyze` | تحليل ثغرة بالذكاء الاصطناعي |
| `GET /reports/{scan_id}` | توليد PDF تقرير |

للاطلاع على كل النقاط: <http://localhost:8000/docs>

---

## Deployment

### Vercel

مُعدّ مسبقاً عبر `vercel.json`. خطوات النشر:

1. ادخل <https://vercel.com/new>
2. استورد المستودع من GitHub
3. في **Environment Variables**، أضف كل المتغيرات من `.env.example`
4. اضغط **Deploy**

> ⚠️ ملاحظة: بعض أدوات الفحص (nmap, sqlmap, nuclei) لا تعمل على Vercel serverless بسبب قيود النظام. للفحص الكامل استخدم Docker أو VPS.

### Docker

```bash
# بناء الصورة
docker build -t securevision-ai-backend .

# تشغيل الحاوية
docker run -d \
  --name securevision-backend \
  -p 8000:8000 \
  --env-file .env \
  securevision-ai-backend
```

أو عبر Docker Compose (مع قاعدة بيانات PostgreSQL):

```yaml
# docker-compose.yml
version: '3.8'
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: securevision
      POSTGRES_USER: securevision
      POSTGRES_PASSWORD: securevision
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  backend:
    build: .
    ports:
      - "8000:8000"
    env_file: .env
    depends_on:
      - db
    environment:
      DATABASE_URL: postgresql+psycopg://securevision:securevision@db:5432/securevision

volumes:
  pgdata:
```

### Render / Heroku

مُعدّ مسبقاً عبر `Procfile` و `runtime.txt`:

1. ادخل <https://render.com> ← **New Web Service**
2. اختر المستودع
3. **Build Command**: `pip install -r requirements.txt && alembic upgrade head`
4. **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. أضف متغيرات البيئة في **Environment**

---

## Security Notes

<div dir="rtl">

- ✅ **CORS محدود**: ضع نطاقات الفرونت-إند فقط في `ALLOWED_ORIGINS`.
- ✅ **Rate Limiting**: 5 تسجيلات دخول/دقيقة و3 طلبات استعادة/دقيقة لكل IP.
- ✅ **JWT Authentication**: كل المسارات المحمية تتطلب توكن صالح.
- ✅ **Password Hashing**: bcrypt مع salt تلقائي.
- ✅ **SQL Injection Protection**: SQLAlchemy ORM مع استعلامات مُعلمة.
- ⚠️ **مفتاح JWT**: غيّره من القيمة الافتراضية إلى نص عشوائي طويل (64 حرف).
- ⚠️ **Service Account**: لو تستخدم Firebase Admin SDK، لا ترفع ملف الـ JSON إلى GitHub.

</div>

---

## License

MIT — استخدمه بحرية لمشاريعك.

---

## Author

**Abdullah Quraea** — <https://github.com/abdullahquraea-cell>
