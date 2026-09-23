"""إضافة أعمدة تأكيد البريد لجدول المستخدمين — يُشغّل مرة واحدة."""
import os
from pathlib import Path
from sqlalchemy import create_engine, text

# اقرأ DATABASE_URL من ملف .env مباشرة
db_url = None
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("DATABASE_URL="):
            db_url = line.split("=", 1)[1].strip().strip('"').strip("'")
            break

if not db_url:
    db_url = os.environ.get("DATABASE_URL")

if not db_url:
    raise SystemExit("لم يتم العثور على DATABASE_URL في ملف .env")

engine = create_engine(db_url)

with engine.begin() as conn:
    conn.execute(text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE"
    ))
    conn.execute(text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token VARCHAR"
    ))
    # اعتبر جميع المستخدمين الحاليين مؤكَّدين حتى لا نمنعهم
    conn.execute(text(
        "UPDATE users SET is_verified = TRUE WHERE is_verified IS NULL OR is_verified = FALSE"
    ))

print("تم إضافة أعمدة تأكيد البريد بنجاح ✅")