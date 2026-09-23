"""إضافة أعمدة استعادة كلمة المرور — يُشغّل مرة واحدة."""
from pathlib import Path
from sqlalchemy import create_engine, text

db_url = None
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("DATABASE_URL="):
            db_url = line.split("=", 1)[1].strip().strip('"').strip("'")
            break

if not db_url:
    raise SystemExit("لم يتم العثور على DATABASE_URL في ملف .env")

engine = create_engine(db_url)

with engine.begin() as conn:
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token VARCHAR"))
    conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expiry TIMESTAMP"))

print("تم إضافة أعمدة استعادة كلمة المرور بنجاح ✅")