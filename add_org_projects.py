"""إضافة organization_id للمشاريع + ربط المشاريع الحالية بمؤسسة مالكها."""
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
    conn.execute(text(
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS organization_id INTEGER"
    ))
    # اربط كل مشروع بمؤسسة مالكه
    conn.execute(text("""
        UPDATE projects p
        SET organization_id = u.organization_id
        FROM users u
        WHERE p.owner_id = u.id AND p.organization_id IS NULL
    """))

print("تم ربط المشاريع بالمؤسسات ✅")