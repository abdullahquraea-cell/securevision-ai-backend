"""إنشاء جدول المؤسسات + ربط المستخدمين + مؤسسة افتراضية لكل مستخدم حالي."""
from pathlib import Path
from datetime import datetime
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
    # جدول المؤسسات
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS organizations (
            id SERIAL PRIMARY KEY,
            name VARCHAR NOT NULL,
            owner_id INTEGER NOT NULL,
            plan VARCHAR DEFAULT 'free',
            created_at TIMESTAMP DEFAULT NOW()
        )
    """))

    # أعمدة المستخدم
    conn.execute(text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS organization_id INTEGER"
    ))
    conn.execute(text(
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS org_role VARCHAR DEFAULT 'owner'"
    ))

    # أنشئ مؤسسة افتراضية لكل مستخدم ليس له مؤسسة
    users = conn.execute(text(
        "SELECT id, username FROM users WHERE organization_id IS NULL"
    )).fetchall()

    for uid, uname in users:
        org_name = f"مؤسسة {uname}"
        org_id = conn.execute(
            text("INSERT INTO organizations (name, owner_id, plan, created_at) "
                 "VALUES (:n, :o, 'free', :c) RETURNING id"),
            {"n": org_name, "o": uid, "c": datetime.utcnow()},
        ).scalar()
        conn.execute(
            text("UPDATE users SET organization_id = :org, org_role = 'owner' WHERE id = :uid"),
            {"org": org_id, "uid": uid},
        )

    print(f"تم إنشاء الجداول وربط {len(users)} مستخدم بمؤسساتهم ✅")