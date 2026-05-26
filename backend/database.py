from pymongo import MongoClient
from datetime import datetime
import hashlib
from config import MONGO_URI

client = MongoClient(MONGO_URI)
db = client["smart_attendance_saas"]

# ── Global Collections ─────────────────────────────────
organizations_col = db["organizations"]   # one doc per company/tenant
users_col         = db["users"]           # all users (admin + employee), has org_id
employees_col     = db["employees"]       # face encodings, has org_id
attendance_col    = db["attendance"]      # legacy collection (keep for backwards compatibility)

# Split collections: office vs field engineer
office_attendance_col = db["office_attendance"]  # office attendance records, has org_id
field_attendance_col  = db["field_attendance"]   # field engineer visits, has org_id


# ── Indexes ────────────────────────────────────────────
# Create indexes safely (idempotent) to avoid startup crashes.
# If an index with the same key already exists but with a different name,
# MongoDB will throw IndexOptionsConflict/IndexKeySpecsConflict.
# We ignore those failures because the goal is to ensure indexes exist.

def ensure_index(collection, keys, *, unique=False, name=None):
    try:
        collection.create_index(keys, unique=unique, name=name)
    except Exception:
        # Index already exists (possibly with different auto-generated name)
        # or conflicting options. Since we only need the index for performance
        # and uniqueness constraints, ignore duplicate-name conflicts.
        pass


ensure_index(organizations_col, "slug", unique=True, name="organizations_slug_unique")
ensure_index(users_col, [("mobile", 1), ("org_id", 1)], unique=True, name="users_mobile_1_org_id_1_unique")
ensure_index(users_col, [("emp_id", 1), ("org_id", 1)], unique=False, name="users_emp_id_1_org_id_1")
ensure_index(employees_col, [("emp_id", 1), ("org_id", 1)], unique=True, name="employees_emp_id_1_org_id_1_unique")
ensure_index(attendance_col, [("emp_id", 1), ("org_id", 1), ("date", 1)], unique=True, name="attendance_emp_id_1_org_id_1_date_1_unique")

ensure_index(office_attendance_col, [("emp_id", 1), ("org_id", 1), ("date", 1)], unique=True, name="office_attendance_emp_id_1_org_id_1_date_1_unique")
ensure_index(field_attendance_col,  [("emp_id", 1), ("org_id", 1), ("date", 1)], unique=False, name="field_attendance_emp_id_1_org_id_1_date_1_idx")






def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def get_org(org_id: str):
    """Fetch org document by _id string."""
    from bson import ObjectId
    try:
        return organizations_col.find_one({"_id": ObjectId(org_id)})
    except Exception:
        return None


def seed_super_admin():
    """Create a default super-admin account if none exists."""
    if not users_col.find_one({"role": "super_admin"}):
        users_col.insert_one({
            "name":     "Super Admin",
            "mobile":   "0000000000",
            "password": hash_password("superadmin123"),
            "role":     "super_admin",
            "org_id":   None,
            "created":  datetime.now().strftime("%Y-%m-%d %H:%M")
        })
        print("✅ Super admin created — mobile: 0000000000 | password: superadmin123")


seed_super_admin()
