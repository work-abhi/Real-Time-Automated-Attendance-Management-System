from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
from zoneinfo import ZoneInfo

from bson import ObjectId
import socket, os, csv, io, random, math, re

from config import SECRET_KEY, DEFAULT_OFFICE_LAT, DEFAULT_OFFICE_LNG, DEFAULT_OFFICE_RADIUS_M, DEFAULT_OFFICE_IP
from database import (
    db, organizations_col, employees_col,
    attendance_col, office_attendance_col, field_attendance_col,
    users_col,

    hash_password, get_org, seed_super_admin
)
from face_engine import encode_face_from_b64, recognize_face_from_b64
from wifi_attendance import get_client_real_ip
from field_engineer import handle_field_engineer_attendance



app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)
app.secret_key = SECRET_KEY
# ProxyFix: AWS ALB / Nginx ke peeche real client IP aane ke liye
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1, x_host=1, x_prefix=1)
CORS(app)

# In-memory OTP store: {(org_id, emp_id): {"otp": "123456", "expires": ts}}
otp_store = {}

# In-memory password reset store: {key: {code, expires, role, org_id}}
# key: (role, org_id_or_none, mobile)
password_reset_store = {}


# ══════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════


def get_local_ip():
    """
    AWS pe public IP return karo.
    Pehle AWS EC2 instance metadata (IMDSv2) try karo,
    phir fallback as external service, phir private IP.
    """
    import urllib.request

    # 1. AWS EC2 IMDSv2 — token le ke public IP fetch karo
    try:
        token_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            method="PUT"
        )
        token = urllib.request.urlopen(token_req, timeout=1).read().decode()
        pub_ip_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            headers={"X-aws-ec2-metadata-token": token}
        )
        pub_ip = urllib.request.urlopen(pub_ip_req, timeout=1).read().decode().strip()
        if pub_ip:
            return pub_ip
    except Exception:
        pass

    # 2. Fallback: public IP via external service
    for url in ["https://api.ipify.org", "https://checkip.amazonaws.com"]:
        try:
            pub_ip = urllib.request.urlopen(url, timeout=2).read().decode().strip()
            if pub_ip:
                return pub_ip
        except Exception:
            continue

    # 3. Fallback: private/local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def haversine_distance(lat1, lng1, lat2, lng2):
    R = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lng2 - lng1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


def is_in_office_for_org(lat, lng, org):
    """Check GPS using org-specific settings."""
    if lat is None or lng is None:
        return False, 0.0
    olat   = org.get("office_lat",      DEFAULT_OFFICE_LAT)
    olng   = org.get("office_lng",      DEFAULT_OFFICE_LNG)
    radius = org.get("office_radius_m", DEFAULT_OFFICE_RADIUS_M)
    dist   = haversine_distance(lat, lng, olat, olng)
    return dist <= radius, round(dist, 1)


def is_office_ip_for_org(ip, org):
    """
    Strict IP verification:
    - Sirf configured office IP(s) se exact match allow karo
    - Koi bhi aur IP reject
    - 127.0.0.1 (localhost) sirf tab allow karo jab office_ip configure na ho (pure dev mode)
    """
    office_ip_config = org.get("office_ip", "").strip()
    ip = str(ip).strip()

    if not ip:
        return False, "Client IP is not detecting"

    # Office IP configured nahi — sirf localhost allow (dev only)
    if not office_ip_config:
        if ip in ("127.0.0.1", "::1"):
            return True, f"Dev mode: Public IP allowed ({ip})"
        return False, "Office IP not  configured  — Enter actual IP in admin settings "

    # Office IP configured hai — sirf exact match allow karo, kuch nahi
    allowed_ips = [x.strip() for x in office_ip_config.split(",") if x.strip()]
    for allowed in allowed_ips:
        if ip == allowed:
            return True, f"Office WiFi verified ({ip})"

    return False, f"This network is not allowed ({ip}). connect Office WiFi ."


def client_ip():
    """Real client IP — AWS ALB/Nginx proxy headers sahi handle karo."""
    # X-Forwarded-For mein pehla IP actual client hota hai
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    # Nginx reverse proxy
    real = request.headers.get("X-Real-IP", "")
    if real:
        return real.strip()
    return request.remote_addr or ""


def require_login(role=None):
    """Validate session + (optionally) role.

    role can be a string role (e.g. "employee") or an iterable of roles
    (e.g. ("employee", "admin")).

    Returns (user_doc, None) on success or (None, error_response) on failure.
    For admin/employee roles also returns the org doc in user["_org"].
    """
    if "user_id" not in session:
        return None, (jsonify({"ok": False, "error": "Login required"}), 401)
    try:
        user = users_col.find_one({"_id": ObjectId(session["user_id"])}, {"password": 0})
    except Exception:
        return None, (jsonify({"ok": False, "error": "Session invalid"}), 401)
    if not user:
        return None, (jsonify({"ok": False, "error": "Session invalid"}), 401)

    if role:
        if isinstance(role, (list, tuple, set)):
            if user.get("role") not in role:
                return None, (jsonify({"ok": False, "error": "Access denied"}), 403)
        else:
            if user.get("role") != role:
                return None, (jsonify({"ok": False, "error": "Access denied"}), 403)

    # Attach org for non-super-admin users
    if user.get("role") not in ("super_admin",) and user.get("org_id"):
        org = get_org(user["org_id"])
        user["_org"] = org or {}
    return user, None



def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def now_ist():
    """Return current datetime in Asia/Kolkata (IST)."""
    return datetime.now(tz=ZoneInfo("Asia/Kolkata"))



# ══════════════════════════════════════════════════
#  PAGE ROUTES
# ══════════════════════════════════════════════════

@app.route("/")
def index():
    if "user_id" in session:
        try:
            user = users_col.find_one({"_id": ObjectId(session["user_id"])}, {"password": 0})
            if user:
                role = user.get("role")
                if role == "super_admin":
                    return redirect(url_for("super_admin_dashboard"))
                elif role == "admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("employee_dashboard"))
        except Exception:
            session.clear()
    return render_template("login.html")


@app.route("/super-admin")
def super_admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))
    try:
        user = users_col.find_one({"_id": ObjectId(session["user_id"])}, {"password": 0})
    except Exception:
        session.clear()
        return redirect(url_for("index"))
    if not user or user.get("role") != "super_admin":
        return redirect(url_for("index"))
    return render_template("super_admin.html")


@app.route("/admin")
def admin_dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))
    try:
        user = users_col.find_one({"_id": ObjectId(session["user_id"])}, {"password": 0})
    except Exception:
        session.clear()
        return redirect(url_for("index"))
    if not user or user.get("role") != "admin":
        return redirect(url_for("index"))
    return render_template("admin.html")


@app.route("/employee")
def employee_dashboard():
    if "user_id" not in session:
        return redirect(url_for("index"))
    try:
        user = users_col.find_one({"_id": ObjectId(session["user_id"])}, {"password": 0})
    except Exception:
        session.clear()
        return redirect(url_for("index"))
    if not user or user.get("role") != "employee":
        return redirect(url_for("index"))
    return render_template("employee.html")


@app.route("/employee/face")
def face_attendance():
    return render_template("face_attendance.html")


@app.route("/employee/wifi")
def wifi_attendance_page():
    if "user_id" not in session:
        return redirect(url_for("index"))
    return render_template("wifi_attendance.html")


@app.route("/employee/otp")
def otp_attendance_page():
    if "user_id" not in session:
        return redirect(url_for("index"))
    return render_template("otp_attendance.html")


@app.route("/employee/field-engineer")
def field_engineer_attendance_page():
    if "user_id" not in session:
        return redirect(url_for("index"))
    return render_template("field_engineer_attendance.html")


@app.route("/api/field-engineer-attendance", methods=["POST"])
def field_engineer_attendance_api():
    return handle_field_engineer_attendance()


@app.route("/api/location-attendance/today-count", methods=["GET"])
def location_attendance_today_count():
    """Return today's count of field-engineer visits for the employee's org.

    Frontend expects: { ok: true, count: <int> }
    """
    user, err = require_login(role=("employee", "admin"))
    if err:
        return err

    org_id = user.get("org_id")
    if not org_id:
        return jsonify({"ok": False, "error": "Organization not found"}), 400

    today = now_ist().strftime("%Y-%m-%d")

    # Count both possible method spellings
    count = field_attendance_col.count_documents({
        "org_id": org_id,
        "date": today,
        "method": {"$in": ["FieldEngineer", "Field Engineer"]}
    })

    return jsonify({"ok": True, "count": int(count)})






@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")


# ══════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════

@app.route("/api/login", methods=["POST"])
def login():
    data     = request.json or {}
    mobile   = data.get("mobile", "").strip()
    password = data.get("password", "").strip()
    role     = data.get("role", "").strip()
    org_slug = data.get("org_slug", "").strip()  # NEW: company slug

    if not mobile or not password or not role:
        return jsonify({"ok": False, "error": "All fields are required"})

    query = {"mobile": mobile, "role": role}

    if role == "super_admin":
        # Super admin has no org
        user = users_col.find_one({"mobile": mobile, "role": "super_admin"})
    else:
        # Find the org first
        if not org_slug:
            return jsonify({"ok": False, "error": "Company slug is required"})
        org = organizations_col.find_one({"slug": org_slug, "active": True})
        if not org:
            return jsonify({"ok": False, "error": "Company not found or inactive"})
        query["org_id"] = str(org["_id"])
        user = users_col.find_one(query)

    if not user or user["password"] != hash_password(password):
        return jsonify({"ok": False, "error": "Incorrect credentials"})

    session["user_id"] = str(user["_id"])

    resp = {
        "ok":     True,
        "role":   user["role"],
        "name":   user.get("name", ""),
        "emp_id": user.get("emp_id", ""),
        "mobile": user.get("mobile", "")
    }
    if user.get("org_id"):
        resp["org_id"] = user["org_id"]
    return jsonify(resp)


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════════
#  PASSWORD RESET
# ══════════════════════════════════════════════════

@app.route("/api/password-reset/request", methods=["POST"])
def password_reset_request():
    """Request OTP for resetting password.

    Expected JSON:
      - role: "admin" | "employee" | "super_admin"
      - mobile: 10-digit
      - org_slug: required for admin/employee

    Returns:
      {ok: True, message: ...} or {ok: False, error: ...}
    """
    data = request.json or {}
    role = (data.get("role") or "").strip()
    mobile = (data.get("mobile") or "").strip()
    org_slug = (data.get("org_slug") or "").strip()

    if not role or role not in ("admin", "employee", "super_admin"):
        return jsonify({"ok": False, "error": "Invalid role"})
    if not mobile or len(mobile) != 10 or not mobile.isdigit():
        return jsonify({"ok": False, "error": "Valid 10-digit mobile required"})
    if role != "super_admin" and not org_slug:
        return jsonify({"ok": False, "error": "Enter Company code "})

    # Resolve user
    if role == "super_admin":
        user = users_col.find_one({"mobile": mobile, "role": "super_admin"})
        org_id = None
    else:
        org = organizations_col.find_one({"slug": org_slug, "active": True})
        if not org:
            return jsonify({"ok": False, "error": "Company not found or inactive"})
        org_id = str(org["_id"])
        user = users_col.find_one({"mobile": mobile, "role": role, "org_id": org_id})

    if not user:
        # avoid account enumeration
        return jsonify({"ok": False, "error": "Incorrect credentials"})

    # Generate OTP (6 digits) and store in memory
    code = str(random.randint(100000, 999999))
    expires = now_ist().timestamp() + 300


    key = (role, org_id, mobile)
    password_reset_store[key] = {
        "code": code,
        "expires": expires,
        "role": role,
        "org_id": org_id,
    }

    # NOTE: For development, frontend will not show OTP. We log it server-side.
    print(f"\n{'='*40}\nPASSWORD RESET OTP for role={role} mobile={mobile} org_id={org_id} -> OTP={code}\n{'='*40}\n")

    masked = mobile[:2] + "****" + mobile[-2:]
    return jsonify({"ok": True, "message": f"OTP sent to {masked}"})


@app.route("/api/password-reset/confirm", methods=["POST"])
def password_reset_confirm():
    """Confirm OTP and update password.

    Expected JSON:
      - role
      - mobile
      - org_slug (admin/employee)
      - code: 6-digit
      - password: new password (6+)
    """
    data = request.json or {}
    role = (data.get("role") or "").strip()
    mobile = (data.get("mobile") or "").strip()
    code = (data.get("code") or "").strip()
    new_password = (data.get("password") or "").strip()
    org_slug = (data.get("org_slug") or "").strip()

    if not role or role not in ("admin", "employee", "super_admin"):
        return jsonify({"ok": False, "error": "Invalid role"})
    if not mobile or len(mobile) != 10 or not mobile.isdigit():
        return jsonify({"ok": False, "error": "Valid 10-digit mobile required"})
    if not code or len(code) != 6:
        return jsonify({"ok": False, "error": "6-digit code daalo"})
    if not new_password or len(new_password) < 6:
        return jsonify({"ok": False, "error": "Password must be 6+ characters"})

    if role != "super_admin" and not org_slug:
        return jsonify({"ok": False, "error": "Enter Company code"})

    # Resolve org_id for key
    if role == "super_admin":
        org_id = None
    else:
        org = organizations_col.find_one({"slug": org_slug, "active": True})
        if not org:
            return jsonify({"ok": False, "error": "Company not found or inactive"})
        org_id = str(org["_id"])

    key = (role, org_id, mobile)
    stored = password_reset_store.get(key)
    if not stored:
        return jsonify({"ok": False, "error": "OTP not request"})
    if now_ist().timestamp() > stored.get("expires", 0):

        password_reset_store.pop(key, None)
        return jsonify({"ok": False, "error": "OTP expire "})
    if code != stored.get("code"):
        return jsonify({"ok": False, "error": "Wrong OTP"})

    # Update password
    if role == "super_admin":
        users_col.update_one({"mobile": mobile, "role": "super_admin"}, {"$set": {"password": hash_password(new_password)}})
    else:
        users_col.update_one({"mobile": mobile, "role": role, "org_id": org_id}, {"$set": {"password": hash_password(new_password)}})

    password_reset_store.pop(key, None)
    return jsonify({"ok": True, "message": "Password updated"})


# ══════════════════════════════════════════════════
#  PASSWORD RESET 
# ══════════════════════════════════════════════════

@app.route("/api/password-reset/direct", methods=["POST"])
def password_reset_direct():
    """Direct password reset using identity fields.

    Expected JSON varies by role:
      - role=employee:
          {name, mobile, emp_id, password}
          (Employee is identified by mobile+emp_id within their org.)
      - role=admin:
          {name, mobile, org_slug, password}
          (Admin is identified by mobile within that org.)
      - role=super_admin:
          {name, mobile, password}
          (Super admin identified by mobile.)

    NOTE: This is for development UX. Production should use OTP/email verification.
    """
    data = request.json or {}
    role = (data.get("role") or "").strip()
    password = (data.get("password") or "").strip()

    if not role or role not in ("admin", "employee", "super_admin"):
        return jsonify({"ok": False, "error": "Invalid role"})
    if not password or len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be 6+ characters"})

    name = (data.get("name") or "").strip()
    mobile = (data.get("mobile") or "").strip()

    if not name or not mobile or len(mobile) != 10 or not mobile.isdigit():
        return jsonify({"ok": False, "error": "Valid name + 10-digit mobile required"})

    if role == "super_admin":
        user = users_col.find_one({"mobile": mobile, "role": "super_admin"})
        if not user:
            return jsonify({"ok": False, "error": "Incorrect credentials"})
        users_col.update_one({"mobile": mobile, "role": "super_admin"}, {"$set": {"password": hash_password(password)}})
        return jsonify({"ok": True, "message": "Password updated"})

    if role == "admin":
        org_slug = (data.get("org_slug") or "").strip()
        if not org_slug:
            return jsonify({"ok": False, "error": "Enter Company code "})
        org = organizations_col.find_one({"slug": org_slug, "active": True})
        if not org:
            return jsonify({"ok": False, "error": "Company not found or inactive"})
        org_id = str(org["_id"])

        user = users_col.find_one({"mobile": mobile, "role": "admin", "org_id": org_id})
        if not user:
            return jsonify({"ok": False, "error": "Incorrect credentials"})
        users_col.update_one({"_id": user["_id"]}, {"$set": {"password": hash_password(password), "name": name}})
        return jsonify({"ok": True, "message": "Password updated"})

    # employee
    emp_id = (data.get("emp_id") or "").strip()
    if not emp_id:
        return jsonify({"ok": False, "error": "Enter Employee ID "})

    # Try match by mobile+emp_id (org stored on user)
    user = users_col.find_one({"mobile": mobile, "role": "employee", "emp_id": emp_id})
    if not user:
        return jsonify({"ok": False, "error": "Incorrect credentials"})

    users_col.update_one({"_id": user["_id"]}, {"$set": {"password": hash_password(password), "name": name}})
    return jsonify({"ok": True, "message": "Password updated"})


# ══════════════════════════════════════════════════
#  SUPER ADMIN — ORGANIZATION MANAGEMENT
# ══════════════════════════════════════════════════



@app.route("/api/super/orgs", methods=["GET"])
def super_list_orgs():
    user, err = require_login(role="super_admin")
    if err:
        return err
    orgs = list(organizations_col.find({}, {"_id": 1, "name": 1, "slug": 1, "active": 1, "created": 1, "admin_name": 1, "admin_mobile": 1}))

    # NOTE: 'slug' is the company code used for login (admin/employee via org_slug)
    # (Generated randomly, not from org_name)


    for o in orgs:
        o["_id"] = str(o["_id"])
        # Count employees in this org
        o["employee_count"] = users_col.count_documents({"org_id": str(o["_id"]), "role": "employee"})
    # plan field intentionally not returned
    for o in orgs:
        o.pop("plan", None)
    return jsonify({"ok": True, "orgs": orgs})



@app.route("/api/super/orgs/create", methods=["POST"])
def super_create_org():
    """Create a new organization + its first admin account."""
    user, err = require_login(role="super_admin")
    if err:
        return err

    data         = request.json or {}
    org_name     = data.get("org_name", "").strip()
    admin_name   = data.get("admin_name", "").strip()
    admin_mobile = data.get("admin_mobile", "").strip()
    admin_pass   = data.get("admin_password", "").strip()


    if not all([org_name, admin_name, admin_mobile, admin_pass]):
        return jsonify({"ok": False, "error": "All fields are required"})
    if len(admin_mobile) != 10 or not admin_mobile.isdigit():
        return jsonify({"ok": False, "error": "Enter a valid 10-digit mobile"})
    if len(admin_pass) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters"})

    # Generate UNIQUE company code (NOT based on org_name)
    # Format: Random 8-char alphanumeric
    def generate_code(n=8):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "".join(random.choice(alphabet) for _ in range(n))

    slug = generate_code(8)
    while organizations_col.find_one({"slug": slug}):
        slug = generate_code(8)


    # Create org
    org_doc = {
        "name":             org_name,
        "slug":             slug,

        "active":           True,
        "admin_name":       admin_name,
        "admin_mobile":     admin_mobile,
        "office_lat":       DEFAULT_OFFICE_LAT,
        "office_lng":       DEFAULT_OFFICE_LNG,
        "office_radius_m":  DEFAULT_OFFICE_RADIUS_M,
        "office_ip":        DEFAULT_OFFICE_IP,
        "created":          datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    result = organizations_col.insert_one(org_doc)
    org_id = str(result.inserted_id)

    # Check mobile not already used within this org
    if users_col.find_one({"mobile": admin_mobile, "org_id": org_id}):
        organizations_col.delete_one({"_id": result.inserted_id})
        return jsonify({"ok": False, "error": "Mobile already registered"})

    # Create admin account for this org
    users_col.insert_one({
        "name":     admin_name,
        "mobile":   admin_mobile,
        "password": hash_password(admin_pass),
        "role":     "admin",
        "org_id":   org_id,
        "created":  datetime.now().strftime("%Y-%m-%d %H:%M")
    })

    return jsonify({
        "ok":   True,
        "message": f"Organization '{org_name}' created!",
        "slug": slug,
        "org_id": org_id
    })


@app.route("/api/super/orgs/<org_id>/toggle", methods=["POST"])
def super_toggle_org(org_id):
    """Activate or deactivate an organization."""
    user, err = require_login(role="super_admin")
    if err:
        return err
    try:
        oid = ObjectId(org_id)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid org ID"})
    org = organizations_col.find_one({"_id": oid})
    if not org:
        return jsonify({"ok": False, "error": "Org not found"})
    new_state = not org.get("active", True)
    organizations_col.update_one({"_id": oid}, {"$set": {"active": new_state}})
    return jsonify({"ok": True, "active": new_state})


@app.route("/api/super/orgs/<org_id>", methods=["DELETE"])
def super_delete_org(org_id):
    """Delete an organization and ALL its data."""
    user, err = require_login(role="super_admin")
    if err:
        return err
    try:
        oid = ObjectId(org_id)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid org ID"})

    org_id_str = str(oid)
    users_col.delete_many({"org_id": org_id_str})
    employees_col.delete_many({"org_id": org_id_str})
    attendance_col.delete_many({"org_id": org_id_str})
    organizations_col.delete_one({"_id": oid})
    return jsonify({"ok": True, "message": "Organization and all data deleted"})


@app.route("/api/super/orgs/<org_id>/settings", methods=["POST"])
def super_update_org_settings(org_id):
    """Update org office GPS/WiFi settings from super-admin panel."""
    user, err = require_login(role="super_admin")
    if err:
        return err
    data = request.json or {}
    update = {}
    for field in ["office_lat", "office_lng", "office_radius_m", "name"]:

        if field in data:
            update[field] = data[field]
    if "office_ip" in data:
        update["office_ip"] = data["office_ip"]
    try:
        organizations_col.update_one({"_id": ObjectId(org_id)}, {"$set": update})
    except Exception:
        return jsonify({"ok": False, "error": "Invalid org ID"})
    return jsonify({"ok": True, "message": "Settings updated"})


@app.route("/api/super/me", methods=["POST"])
def super_update_me():
    """Super admin can update ONLY their own mobile/password."""
    user, err = require_login(role="super_admin")
    if err:
        return err

    data = request.json or {}
    new_mob = (data.get("mobile") or "").strip()
    new_pass = (data.get("password") or "").strip()

    update = {}

    if new_mob:
        if len(new_mob) != 10 or not new_mob.isdigit():
            return jsonify({"ok": False, "error": "Valid 10-digit mobile required"})
        # Ensure mobile uniqueness across all users (simple + safe)
        existing = users_col.find_one({"mobile": new_mob, "role": "super_admin", "_id": {"$ne": user["_id"]}})
        if existing:
            return jsonify({"ok": False, "error": "Mobile already used"})
        update["mobile"] = new_mob

    if new_pass:
        if len(new_pass) < 6:
            return jsonify({"ok": False, "error": "Password must be 6+ characters"})
        update["password"] = hash_password(new_pass)

    if not update:
        return jsonify({"ok": False, "error": "No changes provided"})

    users_col.update_one({"_id": user["_id"]}, {"$set": update})
    return jsonify({"ok": True, "message": "Super admin details updated"})


@app.route("/api/super/stats", methods=["GET"])
def super_stats():
    user, err = require_login(role="super_admin")
    if err:
        return err
    total_orgs    = organizations_col.count_documents({})
    active_orgs   = organizations_col.count_documents({"active": True})
    total_users   = users_col.count_documents({"role": "employee"})
    today         = now_ist().strftime("%Y-%m-%d")

    today_records = office_attendance_col.count_documents({"date": today})
    return jsonify({
        "ok": True,
        "total_orgs":    total_orgs,
        "active_orgs":   active_orgs,
        "total_users":   total_users,
        "today_records": today_records
    })


@app.route("/api/super/orgs/<org_id>/report", methods=["GET"])
def super_org_report_by_date(org_id):
    """Super admin can view a company's attendance date-wise."""
    user, err = require_login(role="super_admin")
    if err:
        return err

    try:
        oid = ObjectId(org_id)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid org ID"})

    date = request.args.get("date", now_ist().strftime("%Y-%m-%d")).strip()
    att_type = request.args.get("attendance_type", "").strip()

    office_query = {"org_id": str(oid), "date": date}
    field_query  = {"org_id": str(oid), "date": date}

    if att_type == "WFH":
        office_query["attendance_type"] = "WFH"
        field_query = None
    elif att_type == "WFO":
        office_query["attendance_type"] = {"$in": ["WFO", None, ""]}
        field_query = None
    elif att_type == "Field":
        office_query = None

    rows = []
    if office_query is not None:
        for r in office_attendance_col.find(office_query).sort([("date",1),("in_time",1)]):
            r["_id"] = str(r["_id"])
            r["attendance_type"] = r.get("attendance_type", "WFO")
            rows.append(r)
    if field_query is not None:
        for r in field_attendance_col.find(field_query).sort([("date",1),("in_time",1)]):
            r["_id"] = str(r["_id"])
            r["attendance_type"] = "Field"
            rows.append(r)

    rows.sort(key=lambda x: (x.get("date",""), x.get("in_time","")))
    return jsonify({"ok": True, "rows": rows, "date": date})



# ══════════════════════════════════════════════════
#  ADMIN — ORG SETTINGS
# ══════════════════════════════════════════════════

@app.route("/api/admin/org-settings", methods=["GET"])
def admin_get_org_settings():
    user, err = require_login(role="admin")
    if err:
        return err
    org = user.get("_org", {})
    return jsonify({
        "ok":              True,
        "org_name":        org.get("name", ""),
        "slug":            org.get("slug", ""),
        "office_lat":      org.get("office_lat",      DEFAULT_OFFICE_LAT),
        "office_lng":      org.get("office_lng",      DEFAULT_OFFICE_LNG),
        "office_radius_m": org.get("office_radius_m", DEFAULT_OFFICE_RADIUS_M),
        "office_ip":   org.get("office_ip",   DEFAULT_OFFICE_IP),

    })


@app.route("/api/admin/org-settings", methods=["POST"])
def admin_update_org_settings():
    """Admin can update their own org's office GPS/WiFi settings."""
    user, err = require_login(role="admin")
    if err:
        return err
    data   = request.json or {}
    org_id = user.get("org_id")
    update = {}
    for field in ["office_lat", "office_lng", "office_radius_m", "office_ip"]:
        if field in data:
            update[field] = data[field]
    if update:
        organizations_col.update_one({"_id": ObjectId(org_id)}, {"$set": update})
    return jsonify({"ok": True, "message": "Office settings updated!"})


# ══════════════════════════════════════════════════
#  NETWORK / LOCATION (org-aware)
# ══════════════════════════════════════════════════

@app.route("/api/location-status", methods=["POST"])
def location_status():

    user, err = require_login(role=("employee", "admin"))
    if err:
        return err
    org  = user.get("_org", {})
    data = request.json or {}
    lat  = data.get("lat")
    lng  = data.get("lng")
    in_office, distance = is_in_office_for_org(lat, lng, org)
    return jsonify({
        "in_office": in_office,
        "distance":  distance,
        "radius":    org.get("office_radius_m", DEFAULT_OFFICE_RADIUS_M)
    })



@app.route("/api/office-location")
def office_location():
    user, err = require_login(role=("employee", "admin"))
    if err:
        return err
    org = user.get("_org", {})
    return jsonify({
        "lat":    org.get("office_lat",      DEFAULT_OFFICE_LAT),
        "lng":    org.get("office_lng",      DEFAULT_OFFICE_LNG),
        "radius": org.get("office_radius_m", DEFAULT_OFFICE_RADIUS_M)
    })



# ══════════════════════════════════════════════════
#  WIFI CHECK API
# ══════════════════════════════════════════════════

@app.route("/api/wifi-check", methods=["GET", "POST"])
def wifi_check():
    user, err = require_login(role=("employee", "admin"))
    if err:
        return err
    org = user.get("_org", {})
    configured_ip = org.get("office_ip", "").strip()

    # Client apna public IP bhej sakta hai (POST se)
    # Agar nahi bheja toh server headers se try karo
    if request.method == "POST":
        data = request.json or {}
        ip = data.get("client_ip", "").strip()
    else:
        ip = get_client_real_ip(request)

    on_office, reason = is_office_ip_for_org(ip, org)
    return jsonify({
        "on_office_wifi":  on_office,
        "on_net":          on_office,
        "client_ip":       ip,
        "ip":              ip,
        "configured_ip":   configured_ip,
        "reason":          reason
    })


# Admin template expects this endpoint
@app.route("/api/network-status", methods=["GET"])
def network_status():
    # Alias to wifi-check
    return wifi_check()



# ══════════════════════════════════════════════════
#  WIFI MARK ATTENDANCE
# ══════════════════════════════════════════════════

@app.route("/api/wifi-attendance", methods=["POST"])
def wifi_attendance():
    user, err = require_login(role="employee")
    if err:
        return err

    org    = user.get("_org", {})
    org_id = user.get("org_id")

    # Browser se bheja hua public IP use karo (zyada accurate)
    data = request.json or {}
    ip = data.get("client_ip", "").strip() or get_client_real_ip(request)

    on_office, reason = is_office_ip_for_org(ip, org)

    if not on_office:
        return jsonify({"ok": False, "error": f"Not in Office WiFi — {reason}"})

    emp_id = user.get("emp_id")
    name   = user.get("name")
    today  = now_ist().strftime("%Y-%m-%d")
    now    = now_ist().strftime("%H:%M:%S")


    # 2-step attendance: first mark => in_time, second mark => out_time
    existing = office_attendance_col.find_one({"emp_id": emp_id, "org_id": org_id, "date": today})
    if existing:
        if not existing.get("in_time"):
            office_attendance_col.update_one(
                {"_id": existing["_id"]},
                {"$set": {"in_time": now, "method": "WiFi", "ip": ip, "status": "Present"}}
            )
            return jsonify({"ok": True, "status": "in_marked", "in_time": now,
                            "message": f"✓ WiFi IN marked! Time: {now}"})
        if existing.get("in_time") and not existing.get("out_time"):
            office_attendance_col.update_one(
                {"_id": existing["_id"]},
                {"$set": {"out_time": now, "method_out": "WiFi", "ip_out": ip, "status": "Present"}}
            )
            return jsonify({"ok": True, "status": "out_marked", "out_time": now,
                            "message": f"✓ WiFi OUT marked! Time: {now}"})
        return jsonify({"ok": True, "status": "completed",
                        "message": "Attendance already completed (IN & OUT)"})

    # If not existing doc, create with in_time
    office_attendance_col.insert_one({
        "org_id": org_id, "emp_id": emp_id, "name": name,
        "date": today,
        "in_time": now,
        "out_time": None,
        "status": "Present",
        "method": "WiFi",
        "method_out": None,
        "ip": ip,
        "ip_out": None,
        "attendance_type": "WFO"
    })
    return jsonify({"ok": True, "status": "in_marked", "in_time": now,
                    "message": f"✓ WiFi IN marked! Time: {now}"})



# ══════════════════════════════════════════════════
#  OTP ATTENDANCE
# ══════════════════════════════════════════════════

@app.route("/api/otp/send", methods=["POST"])
def send_otp():
    user, err = require_login(role="employee")
    if err:
        return err

    emp_id  = user.get("emp_id")
    org_id  = user.get("org_id")
    mobile  = user.get("mobile", "")
    name    = user.get("name", "")
    key     = (org_id, emp_id)

    otp_code = str(random.randint(100000, 999999))
    expires  = now_ist().timestamp() + 300

    otp_store[key] = {"otp": otp_code, "expires": expires, "mobile": mobile}

    print(f"\n{'='*40}\nOTP for {name} ({emp_id}) | Org: {org_id}\nMobile: {mobile}\nOTP: {otp_code}\n{'='*40}\n")

    masked = mobile[:2] + "****" + mobile[-2:]
    return jsonify({"ok": True, "message": f"OTP sent to {masked}", "otp_dev": otp_code})


@app.route("/api/otp/verify", methods=["POST"])
def verify_otp():
    user, err = require_login(role="employee")
    if err:
        return err

    data    = request.json or {}
    entered = data.get("otp", "").strip()
    emp_id  = user.get("emp_id")
    org_id  = user.get("org_id")
    name    = user.get("name")
    key     = (org_id, emp_id)

    if not entered:
        return jsonify({"ok": False, "error": "OTP daalo"})

    stored = otp_store.get(key)
    if not stored:
        return jsonify({"ok": False, "error": "No any Otp, Send New request "})
    if now_ist().timestamp() > stored["expires"]:

        del otp_store[key]
        return jsonify({"ok": False, "error": "OTP expire "})
    if entered != stored["otp"]:
        return jsonify({"ok": False, "error": "Wrong OTP"})

    del otp_store[key]
    today = now_ist().strftime("%Y-%m-%d")
    now   = now_ist().strftime("%H:%M:%S")

    ip    = client_ip()

    existing = office_attendance_col.find_one({"emp_id": emp_id, "org_id": org_id, "date": today})
    if existing:
        if not existing.get("in_time"):
            office_attendance_col.update_one(
                {"_id": existing["_id"]},
                {"$set": {"in_time": now, "method": "OTP", "ip": ip, "status": "Present"}}
            )
            return jsonify({"ok": True, "status": "in_marked", "in_time": now,
                            "message": f"✓ OTP IN marked! Time: {now}"})
        if existing.get("in_time") and not existing.get("out_time"):
            office_attendance_col.update_one(
                {"_id": existing["_id"]},
                {"$set": {"out_time": now, "method_out": "OTP", "ip_out": ip, "status": "Present"}}
            )
            return jsonify({"ok": True, "status": "out_marked", "out_time": now,
                            "message": f"✓ OTP OUT marked! Time: {now}"})
        return jsonify({"ok": True, "status": "completed",
                        "message": "Attendance already completed (IN & OUT)"})

    office_attendance_col.insert_one({
        "org_id": org_id, "emp_id": emp_id, "name": name,
        "date": today,
        "in_time": now,
        "out_time": None,
        "status": "Present",
        "method": "OTP",
        "method_out": None,
        "ip": ip,
        "ip_out": None,
        "attendance_type": "WFO"
    })
    return jsonify({"ok": True, "status": "in_marked", "in_time": now,
                    "message": f"✓ OTP IN marked! Time: {now}"})



# ══════════════════════════════════════════════════
#  FACE REGISTER
# ══════════════════════════════════════════════════

@app.route("/api/register-face", methods=["POST"])
def register_face():
    user, err = require_login(role="admin")
    if err:
        return err

    data   = request.json or {}
    emp_id = data.get("emp_id", "").strip()
    name   = data.get("name", "").strip()
    image  = data.get("image", "")
    org_id = user.get("org_id")

    if not emp_id or not name or not image:
        return jsonify({"ok": False, "error": "emp_id, name, and image required"})

    encoding, error = encode_face_from_b64(image)
    if error:
        return jsonify({"ok": False, "error": error})

    employees_col.update_one(
        {"emp_id": emp_id, "org_id": org_id},
        {"$set": {"emp_id": emp_id, "name": name, "org_id": org_id,
                  "encoding": encoding, "registered_at": datetime.now().strftime("%Y-%m-%d %H:%M")}},
        upsert=True
    )
    return jsonify({"ok": True, "message": f"{emp_id} | {name} registered!"})


# ══════════════════════════════════════════════════
#  FACE MARK ATTENDANCE
# ══════════════════════════════════════════════════

@app.route("/api/mark-attendance", methods=["POST"])
def mark_attendance():
    # Face attendance can be done by employee (no strict login needed for kiosk mode)
    # but we still need org context — pass org_slug in request
    data     = request.json or {}
    image    = data.get("image", "")
    tol      = float(data.get("tolerance", 0.5))
    lat      = data.get("lat")
    lng      = data.get("lng")
    org_slug = data.get("org_slug", "").strip()
    attendance_type = data.get("attendance_type", "WFO").strip()  # WFH / WFO

    # SECURITY FIX: face kiosk is login-required. Ignore client-provided org_slug.
    # Always derive org_id from logged-in employee session.
    user, err = require_login(role="employee")
    if err:
        return err
    org_id = user.get("org_id")
    if not org_id:
        return jsonify({"ok": False, "error": "Organization not found"})

    org = get_org(org_id)
    if not org:
        return jsonify({"ok": False, "error": "Company not found"})

    # WFH mode: GPS check bypass karo
    if attendance_type == "WFH":
        in_office = True
        distance = 0.0
    else:
        in_office, distance = is_in_office_for_org(lat, lng, org)

    if not in_office:
        radius = org.get("office_radius_m", 100)
        return jsonify({"ok": False,
                        "error": f"Out Of Office ({distance}m). Max allowed: {radius}m"})

    ip = client_ip()
    if not image:
        return jsonify({"ok": False, "error": "No image received"})

    # Only recognize faces from THIS org's employees
    results, error = recognize_face_from_b64(image, tolerance=tol, org_id=org_id)
    if error:
        return jsonify({"ok": False, "error": error})
    if not results:
        return jsonify({"ok": False, "error": "Not detect any face"})

    today    = now_ist().strftime("%Y-%m-%d")
    now_time = now_ist().strftime("%H:%M:%S")

    marked   = []

    for r in results:
        if r["emp_id"] == "Unknown":
            continue
        existing = office_attendance_col.find_one({"emp_id": r["emp_id"], "org_id": org_id, "date": today})
        if existing:
            # IN then OUT
            if not existing.get("in_time"):
                office_attendance_col.update_one(
                    {"_id": existing["_id"]},
                    {"$set": {"in_time": now_time, "method": "Face", "ip": ip, "status": "Present"}}
                )
                marked.append({"emp_id": r["emp_id"], "name": r["name"],
                               "status": "in_marked", "in_time": now_time})
                continue
            if existing.get("in_time") and not existing.get("out_time"):
                office_attendance_col.update_one(
                    {"_id": existing["_id"]},
                    {"$set": {"out_time": now_time, "method_out": "Face", "ip_out": ip, "status": "Present"}}
                )
                marked.append({"emp_id": r["emp_id"], "name": r["name"],
                               "status": "out_marked", "out_time": now_time})
                continue
            marked.append({"emp_id": r["emp_id"], "name": r["name"],
                           "status": "completed"})
            continue

        office_attendance_col.insert_one({
            "org_id": org_id, "emp_id": r["emp_id"], "name": r["name"],
            "date": today,
            "in_time": now_time,
            "out_time": None,
            "status": "Present",
            "method": "Face",
            "method_out": None,
            "ip": ip,
            "ip_out": None,
            "attendance_type": attendance_type
        })
        marked.append({"emp_id": r["emp_id"], "name": r["name"],
                       "status": "in_marked", "in_time": now_time})


    unknown_count = sum(1 for r in results if r["emp_id"] == "Unknown")
    return jsonify({"ok": True, "marked": marked, "unknown": unknown_count, "total_faces": len(results)})


# ══════════════════════════════════════════════════
#  STATS & REPORTS (org-scoped)
# ══════════════════════════════════════════════════

@app.route("/api/stats")
def stats():
    user, err = require_login(role="admin")
    if err:
        return err
    org_id     = user.get("org_id")
    today      = now_ist().strftime("%Y-%m-%d")

    present    = office_attendance_col.count_documents({"org_id": org_id, "date": today})
    registered = employees_col.count_documents({"org_id": org_id})
    absent     = max(0, registered - present)
    return jsonify({"present": present, "absent": absent, "registered": registered, "date": today})


@app.route("/api/today-log")
def today_log():
    user, err = require_login(role="admin")
    if err:
        return err

    org_id = user.get("org_id")
    today = now_ist().strftime("%Y-%m-%d")

    office_rows = list(
        office_attendance_col.find({"org_id": org_id, "date": today}, {"_id": 0})
        .sort([("date", 1), ("in_time", 1), ("out_time", 1)])
    )

    field_rows = list(
        field_attendance_col.find({"org_id": org_id, "date": today}, {"_id": 0})
        .sort([("date", 1), ("in_time", 1), ("out_time", 1)])
    )

    rows = []
    for r in office_rows:
        rows.append({
            "emp_id": r.get("emp_id"),
            "name": r.get("name"),
            "in_time": r.get("in_time"),
            "out_time": r.get("out_time"),
            "ip": r.get("ip"),
            "ip_out": r.get("ip_out"),
            "method": r.get("method"),
            "type": "office",
        })

    for r in field_rows:
        rows.append({
            "emp_id": r.get("emp_id"),
            "name": r.get("name"),
            "in_time": r.get("in_time"),
            "out_time": r.get("out_time"),
            "ip": r.get("ip"),
            "ip_out": r.get("ip_out"),
            "method": r.get("method"),
            "type": "field",
            "place": r.get("place"),
            "full_address": r.get("full_address"),
        })

    rows.sort(key=lambda x: (x.get("in_time") or ""))
    return jsonify({"ok": True, "rows": rows})




@app.route("/api/report")
def report():
    user, err = require_login(role="admin")
    if err:
        return err

    org_id = user.get("org_id")
    date = request.args.get("date", now_ist().strftime("%Y-%m-%d")).strip()
    att_type = request.args.get("attendance_type", "").strip()  # WFH / WFO / Field / ""

    # Office + Field engineer attendance dono show honge
    office_query = {"org_id": org_id, "date": date}
    field_query  = {"org_id": org_id, "date": date}

    # Type filter
    if att_type == "WFH":
        office_query["attendance_type"] = "WFH"
        field_query = None  # WFH = no field rows
    elif att_type == "WFO":
        office_query["attendance_type"] = {"$in": ["WFO", None, ""]}
        # Also include docs without attendance_type (legacy data)
        field_query = None
    elif att_type == "Field":
        office_query = None  # Field = only field_attendance_col

    office_rows_raw = list(
        office_attendance_col.find(office_query)
        .sort([("date", 1), ("in_time", 1), ("out_time", 1)])
    ) if office_query is not None else []

    field_rows_raw = list(
        field_attendance_col.find(field_query)
        .sort([("date", 1), ("in_time", 1), ("out_time", 1)])
    ) if field_query is not None else []

    rows = []

    for r in office_rows_raw:
        rid = str(r["_id"])
        rows.append({
            "_id": rid,
            "emp_id": r.get("emp_id"),
            "name": r.get("name"),
            "date": r.get("date"),
            "in_time": r.get("in_time"),
            "out_time": r.get("out_time"),
            "status": r.get("status"),
            "place": None,
            "full_address": None,
            "city": None,
            "ip": r.get("ip"),
            "ip_out": r.get("ip_out"),
            "method": r.get("method"),
            "attendance_type": r.get("attendance_type", "WFO"),
        })

    for r in field_rows_raw:
        rid = str(r.get("_id"))
        rows.append({
            "_id": rid,
            "emp_id": r.get("emp_id"),
            "name": r.get("name"),
            "date": r.get("date"),
            "in_time": r.get("in_time"),
            "out_time": r.get("out_time"),
            "status": r.get("status"),
            "place": r.get("place"),
            "full_address": r.get("full_address"),
            "city": r.get("city"),
            "ip": r.get("ip"),
            "ip_out": r.get("ip_out"),
            "method": r.get("method"),
            "visit_type": r.get("visit_type"),
            "attendance_type": "Field",
        })

    # in_time sort (string HH:MM:SS safe for lexicographic too)
    rows.sort(key=lambda x: (x.get("date") or "", x.get("in_time") or "", x.get("out_time") or ""))
    return jsonify({"ok": True, "rows": rows, "date": date})




@app.route("/api/download-csv")
def download_csv():
    user, err = require_login(role="admin")
    if err:
        return err

    org_id = user.get("org_id")
    period = request.args.get("period", "today")
    att_type = request.args.get("attendance_type", "").strip()  # WFH / WFO / Field / ""
    today = now_ist()

    query = {"org_id": org_id}

    if period == "today":
        query["date"] = today.strftime("%Y-%m-%d")
        fname = f"attendance_today_{today.strftime('%Y-%m-%d')}.csv"
    elif period == "month":
        month_str = today.strftime("%Y-%m")
        query["date"] = {"$regex": f"^{month_str}"}
        fname = f"attendance_month_{month_str}.csv"
    elif period == "year":
        year_str = today.strftime("%Y")
        query["date"] = {"$regex": f"^{year_str}"}
        fname = f"attendance_year_{year_str}.csv"
    elif period == "custom":
        custom_date = request.args.get("date", today.strftime("%Y-%m-%d"))
        query["date"] = custom_date
        fname = f"attendance_{custom_date}.csv"
    else:
        fname = "attendance_all_time.csv"

    # Apply attendance_type filter
    office_query = dict(query)
    field_query  = dict(query)
    if att_type == "WFH":
        office_query["attendance_type"] = "WFH"
        field_query = None
    elif att_type == "WFO":
        office_query["attendance_type"] = {"$in": ["WFO", None, ""]}
        field_query = None
    elif att_type == "Field":
        office_query = None

    office_rows = list(
        office_attendance_col.find(office_query, {"_id": 0, "org_id": 0})
        .sort([("date", 1), ("in_time", 1), ("out_time", 1)])
    ) if office_query is not None else []
    field_rows = list(
        field_attendance_col.find(field_query, {"_id": 0, "org_id": 0})
        .sort([("date", 1), ("in_time", 1), ("out_time", 1)])
    ) if field_query is not None else []

    # Determine if we are exporting a single type or mixed
    is_wfh_only  = (att_type == "WFH")
    is_wfo_only  = (att_type == "WFO")
    is_field_only= (att_type == "Field")

    rows = []
    for r in office_rows:
        rec_type = r.get("attendance_type", "WFO")
        row = {
            "emp_id":          r.get("emp_id"),
            "name":            r.get("name"),
            "date":            r.get("date"),
            "in_time":         r.get("in_time"),
            "out_time":        r.get("out_time"),
            "status":          r.get("status"),
            "attendance_type": rec_type,
        }
        # WFH: only basic fields (no ip, ip_out, place, method_out)
        if rec_type == "WFH":
            row["method"] = r.get("method")
        else:
            # WFO: method shows actual method (Face/WiFi/OTP), no ip/ip_out/place/method_out
            row["method"] = r.get("method")
        rows.append(row)

    for r in field_rows:
        rows.append({
            "emp_id":          r.get("emp_id"),
            "name":            r.get("name"),
            "date":            r.get("date"),
            "in_time":         r.get("in_time"),
            "out_time":        r.get("out_time"),
            "status":          r.get("status"),
            "method":          r.get("method"),
            "attendance_type": "Field",
            "place":           r.get("place", ""),
        })

    if not rows:
        return jsonify({"ok": False, "error": "No records found"}), 404

    # Build fieldnames based on what types are in the export
    has_field = any(r.get("attendance_type") == "Field" for r in rows)
    if has_field and not is_wfh_only and not is_wfo_only:
        # Mixed or Field-only: include place column
        fieldnames = ["emp_id", "name", "date", "in_time", "out_time", "status", "method", "attendance_type", "place"]
    else:
        # WFH-only or WFO-only: no place column
        fieldnames = ["emp_id", "name", "date", "in_time", "out_time", "status", "method", "attendance_type"]

    # Ensure all rows have all fieldnames (fill missing with "")
    for row in rows:
        for f in fieldnames:
            if f not in row:
                row[f] = ""

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")

    writer.writeheader()
    writer.writerows(rows)
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})



@app.route("/api/registered-employees")
def registered_employees():
    user, err = require_login(role="admin")
    if err:
        return err
    org_id = user.get("org_id")
    docs   = list(employees_col.find({"org_id": org_id}, {"_id": 0, "encoding": 0, "org_id": 0}))
    return jsonify({"ok": True, "employees": docs})


# ══════════════════════════════════════════════════
#  EMPLOYEE MANAGEMENT (Admin, org-scoped)
# ══════════════════════════════════════════════════

@app.route("/api/delete-employee", methods=["POST"])
def delete_employee():
    user, err = require_login(role="admin")
    if err:
        return err
    org_id = user.get("org_id")
    query  = request.json.get("query", "").strip()
    res    = employees_col.delete_one({
        "org_id": org_id,
        "$or": [{"emp_id": query}, {"name": query}]
    })
    if res.deleted_count == 0:
        return jsonify({"ok": False, "error": "Employee not found"})
    return jsonify({"ok": True, "message": "Employee deleted"})


@app.route("/api/accounts/list")
def accounts_list():
    user, err = require_login(role="admin")
    if err:
        return err
    org_id = user.get("org_id")
    docs   = list(users_col.find({"role": "employee", "org_id": org_id}, {"_id": 0, "password": 0, "org_id": 0}))
    return jsonify({"ok": True, "accounts": docs})


@app.route("/api/accounts/create", methods=["POST"])
def create_account():
    user, err = require_login(role="admin")
    if err:
        return err
    org_id   = user.get("org_id")
    data     = request.json or {}
    name     = data.get("name", "").strip()
    emp_id   = data.get("emp_id", "").strip()
    mobile   = data.get("mobile", "").strip()
    password = data.get("password", "").strip()

    if not all([name, emp_id, mobile, password]):
        return jsonify({"ok": False, "error": "All fields required"})
    if len(mobile) != 10 or not mobile.isdigit():
        return jsonify({"ok": False, "error": "Valid 10-digit mobile required"})

    if users_col.find_one({"mobile": mobile, "org_id": org_id}):
        return jsonify({"ok": False, "error": "Mobile already registered in this company"})
    if users_col.find_one({"emp_id": emp_id, "org_id": org_id}):
        return jsonify({"ok": False, "error": f"Employee ID '{emp_id}' already in use"})

    users_col.insert_one({
        "name": name, "emp_id": emp_id, "mobile": mobile,
        "password": hash_password(password), "role": "employee",
        "org_id": org_id, "created": datetime.now().strftime("%Y-%m-%d %H:%M")
    })
    return jsonify({"ok": True, "message": f"Account created for {name} ({emp_id})"})


@app.route("/api/accounts/delete", methods=["POST"])
def delete_account():
    user, err = require_login(role="admin")
    if err:
        return err
    org_id = user.get("org_id")
    query  = request.json.get("query", "").strip()
    res    = users_col.delete_one({
        "role": "employee", "org_id": org_id,
        "$or": [{"mobile": query}, {"emp_id": query}]
    })
    if res.deleted_count == 0:
        return jsonify({"ok": False, "error": "Account not found"})
    return jsonify({"ok": True})


@app.route("/api/accounts/update-admin", methods=["POST"])
def update_admin():
    user, err = require_login(role="admin")
    if err:
        return err
    data     = request.json or {}
    new_mob  = data.get("mobile", "").strip()
    new_pass = data.get("password", "").strip()
    update   = {}
    if new_mob:
        if len(new_mob) != 10 or not new_mob.isdigit():
            return jsonify({"ok": False, "error": "Valid 10-digit mobile required"})
        update["mobile"] = new_mob
    if new_pass:
        if len(new_pass) < 6:
            return jsonify({"ok": False, "error": "Password must be 6+ chars"})
        update["password"] = hash_password(new_pass)
    if not update:
        return jsonify({"ok": False, "error": "No changes provided"})
    users_col.update_one({"_id": ObjectId(session["user_id"])}, {"$set": update})
    return jsonify({"ok": True, "message": "Admin details updated!"})


@app.route("/api/my-status")
def my_status():
    user, err = require_login(role="employee")
    if err:
        return err
    org_id = user.get("org_id")
    today  = now_ist().strftime("%Y-%m-%d")

    record = office_attendance_col.find_one(

        {"emp_id": user.get("emp_id"), "org_id": org_id, "date": today},
        {"_id": 0}
    )

    marked = bool(record)
    return jsonify({"ok": True, "marked": marked, "record": record,
                    "name": user.get("name"), "emp_id": user.get("emp_id")})




# ══════════════════════════════════════════════════
#  ATTENDANCE DELETE ROUTES (org-scoped)
# ══════════════════════════════════════════════════

@app.route("/api/attendance/delete/<emp_id>", methods=["DELETE"])
def delete_attendance_record(emp_id):
    user, err = require_login(role="admin")
    if err:
        return err

    org_id = user.get("org_id")
    date = request.args.get("date")
    mongo_id = request.args.get("mongo_id")

    if not date:
        return jsonify({"ok": False, "error": "Date parameter required"})

    # agar mongo_id diya hai to directly delete by _id (office + field dono)
    if mongo_id:
        try:
            oid = ObjectId(mongo_id)
            res_office = office_attendance_col.delete_one({"_id": oid, "org_id": org_id})
            if res_office.deleted_count:
                return jsonify({"ok": True, "deleted": res_office.deleted_count, "source": "office"})

            res_field = field_attendance_col.delete_one({"_id": oid, "org_id": org_id})
            if res_field.deleted_count:
                return jsonify({"ok": True, "deleted": res_field.deleted_count, "source": "field"})
        except Exception:
            pass

    # Fallback: emp_id + date based delete (office first)
    res = office_attendance_col.delete_one({"emp_id": emp_id, "org_id": org_id, "date": date})
    if res.deleted_count:
        return jsonify({"ok": True, "deleted": res.deleted_count, "source": "office"})

    res_field = field_attendance_col.delete_one({"emp_id": emp_id, "org_id": org_id, "date": date})
    if res_field.deleted_count:
        return jsonify({"ok": True, "deleted": res_field.deleted_count, "source": "field"})

    return jsonify({"ok": False, "error": "Record not found"})



@app.route("/api/attendance/delete-by-date/<date>", methods=["DELETE"])
def delete_attendance_by_date(date):
    user, err = require_login(role="admin")
    if err:
        return err
    org_id = user.get("org_id")
    res    = office_attendance_col.delete_many({"date": date, "org_id": org_id})
    return jsonify({"ok": True, "deleted": res.deleted_count})


@app.route("/api/attendance/bulk-delete", methods=["DELETE"])
def bulk_delete_attendance():
    user, err = require_login(role="admin")
    if err:
        return err
    org_id = user.get("org_id")
    data   = request.json or {}
    ids    = data.get("record_ids", [])
    if not ids:
        return jsonify({"ok": False, "error": "record_ids list required"})
    try:
        obj_ids = [ObjectId(i) for i in ids if i]
    except Exception:
        return jsonify({"ok": False, "error": "Invalid ID format"})
    # Verify records belong to this org before deleting
    res = office_attendance_col.delete_many({"_id": {"$in": obj_ids}, "org_id": org_id})
    return jsonify({"ok": True, "deleted": res.deleted_count})


# ══════════════════════════════════════════════════
#  PUBLIC — Org slug lookup
# ══════════════════════════════════════════════════

@app.route("/api/org-info", methods=["GET"])
def org_info():
    """Public endpoint — check if a company slug exists."""
    slug = request.args.get("slug", "").strip()
    if not slug:
        return jsonify({"ok": False, "error": "slug required"})
    org = organizations_col.find_one({"slug": slug, "active": True}, {"name": 1, "slug": 1})
    if not org:
        return jsonify({"ok": False, "error": "Company not found"})
    return jsonify({"ok": True, "name": org["name"], "slug": org["slug"]})


# ══════════════════════════════════════════════════
#  RUN
# ══════════════════════════════════════════════════

if __name__ == "__main__":
    seed_super_admin()
    app.run(host="0.0.0.0", port=5000, debug=True)


# ══════════════════════════════════════════════════
#  EMPLOYEE SELF-REGISTRATION (via org slug)
# ══════════════════════════════════════════════════

@app.route("/api/accounts/create-self", methods=["POST"])
def create_account_self():
    """Employees can register themselves using their company's slug."""
    data     = request.json or {}
    slug     = data.get("org_slug", "").strip()
    name     = data.get("name", "").strip()
    emp_id   = data.get("emp_id", "").strip()
    mobile   = data.get("mobile", "").strip()
    password = data.get("password", "").strip()

    if not all([slug, name, emp_id, mobile, password]):
        return jsonify({"ok": False, "error": "All fields required"})
    if len(mobile) != 10 or not mobile.isdigit():
        return jsonify({"ok": False, "error": "Valid 10-digit mobile required"})
    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be 6+ characters"})

    org = organizations_col.find_one({"slug": slug, "active": True})
    if not org:
        return jsonify({"ok": False, "error": "Company not found"})

    org_id = str(org["_id"])
    if users_col.find_one({"mobile": mobile, "org_id": org_id}):
        return jsonify({"ok": False, "error": "Mobile already registered in this company"})
    if users_col.find_one({"emp_id": emp_id, "org_id": org_id}):
        return jsonify({"ok": False, "error": f"Employee ID '{emp_id}' already in use"})

    users_col.insert_one({
        "name": name, "emp_id": emp_id, "mobile": mobile,
        "password": hash_password(password), "role": "employee",
        "org_id": org_id, "created": datetime.now().strftime("%Y-%m-%d %H:%M")
    })
    return jsonify({"ok": True, "message": f"Account created! Login ."})
