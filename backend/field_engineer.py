from datetime import datetime
from datetime import datetime
from flask import request, jsonify

from database import field_attendance_col



def _require_login(role=None):
    """Avoid circular import by importing require_login at runtime."""
    from app import require_login as rl
    return rl(role=role)





def reverse_geocode_place(lat: float, lng: float) -> dict:
    """Client does reverse-geocode; backend just receives place label.

    Keep function for future server-side fallback.
    """
    return {}


def handle_field_engineer_attendance():
    """API handler for marking field engineer attendance with location."""
    user, err = _require_login(role="employee")
    if err:
        return err


    data = request.json or {}
    lat = data.get("lat")
    lng = data.get("lng")
    accuracy = data.get("accuracy", 0)
    place = (data.get("place") or "Unknown").strip()
    city = (data.get("city") or "").strip()
    state = (data.get("state") or "").strip()
    full_address = (data.get("full_address") or "").strip()
    visit_type = (data.get("visit_type") or "Field Engineering").strip()

    if lat is None or lng is None:
        return jsonify({"ok": False, "error": "GPS coordinates not found"})

    emp_id = user.get("emp_id")
    name = user.get("name")
    org_id = user.get("org_id")

    if not org_id:
        return jsonify({"ok": False, "error": "Organization not found"})

    today = datetime.now().strftime("%Y-%m-%d")
    now_time = datetime.now().strftime("%H:%M:%S")

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ip = (ip or "").split(",")[0].strip()

    field_attendance_col.insert_one({
        "org_id": org_id,

        "emp_id": emp_id,
        "name": name,
        "date": today,
        "in_time": now_time,
        "out_time": None,
        "status": "Present",
        "method": "FieldEngineering",
        "method_out": None,
        "ip": ip,
        "ip_out": None,
        "visit_type": visit_type,
        "lat": lat,
        "lng": lng,
        "accuracy": accuracy,
        "place": place,
        "city": city,
        "state": state,
        "full_address": full_address,
        "attendance_type": "Field",
    })

    place_label = place + (", " + city if city else "")
    return jsonify({
        "ok": True,
        "status": "field_engineer_marked",
        "time": now_time,
        "place": place_label,
        "message": f"✓ {visit_type} marked! {place_label} • {now_time}",
    })

