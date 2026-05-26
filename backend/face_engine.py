import face_recognition
import numpy as np
import cv2
import base64
from database import employees_col


def _load_known(org_id: str = None):
    """Load face encodings — scoped to org if org_id provided."""
    query = {}
    if org_id:
        query["org_id"] = org_id
    docs = list(employees_col.find(query, {"emp_id": 1, "name": 1, "encoding": 1}))
    known_encs, known_names, known_ids = [], [], []
    for d in docs:
        enc = d.get("encoding")
        if enc:
            known_encs.append(np.array(enc))
            known_names.append(d["name"])
            known_ids.append(d["emp_id"])
    return known_encs, known_names, known_ids


def encode_face_from_b64(image_b64: str):
    """
    Accept base64 image from browser webcam.
    Returns (encoding_list, error_string)
    """
    try:
        img_bytes = base64.b64decode(image_b64.split(",")[-1])
        np_arr    = np.frombuffer(img_bytes, np.uint8)
        frame     = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        rgb       = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        locs      = face_recognition.face_locations(rgb, model="hog")
        if not locs:
            return None, " See on Camera "
        encs = face_recognition.face_encodings(rgb, locs)
        if not encs:
            return None, "Face encoding fail —Try again"
        return encs[0].tolist(), None
    except Exception as e:
        return None, str(e)


def recognize_face_from_b64(image_b64: str, tolerance: float = 0.5, org_id: str = None):
    """
    Match face from b64 image against registered employees.
    org_id scopes the search to one company only.
    Returns list of dicts: [{emp_id, name, distance}]
    """
    try:
        img_bytes = base64.b64decode(image_b64.split(",")[-1])
        np_arr    = np.frombuffer(img_bytes, np.uint8)
        frame     = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        rgb       = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        locs = face_recognition.face_locations(rgb, model="hog")
        encs = face_recognition.face_encodings(rgb, locs)

        known_encs, known_names, known_ids = _load_known(org_id=org_id)
        results = []

        for enc in encs:
            if not known_encs:
                results.append({"emp_id": "Unknown", "name": "Unknown", "distance": 1.0})
                continue
            dists = face_recognition.face_distance(known_encs, enc)
            best  = int(np.argmin(dists))
            if dists[best] < tolerance:
                results.append({
                    "emp_id":   known_ids[best],
                    "name":     known_names[best],
                    "distance": float(dists[best])
                })
            else:
                results.append({"emp_id": "Unknown", "name": "Unknown", "distance": float(dists[best])})

        return results, None
    except Exception as e:
        return [], str(e)
