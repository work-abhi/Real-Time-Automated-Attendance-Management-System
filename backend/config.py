import os

# MongoDB connection URL
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")

# Flask secret key
SECRET_KEY = os.environ.get("SECRET_KEY", "smartattendance_saas_secret_2024")

# Default fallback values (overridden per-org from DB)
DEFAULT_OFFICE_LAT      = float(os.environ.get("OFFICE_LAT",    "28.626001"))
DEFAULT_OFFICE_LNG      = float(os.environ.get("OFFICE_LNG",    "77.378001"))
DEFAULT_OFFICE_RADIUS_M = float(os.environ.get("OFFICE_RADIUS", "82"))
DEFAULT_OFFICE_IP   = os.environ.get("OFFICE_IP", "49.xx.xx.xx")
