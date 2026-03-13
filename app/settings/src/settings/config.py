"""VirusTotal API configuration constants and defaults."""

import os

# --- VirusTotal API ---
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_BASE_URL = os.getenv("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3")
REQUEST_TIMEOUT = int(os.getenv("VT_REQUEST_TIMEOUT", "30"))

# --- Logging ---
LOG_FORMAT = os.getenv("LOG_FORMAT", "color")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
