"""
config.py
----------
Central configuration for SecureWatch.

All tunable values live here so the rest of the codebase never hardcodes
secrets, paths, or thresholds. Values are read from environment variables
(via a .env file if present) with sane defaults for local development.

To override in production, create a `.env` file next to this file, e.g.:

    SECRET_KEY=replace-this-with-a-long-random-string
    ADMIN_USERNAME=admin
    ADMIN_PASSWORD=ChangeMe123!
    VT_API_KEY=your_virustotal_api_key_here
    AGENT_API_KEY=shared-secret-between-server-and-agents
"""

import os
from dotenv import load_dotenv

# Load variables from a .env file if one exists in the project root
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# --- RBAC roles (Phase 1 upgrade) ---
# Three roles, ascending privilege. Kept as a plain list (not a DB-enforced
# enum) so SQLite doesn't need a migration - utils/rbac.py is the source of
# truth and validates against this list at the application layer.
ROLE_VIEWER = "viewer"      # read-only: dashboard, logs, alerts, reports
ROLE_ANALYST = "analyst"    # + acknowledge/close alerts, run searches, add notes
ROLE_ADMIN = "admin"        # + manage users, tune detection rules, all settings
ALL_ROLES = (ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN)


class Config:
    # --- Flask core ---
    # Secret key used to sign session cookies. MUST be overridden in production.
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure-secret-key-change-me")

    # --- Database ---
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH", os.path.join(BASE_DIR, "database", "securewatch.db")
    )
    SCHEMA_PATH = os.path.join(BASE_DIR, "database", "schema.sql")

    # --- Admin credentials (used only to seed the first admin user) ---
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@123")

    # --- Agent authentication ---
    # Simple shared-secret API key that endpoint agents must send in the
    # `X-API-KEY` header on every request. In a larger system this would be
    # replaced by per-agent tokens issued at enrollment time.
    AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "securewatch-agent-key")

    # --- VirusTotal (optional) ---
    # If left blank, malware-hash detection rule is skipped gracefully.
    VT_API_KEY = os.environ.get("VT_API_KEY", "")
    VT_API_URL = "https://www.virustotal.com/api/v3/files/"

    # --- Session ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8  # 8 hours

    # --- Detection thresholds (tunable without touching detection code) ---
    FAILED_LOGIN_THRESHOLD = int(os.environ.get("FAILED_LOGIN_THRESHOLD", 5))
    FAILED_LOGIN_WINDOW_MINUTES = int(os.environ.get("FAILED_LOGIN_WINDOW_MINUTES", 10))

    PORT_SCAN_UNIQUE_PORT_THRESHOLD = int(os.environ.get("PORT_SCAN_UNIQUE_PORT_THRESHOLD", 15))
    PORT_SCAN_WINDOW_MINUTES = int(os.environ.get("PORT_SCAN_WINDOW_MINUTES", 2))

    # Suspicious PowerShell keywords/flags (case-insensitive substring match)
    SUSPICIOUS_POWERSHELL_KEYWORDS = [
        "-enc", "-encodedcommand", "-nop", "-noprofile", "downloadstring",
        "invoke-expression", "iex ", "bypass", "hidden", "-w hidden",
        "frombase64string", "net.webclient", "invoke-mimikatz",
    ]

    # Static blacklist of known-bad IPs for offline demo purposes.
    # In production this could be pulled from a live threat-intel feed.
    BLACKLISTED_IPS_PATH = os.path.join(BASE_DIR, "database", "blacklisted_ips.txt")

    # --- Logging ---
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    APP_LOG_FILE = os.path.join(LOG_DIR, "securewatch.log")

    # --- Pagination ---
    DEFAULT_PAGE_SIZE = 25
    MAX_PAGE_SIZE = 200

    # --- CSRF (Flask-WTF) ---
    # Session-authenticated browser requests (login form, alert ack/close
    # fetch calls) are protected. The agent API (/api/agent/*) is exempted
    # in app.py because agents authenticate with X-API-KEY, not a session -
    # CSRF tokens are meaningless for machine-to-machine calls.
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # tokens tied to session lifetime, not a fixed timeout

    # --- Rate limiting (Flask-Limiter) ---
    # Storage backend for limiter counters. In-memory is fine for a single
    # instance; swap to redis:// in production behind a load balancer.
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = "200 per minute"
    LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "10 per minute")

    # --- RBAC ---
    DEFAULT_NEW_USER_ROLE = ROLE_VIEWER

    @classmethod
    def validate(cls):
        """
        Fail loudly at startup instead of silently running insecurely.
        Called once from app.py's create_app(). Warnings (not hard failures)
        for dev-friendliness, since this project still needs to run out of
        the box for coursework demos.
        """
        warnings = []
        if cls.SECRET_KEY == "dev-insecure-secret-key-change-me":
            warnings.append("SECRET_KEY is using the insecure default - set it in .env before deploying.")
        if cls.ADMIN_PASSWORD == "Admin@123":
            warnings.append("ADMIN_PASSWORD is using the default value - change it after first login.")
        if cls.AGENT_API_KEY == "securewatch-agent-key":
            warnings.append("AGENT_API_KEY is using the default value - change it before exposing the server.")
        return warnings


class DevelopmentConfig(Config):
    """Local/coursework use: verbose errors, permissive defaults."""
    DEBUG = True
    ENV = "development"


class ProductionConfig(Config):
    """Deployed use: stricter session/cookie behavior."""
    DEBUG = False
    ENV = "production"
    SESSION_COOKIE_SECURE = True  # requires HTTPS - only enable once TLS is in place


class TestingConfig(Config):
    """Used by the test suite (Phase 10) - isolated in-memory-style DB path."""
    TESTING = True
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "test_securewatch.db")


# Select config class from FLASK_ENV (defaults to development for zero-config demos)
CONFIG_MAP = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "development").lower()
    return CONFIG_MAP.get(env, DevelopmentConfig)
