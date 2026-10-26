"""
app.py
-------
Application entry point for SecureWatch.

Run with:
    python app.py

Before first run, initialize the database:
    python database/init_db.py

This file:
  - Creates the Flask app and loads Config.
  - Registers all blueprints (auth, dashboard, agent API, alert API).
  - Wires up the shared SQLite connection teardown.
  - Sets up application logging.
  - Adds friendly error handlers for 400/401/404/500.
"""

import os
from flask import Flask, jsonify, render_template
from flask_cors import CORS

from config import Config
from models.db import close_connection
from utils.logger import setup_logger
from utils.extensions import csrf, limiter

from routes.auth_routes import auth_bp
from routes.dashboard_routes import dashboard_bp
from routes.api_routes import api_bp
from routes.alert_routes import alert_bp
from routes.incident_routes import case_bp
from routes.detection_routes import detection_bp
from routes.agents_routes import agents_bp
from routes.hunt_routes import hunt_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Set up real logging (rotating file + console) BEFORE anything else
    # logs a message, so startup warnings are actually persisted to
    # logs/securewatch.log and not just printed via Flask's own incidental
    # default handler (which only goes to console/stderr).
    setup_logger(app)

    # Fail loudly (but not fatally) on insecure default secrets - now
    # reaches both the console and logs/securewatch.log.
    for warning in Config.validate():
        app.logger.warning("[SECURITY WARNING] %s", warning)

    # Allow the agent (which may run on a different host) to call the
    # /api/agent/* endpoints cross-origin. Dashboard routes stay
    # same-origin/session-based and are unaffected.
    CORS(app, resources={r"/api/agent/*": {"origins": "*"}})

    # --- Security extensions (Phase 1 upgrade) ---
    csrf.init_app(app)
    limiter.init_app(app)
    # The agent API authenticates machines via X-API-KEY, not a browser
    # session, so CSRF tokens don't apply there - exempt the whole blueprint.
    csrf.exempt(api_bp)

    # Close the per-request SQLite connection when the request ends.
    app.teardown_appcontext(close_connection)

    # --- Blueprints ---
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(case_bp)
    app.register_blueprint(detection_bp)
    app.register_blueprint(agents_bp)
    app.register_blueprint(hunt_bp)

    # --- Error handlers ---
    @app.errorhandler(400)
    def bad_request(e):
        if _wants_json():
            return jsonify({"error": "Bad request."}), 400
        return render_template("errors.html", code=400, message="Bad request."), 400

    @app.errorhandler(401)
    def unauthorized(e):
        if _wants_json():
            return jsonify({"error": "Unauthorized."}), 401
        return render_template("errors.html", code=401, message="Unauthorized."), 401

    @app.errorhandler(403)
    def forbidden(e):
        # Raised by utils/rbac.py's role_required when a viewer/analyst
        # attempts an action above their privilege level, and by Flask-WTF
        # on a missing/invalid CSRF token.
        if _wants_json():
            return jsonify({"error": "Forbidden - insufficient privileges."}), 403
        return render_template("errors.html", code=403, message="Forbidden - insufficient privileges."), 403

    @app.errorhandler(429)
    def rate_limited(e):
        # Raised by Flask-Limiter, e.g. too many login attempts.
        if _wants_json():
            return jsonify({"error": "Too many requests - please slow down."}), 429
        return render_template("errors.html", code=429, message="Too many attempts - please wait and try again."), 429

    @app.errorhandler(404)
    def not_found(e):
        if _wants_json():
            return jsonify({"error": "Resource not found."}), 404
        return render_template("errors.html", code=404, message="Page not found."), 404

    @app.errorhandler(500)
    def server_error(e):
        app.logger.error("Unhandled server error: %s", e)
        if _wants_json():
            return jsonify({"error": "Internal server error."}), 500
        return render_template("errors.html", code=500, message="Internal server error."), 500

    return app


def _wants_json():
    """Best-effort check: was this an API-style request that expects JSON back?"""
    from flask import request
    return request.path.startswith("/api/")


app = create_app()


if __name__ == "__main__":
    if not os.path.exists(app.config["DATABASE_PATH"]):
        print("!! Database not found. Run: python database/init_db.py")
    # debug=True is fine for a student project running locally;
    # set to False and use a real WSGI server for anything production-like.
    app.run(host="0.0.0.0", port=5000, debug=True)
