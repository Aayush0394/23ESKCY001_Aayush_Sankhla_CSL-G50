"""
Two-Factor Authentication (TOTP) Login System
Project Code: CSL-G50
Student: Aayush Sankhla | Roll No: 23ESKCY001
Cyber Security Lab (7CS4-22) | SKIT Jaipur

Features:
- User registration & login with hashed passwords (Werkzeug)
- TOTP-based 2FA compatible with Google Authenticator / Authy
- QR code provisioning
- One-time backup/recovery codes (hashed storage)
- Session management
"""

import os
import secrets
import hashlib
import base64
from io import BytesIO
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# In-memory store for demo (replace with DB in production)
# Structure: username -> {password_hash, otp_secret, otp_enabled, backup_codes (list of hashes), created_at}
users = {}

# ---------- Helpers ----------

def generate_backup_codes(count=8):
    """Generate human-readable one-time backup codes."""
    codes = []
    for _ in range(count):
        # 8-char alphanumeric, easy to type
        code = secrets.token_hex(4).upper()  # e.g. A1B2C3D4
        codes.append(code)
    return codes


def hash_code(code: str) -> str:
    """SHA-256 hash of a backup code."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def verify_backup_code(user, code: str) -> bool:
    """Verify and consume a backup code (one-time use)."""
    code_hash = hash_code(code.strip().upper())
    if code_hash in user["backup_codes"]:
        user["backup_codes"].remove(code_hash)
        return True
    return False


def get_qr_base64(secret: str, username: str, issuer: str = "SKIT-CSL-G50") -> str:
    """Generate QR code as base64 data URI for embedding in HTML."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer)
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode("utf-8")


def current_user():
    """Return the logged-in user dict or None."""
    username = session.get("user")
    if username and username in users:
        return users[username]
    return None


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ---------- Routes ----------

@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")

        if username in users:
            flash("Username already exists.", "danger")
            return render_template("register.html")

        users[username] = {
            "password_hash": generate_password_hash(password),
            "otp_secret": None,
            "otp_enabled": False,
            "backup_codes": [],
            "created_at": datetime.now().isoformat()
        }
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        user = users.get(username)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        # Password OK – check if 2FA is enabled
        if user["otp_enabled"]:
            session["pending_2fa"] = username
            return redirect(url_for("verify_2fa"))
        else:
            session["user"] = username
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    username = session.get("pending_2fa")
    if not username or username not in users:
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    user = users[username]

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        use_backup = request.form.get("use_backup") == "on"

        if use_backup:
            if verify_backup_code(user, code):
                session.pop("pending_2fa", None)
                session["user"] = username
                flash("Login successful using backup code! (Code consumed)", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid or already used backup code.", "danger")
        else:
            # TOTP verification
            if user["otp_secret"]:
                totp = pyotp.TOTP(user["otp_secret"])
                if totp.verify(code, valid_window=1):  # allow ±30s drift
                    session.pop("pending_2fa", None)
                    session["user"] = username
                    flash("2FA verification successful!", "success")
                    return redirect(url_for("dashboard"))
            flash("Invalid TOTP code. Please try again.", "danger")

    return render_template("verify_2fa.html", username=username)


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    return render_template("dashboard.html", username=session["user"], user=user)


@app.route("/enable-2fa", methods=["GET", "POST"])
@login_required
def enable_2fa():
    username = session["user"]
    user = users[username]

    if user["otp_enabled"]:
        flash("2FA is already enabled.", "info")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # Confirm setup with a valid TOTP
        code = request.form.get("code", "").strip()
        secret = session.get("pending_secret")
        if not secret:
            flash("Session expired. Please try again.", "warning")
            return redirect(url_for("enable_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            # Generate backup codes
            plain_codes = generate_backup_codes(8)
            hashed = [hash_code(c) for c in plain_codes]

            user["otp_secret"] = secret
            user["otp_enabled"] = True
            user["backup_codes"] = hashed
            session.pop("pending_secret", None)

            # Show backup codes once
            session["show_backup_codes"] = plain_codes
            flash("Two-Factor Authentication enabled successfully!", "success")
            return redirect(url_for("show_backup_codes"))
        else:
            flash("Invalid code. Please scan the QR again and enter a fresh code.", "danger")

    # Generate new secret for setup
    secret = pyotp.random_base32()
    session["pending_secret"] = secret
    qr_b64 = get_qr_base64(secret, username)
    return render_template("enable_2fa.html", qr_b64=qr_b64, secret=secret, username=username)


@app.route("/show-backup-codes")
@login_required
def show_backup_codes():
    codes = session.pop("show_backup_codes", None)
    if not codes:
        flash("No backup codes to show.", "warning")
        return redirect(url_for("dashboard"))
    return render_template("backup_codes.html", codes=codes)


@app.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    username = session["user"]
    user = users[username]
    user["otp_enabled"] = False
    user["otp_secret"] = None
    user["backup_codes"] = []
    flash("Two-Factor Authentication has been disabled.", "info")
    return redirect(url_for("dashboard"))


@app.route("/regenerate-backup", methods=["POST"])
@login_required
def regenerate_backup():
    username = session["user"]
    user = users[username]
    if not user["otp_enabled"]:
        flash("Enable 2FA first.", "warning")
        return redirect(url_for("dashboard"))

    plain_codes = generate_backup_codes(8)
    user["backup_codes"] = [hash_code(c) for c in plain_codes]
    session["show_backup_codes"] = plain_codes
    flash("New backup codes generated. Old ones are invalidated.", "success")
    return redirect(url_for("show_backup_codes"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------- Run ----------
if __name__ == "__main__":
    # Pre-create a demo user for easy testing (password: demo123)
    if "demo" not in users:
        users["demo"] = {
            "password_hash": generate_password_hash("demo123"),
            "otp_secret": None,
            "otp_enabled": False,
            "backup_codes": [],
            "created_at": datetime.now().isoformat()
        }
        print("Demo user created → username: demo  |  password: demo123")

    print("\n=== TOTP 2FA Login System (CSL-G50) ===")
    print("Open http://127.0.0.1:5000 in your browser")
    print("Register a new account or use demo/demo123\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
