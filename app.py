import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, g, redirect, render_template, request, session, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["DATABASE"] = os.environ.get("DATABASE_PATH", "chat.db")
app.config["ADMIN_INVITE_KEY"] = os.environ.get("ADMIN_INVITE_KEY", "admin-invite-key")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            invited_email TEXT,
            used_by INTEGER,
            created_at TEXT NOT NULL,
            used_at TEXT,
            FOREIGN KEY (used_by) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.before_request
def load_user():
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            "SELECT id, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()


@app.route("/")
def home():
    if g.user:
        return redirect(url_for("chat"))
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        invite_code = request.form.get("invite_code", "").strip()

        if not email or "@" not in email:
            flash("Please enter a valid email address.")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("register.html")

        db = get_db()
        invite = db.execute(
            "SELECT id, invited_email, used_by FROM invites WHERE code = ?", (invite_code,)
        ).fetchone()

        if invite is None:
            flash("Invite code not found.")
            return render_template("register.html")

        if invite["used_by"] is not None:
            flash("Invite code has already been used.")
            return render_template("register.html")

        if invite["invited_email"] and invite["invited_email"].lower() != email:
            flash("This invite is tied to a different email.")
            return render_template("register.html")

        existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if existing:
            flash("This email is already registered.")
            return render_template("register.html")

        cursor = db.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, generate_password_hash(password), datetime.utcnow().isoformat()),
        )
        user_id = cursor.lastrowid

        db.execute(
            "UPDATE invites SET used_by = ?, used_at = ? WHERE id = ?",
            (user_id, datetime.utcnow().isoformat(), invite["id"]),
        )
        db.commit()

        session["user_id"] = user_id
        flash("Welcome! Your account is ready.")
        return redirect(url_for("chat"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = get_db().execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid credentials.")
            return render_template("login.html")

        session["user_id"] = user["id"]
        return redirect(url_for("chat"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    db = get_db()
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        if not body:
            flash("Message cannot be empty.")
        elif len(body) > 500:
            flash("Message must be 500 characters or less.")
        else:
            db.execute(
                "INSERT INTO messages (user_id, body, created_at) VALUES (?, ?, ?)",
                (g.user["id"], body, datetime.utcnow().isoformat()),
            )
            db.commit()
            return redirect(url_for("chat"))

    messages = db.execute(
        """
        SELECT m.body, m.created_at, u.email
        FROM messages m
        JOIN users u ON u.id = m.user_id
        ORDER BY m.id DESC
        LIMIT 50
        """
    ).fetchall()
    return render_template("chat.html", messages=messages)


@app.route("/admin/invite", methods=["GET", "POST"])
def admin_invite():
    generated_code = None
    if request.method == "POST":
        admin_key = request.form.get("admin_key", "")
        invited_email = request.form.get("invited_email", "").strip().lower() or None

        if admin_key != app.config["ADMIN_INVITE_KEY"]:
            flash("Invalid admin key.")
        elif invited_email and "@" not in invited_email:
            flash("Invited email must be valid, or blank for open invite.")
        else:
            code = secrets.token_urlsafe(12)
            get_db().execute(
                "INSERT INTO invites (code, invited_email, created_at) VALUES (?, ?, ?)",
                (code, invited_email, datetime.utcnow().isoformat()),
            )
            get_db().commit()
            generated_code = code

    invites = get_db().execute(
        """
        SELECT code, invited_email, created_at, used_at, used_by
        FROM invites
        ORDER BY id DESC
        LIMIT 25
        """
    ).fetchall()

    return render_template("admin_invite.html", generated_code=generated_code, invites=invites)


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
