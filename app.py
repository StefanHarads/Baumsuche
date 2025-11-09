# app.py
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_file, current_app
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import UniqueConstraint
import os
import csv
import io
import logging

# 🔊 Logging
logging.basicConfig(level=logging.DEBUG)

# ──────────────────────────────────────────────────────────────
# Flask- & DB-Setup
# ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret")

# Render-Kompatibilität: postgres:// → postgresql+psycopg2://
uri = os.getenv("DATABASE_URL", "sqlite:///local.db")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql+psycopg2://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = uri
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# ──────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)


class Tree(db.Model):
    __tablename__ = "tree"   # 👈 Beibehaltung des alten Tabellennamens!
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(100), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "uid", name="uq_tree_user_uid"),
    )


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ──────────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────────
def _normalize_header(name: str) -> str:
    return (name or "").replace("\ufeff", "").strip().lower()

# ──────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("start.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            if user.username == "admin":
                return redirect(url_for("admin"))
            return redirect(url_for("baum_suche"))
        return render_template("login.html", fehler="Login fehlgeschlagen.")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/suche", methods=["GET", "POST"])
@login_required
def baum_suche():
    if request.method == "POST":
        uid = request.form["uid"].strip()
        tree = Tree.query.filter_by(uid=uid, user_id=current_user.id).first()
        if tree:
            return render_template("baum_ergebnis.html", baum=tree.data)
        return render_template("baum_suche.html", fehler="UID nicht gefunden.")
    return render_template("baum_suche.html")


@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if current_user.username != "admin":
        return redirect(url_for("index"))

    users = User.query.all()

    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username")

        # Benutzerverwaltung
        if action == "create":
            password = generate_password_hash(request.form.get("password"))
            if not User.query.filter_by(username=username).first():
                db.session.add(User(username=username, password=password))
                db.session.commit()
                flash("Benutzer erstellt.")
            else:
                flash("Benutzer existiert bereits.")

        elif action == "delete":
            if username != "admin":
                user = User.query.filter_by(username=username).first()
                if user:
                    Tree.query.filter_by(user_id=user.id).delete()
                    db.session.delete(user)
                    db.session.commit()
                    flash("Benutzer gelöscht.")

        elif action == "update_password":
            new_pw = generate_password_hash(request.form.get("password"))
            user = User.query.filter_by(username=username).first()
            if user:
                user.password = new_pw
                db.session.commit()
                flash("Passwort aktualisiert.")

        # CSV-Upload
        elif action == "upload_csv":
            file = request.files.get("csvfile")
            if not file:
                flash("Keine Datei übermittelt.", "error")
                return render_template("admin.html", users=users)

            if not username:
                flash("Kein Benutzer ausgewählt.", "error")
                return render_template("admin.html", users=users)

            user = User.query.filter_by(username=username).first()
            if not user:
                flash("Benutzer nicht gefunden.", "error")
                return render_template("admin.html", users=users)

            try:
                # 1) Datei lesen & Encoding erkennen
                raw = file.read()
                try:
                    text = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    text = None
                    for enc in ("cp1252", "latin-1"):
                        try:
                            text = raw.decode(enc)
                            break
                        except UnicodeDecodeError:
                            continue
                    if text is None:
                        flash("Kodierung unbekannt. Bitte als UTF-8 exportieren.", "error")
                        return render_template("admin.html", users=users)

                # 2) Delimiter erkennen
                try:
                    sample = text[:4096]
                    dialect = csv.Sniffer().sniff(sample, delimiters=";, \t")
                    delimiter = dialect.delimiter
                except Exception:
                    delimiter = ";"

                sio = io.StringIO(text, newline="")
                reader = csv.DictReader(sio, delimiter=delimiter)

                if not reader.fieldnames:
                    flash("Keine Kopfzeile in der CSV gefunden.", "error")
                    return render_template("admin.html", users=users)

                original_headers = reader.fieldnames
                header_map = {_normalize_header(h): h for h in original_headers}

                # UID-Spalte finden
                actual_uid_key = header_map.get("uid")
                if not actual_uid_key:
                    for alt in ("baumid", "id", "tree_uid"):
                        if alt in header_map:
                            actual_uid_key = header_map[alt]
                            break
                if not actual_uid_key:
                    flash(f"Spalte 'UID' nicht gefunden. Erkannte Spalten: {original_headers}", "error")
                    return render_template("admin.html", users=users)

                # 3) Import / Upsert
                imported, updated, skipped = 0, 0, 0
                for row in reader:
                    uid_value = (row.get(actual_uid_key) or "").strip()
                    if not uid_value:
                        skipped += 1
                        continue

                    existing = Tree.query.filter_by(user_id=user.id, uid=uid_value).first()
                    if existing:
                        existing.data = row
                        updated += 1
                    else:
                        db.session.add(Tree(uid=uid_value, data=row, user_id=user.id))
                        imported += 1

                db.session.commit()
                flash(f"CSV importiert. Neu: {imported}, aktualisiert: {updated}, übersprungen: {skipped}.", "success")

            except Exception as e:
                current_app.logger.exception("CSV-Verarbeitung fehlgeschlagen")
                db.session.rollback()
                flash(f"CSV-Fehler: {e}", "error")

    return render_template("admin.html", users=users)


@app.route("/init-admin")
def init_admin():
    if User.query.filter_by(username="admin").first():
        return "Admin existiert bereits"
    try:
        hashed_pw = generate_password_hash("admin123")
        db.session.add(User(username="admin", password=hashed_pw))
        db.session.commit()
        return "Admin wurde erstellt"
    except Exception as e:
        return f"Fehler beim Admin-Setup: {e}"


@app.route("/db-check")
def db_check():
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    if uri.startswith("postgresql"):
        typ = "PostgreSQL"
    elif uri.startswith("sqlite"):
        typ = "SQLite"
    else:
        typ = "Unbekannt"
    return f"Datenbanktyp: {typ}"

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
