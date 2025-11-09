# app.py
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, current_app, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import text, UniqueConstraint
import os
import csv
import io
import logging

# 🔊 Logging
logging.basicConfig(level=logging.DEBUG)

# ──────────────────────────────────────────────────────────────────────────────
# Flask & DB Setup
# ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# ──────────────────────────────────────────────────────────────────────────────
# Models
# ──────────────────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False)

class Tree(db.Model):
    __tablename__ = 'trees'
    id      = db.Column(db.Integer, primary_key=True)
    uid     = db.Column(db.String(100), nullable=False)
    data    = db.Column(db.JSON, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    # DB-seitige Duplikatvermeidung: pro Nutzer darf eine UID nur einmal existieren
    __table_args__ = (
        UniqueConstraint('user_id', 'uid', name='uq_tree_user_uid'),
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ──────────────────────────────────────────────────────────────────────────────
# Utils
# ──────────────────────────────────────────────────────────────────────────────
def _normalize_header(name: str) -> str:
    """ Entfernt BOM/Whitespace und normalisiert auf lowercase. """
    return (name or "").replace("\ufeff", "").strip().lower()

# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('start.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            if user.username == 'admin':
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('baum_suche'))
        else:
            return render_template('login.html', fehler='Login fehlgeschlagen.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/suche', methods=['GET', 'POST'])
@login_required
def baum_suche():
    if request.method == 'POST':
        uid = request.form['uid']
        tree = Tree.query.filter_by(uid=uid, user_id=current_user.id).first()
        if tree:
            return render_template('baum_ergebnis.html', baum=tree.data)
        else:
            return render_template('baum_suche.html', fehler='UID nicht gefunden.')
    return render_template('baum_suche.html')

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.username != 'admin':
        return redirect(url_for('index'))

    from werkzeug.utils import secure_filename
    users = User.query.all()

    if request.method == 'POST':
        action   = request.form.get('action')
        username = request.form.get('username')

        if action == 'create':
            password = generate_password_hash(request.form.get('password'))
            if not User.query.filter_by(username=username).first():
                user = User(username=username, password=password)
                db.session.add(user)
                db.session.commit()
                flash('Benutzer erstellt.')
            else
