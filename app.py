from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
import csv
from io import TextIOWrapper
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret')

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://baumdb_user:eKi9mdvkHzadxOiicwc2c3HX6wRbI3Uk@dpg-d249i5ili9vc73cgsso0-a/baumdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Tree(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(100), nullable=False)
    data = db.Column(db.JSON, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('start.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
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
 # ✅ Temporäre Datenbank-Reset-Route
@app.route('/reset-db')
@login_required
def reset_db():
    if current_user.username != 'admin':
        return "Zugriff verweigert", 403
    db.drop_all()
    db.create_all()
    return "Datenbank wurde zurückgesetzt."

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.username != 'admin':
        return redirect(url_for('index'))

    from werkzeug.utils import secure_filename
    users = User.query.all()

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form.get('username')

        if action == 'create':
            password = generate_password_hash(request.form.get('password'))
            if not User.query.filter_by(username=username).first():
                user = User(username=username, password=password)
                db.session.add(user)
                db.session.commit()
                flash('Benutzer erstellt.')
            else:
                flash('Benutzer existiert bereits.')

        elif action == 'delete':
            if username != 'admin':
                user = User.query.filter_by(username=username).first()
                Tree.query.filter_by(user_id=user.id).delete()
                db.session.delete(user)
                db.session.commit()
                flash('Benutzer gelöscht.')

        elif action == 'update_password':
            new_pw = generate_password_hash(request.form.get('password'))
            user = User.query.filter_by(username=username).first()
            user.password = new_pw
            db.session.commit()
            flash('Passwort aktualisiert.')

        elif action == 'upload_csv':
            file = request.files['csvfile']
            if file and username:
                user = User.query.filter_by(username=username).first()
                reader = csv.DictReader(TextIOWrapper(file, encoding='utf-8'))
                Tree.query.filter_by(user_id=user.id).delete()
                for row in reader:
                    tree = Tree(uid=row['UID'], data=row, user_id=user.id)
                    db.session.add(tree)
                db.session.commit()
                flash('CSV importiert.')

    return render_template('admin.html', users=users)

@app.route('/init-admin')
def init_admin():
    if User.query.filter_by(username='admin').first():
        return "Admin existiert bereits"
    admin = User(username='admin', password=generate_password_hash('admin123'))
    db.session.add(admin)
    db.session.commit()
    return "Admin wurde erstellt"
@app.route('/init-db')
def init_db():
    db.create_all()
    return "Datenbanktabellen erstellt"

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
