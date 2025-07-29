
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'dein-geheimer-schluessel'

DB_PATH = 'baeume.db'

USERS = {
    'admin': 'passwort123',
    'demo': 'demo'
}

@app.route('/')
def index():
    return redirect(url_for('start'))

@app.route('/start')
def start():
    return render_template('start.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        benutzer = request.form['username']
        passwort = request.form['password']
        if benutzer in USERS and USERS[benutzer] == passwort:
            session['user'] = benutzer
            return redirect(url_for('baum_suche'))
        else:
            return render_template('login.html', fehler='Login fehlgeschlagen')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('start'))

@app.route('/suche', methods=['GET', 'POST'])
def baum_suche():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        uid = request.form['uid']
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM imported_data WHERE UID = ?", (uid,))
        baum = cursor.fetchone()
        conn.close()
        if baum:
            return render_template('baum_ergebnis.html', baum=baum)
        else:
            return render_template('baum_suche.html', fehler="Keine Daten gefunden.")
    return render_template('baum_suche.html')
