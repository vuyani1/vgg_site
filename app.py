from flask import Flask, render_template, request, session, redirect, url_for, jsonify, flash
import mysql.connector, hashlib, os, re, uuid, datetime, requests
from flask_babel import Babel, _

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = os.urandom(24)
babel = Babel(app)
LANG = {
    'en': '🇬🇧 English','af': '🇿🇦 Afrikaans','zu': '🇿🇦 Zulu','sw': '🇰🇪 Swahili',
    'ar':'🇸🇦 العربية','fr':'🇫🇷 Français','es':'🇪🇸 Español','zh':'🇨🇳 中文',
    'hi':'🇮🇳 हिंदी','pt':'🇵🇹 Português'
}

DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS'),
    'database': os.getenv('DB_NAME')
}

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

def clean(s): return re.sub(r'[^a-zA-Z0-9]', '', s or '')

def hashp(p): return hashlib.sha256(p.encode()).hexdigest()

def geo(ip):
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}').json()
        return r.get('country'), r.get('regionName')
    except:
        return None, None

@babel.localeselector
def get_locale():
    return session.get('lang', request.accept_languages.best_match(LANG.keys()))

@app.route('/lang/<lang>')
def set_lang(lang):
    session['lang'] = lang
    return redirect(request.referrer or '/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = clean(request.form.get('username'))
        pw = clean(request.form.get('password'))
        nm = clean(request.form.get('name', ''))
        action = request.form.get('action')

        if action == 'register':
            if not u or not pw or not nm:
                flash(_('Missing fields')); return redirect('/login')
            db = get_db(); cur = db.cursor()
            try:
                cur.execute("INSERT INTO users (username,password,name) VALUES (%s,%s,%s)", (u, hashp(pw), nm))
                db.commit()
            except mysql.connector.IntegrityError:
                flash(_('User already exists')); return redirect('/login')

        db = get_db(); cur = db.cursor()
        cur.execute("SELECT id, banned FROM users WHERE username=%s AND password=%s", (u, hashp(pw)))
        row = cur.fetchone()
        if not row:
            flash(_('Invalid credentials')); return redirect('/login')
        uid, banned = row
        if banned:
            flash(_('Account banned')); return redirect('/login')

        session['user_id'] = uid
        if u == 'vilakazi2233':
            session['admin'] = True
            return redirect('/admin')

        sid = uuid.uuid4().hex
        ip = request.remote_addr
        country, region = geo(ip)
        cur.execute(
          "INSERT INTO logins (session_id,user_id,login_at,ip,country,region) VALUES (%s,%s,%s,%s,%s,%s)",
          (sid, uid, datetime.datetime.utcnow(), ip, country, region)
        ); db.commit()
        session['sid'] = sid
        return redirect('/dashboard')

    return render_template('login.html', logo='vgg.png', LANG=LANG)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    db = get_db(); cur = db.cursor(dictionary=True)
    cur.execute("SELECT username,name FROM users WHERE id=%s", (session['user_id'],))
    user = cur.fetchone()
    return render_template('dashboard.html', user=user, LANG=LANG, logo='vgg.png')

@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if clean(request.form.get('username')) == 'vilakazi2233' and request.form.get('password') == 'brute22force33isqwer':
            session['admin'] = True
            return redirect('/control')
        flash(_('Invalid admin credentials')); return redirect('/admin')
    return render_template('admin_login.html', logo='vgg.png', LANG=LANG)

@app.route('/control', methods=['GET','POST'])
def control_center():
    if not session.get('admin'):
        return redirect('/admin')
    db = get_db(); cur = db.cursor(dictionary=True)
    if request.method == 'POST':
        action = request.form.get('action')
        val = clean(request.form.get('value'))
        if action == 'ban':
            cur.execute("UPDATE users SET banned=1 WHERE username=%s", (val,))
        elif action == 'unban':
            cur.execute("UPDATE users SET banned=0 WHERE username=%s", (val,))
        elif action == 'blockip':
            cur.execute("INSERT IGNORE INTO blocked_ips (ip) VALUES(%s)", (val,))
        elif action == 'delete':
            cur.execute("DELETE FROM users WHERE username=%s", (val,))
        db.commit()
        flash(_('Action completed')); return redirect('/control')
    cur.execute("SELECT * FROM help_tickets")
    tickets = cur.fetchall()
    return render_template('admin_center.html', tickets=tickets, LANG=LANG, logo='vgg.png')

@app.route('/appeal', methods=['GET','POST'])
def appeal():
    if request.method == 'POST':
        un = clean(request.form.get('username'))
        msg = request.form.get('message', '')
        db = get_db(); cur = db.cursor()
        cur.execute("INSERT INTO appeals (username,message) VALUES (%s,%s)", (un, msg))
        db.commit()
        flash(_('Appeal submitted'))
    return render_template('appeal.html', LANG=LANG, logo='vgg.png')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
