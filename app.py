import sqlite3
import pyotp
from flask import Flask, render_template, request, redirect, url_for, flash
import qrcode
import random
import smtplib
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import pyzbar.pyzbar as pyzbar
from PIL import Image
import requests
import time

def db_shuru():
    conn = sqlite3.connect('sessions.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            otp TEXT,
            expiry TEXT,
            status TEXT,
            created_at TEXT
        )
    ''')
    conn.commit()
    conn.close()

def scan_logs_shuru():
    conn = sqlite3.connect('sessions.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            scan_time TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    conn.close()

db_shuru()
scan_logs_shuru()

app = Flask(__name__)

with open('secret.key', 'rb') as key_file:
    key = key_file.read()
f = Fernet(key)

DEPLOYMENT_URL = 'https://qr-otp-project.onrender.com/'

EMAIL_ADDRESS = 'mayanktanwar2022@gmail.com'
EMAIL_PASSWORD = 'gxzu pvgz mpjp ofbs'

SAFE_BROWSING_API_KEY = 'AIzaSyBsO1ix17GKlERDqujEy-ZX54_4SI7-KRo'
SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + SAFE_BROWSING_API_KEY

URLSCAN_API_KEY = '0197da5d-6852-74fe-a72e-713b6c37259e'
URLSCAN_API_URL = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT_URL = 'https://urlscan.io/api/v1/result/'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    user_email = request.form['email']
    session_id = str(random.randint(100000, 999999))
    otp = str(random.randint(1000, 9999))
    expiry = datetime.now() + timedelta(minutes=5)

    conn = sqlite3.connect('sessions.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO sessions (session_id, otp, expiry, status, created_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (session_id, otp, expiry.strftime("%Y-%m-%d %H:%M:%S"), 'pending', datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    send_email(user_email, otp)
    encrypted_id = f.encrypt(session_id.encode()).decode()
    data = request.url_root + 'verify?sid=' + encrypted_id
    qr = qrcode.make(data)
    qr_path = f'static/qrs/{session_id}.png'
    qr.save(qr_path)

    return render_template('index.html', qr_path=qr_path)

@app.route('/totp-setup')
def totp_setup():
    totp_secret = pyotp.random_base32()
    print("Your secret key for Google Authenticator:", totp_secret)

    uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name="MayankQRProject", issuer_name="CyberSecurityDemo")
    qr = qrcode.make(uri)
    qr_path = 'static/qrs/totp_setup.png'
    qr.save(qr_path)

    return render_template('totp_setup.html', qr_path=qr_path, secret=totp_secret)

@app.route('/totp-verify', methods=['GET', 'POST'])
def totp_verify():
    totp_secret = "N2TMZ4ZGVLBMXLTY3YTDRVTOU3JHUI4X"  
    totp = pyotp.TOTP(totp_secret)

    if request.method == 'POST':
        user_otp = request.form['otp']
        if totp.verify(user_otp):
            return '<h1 style="color:green;">✅ OTP Verified Successfully!</h1><a href="/">Go Home</a>'
        else:
            return '<h1 style="color:red;">❌ Invalid OTP.</h1><a href="/totp-verify">Try Again</a>'

    return '''
        <h1>TOTP Verification 🔑</h1>
        <form method="POST">
            <input type="text" name="otp" placeholder="Enter OTP">
            <button type="submit">Verify</button>
        </form>
    '''

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'GET':
        encrypted_id = request.args.get('sid')
        if not encrypted_id:
            return "Missing or invalid link."
        try:
            session_id = f.decrypt(encrypted_id.encode()).decode()
        except Exception:
            return "Invalid or tampered link."
        conn = sqlite3.connect('sessions.db')
        c = conn.cursor()
        c.execute("SELECT session_id, otp, expiry, status, created_at FROM sessions WHERE session_id=?", (session_id,))
        result = c.fetchone()
        if result:
            expiry_str = result[2]
            expiry_time = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expiry_time:
                c.execute('''INSERT INTO scan_logs (email, scan_time, status) VALUES (?, ?, ?)''', (None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'expired'))
                conn.commit()
                conn.close()
                return render_template('expired.html')
            conn.close()
            return render_template('verify.html', session_id=encrypted_id)
        else:
            conn.close()
            return "Invalid or expired session."
    elif request.method == 'POST':
        encrypted_id = request.form['session_id']
        try:
            session_id = f.decrypt(encrypted_id.encode()).decode()
        except Exception:
            return "Invalid or tampered link."
        otp_input = request.form['otp']
        conn = sqlite3.connect('sessions.db')
        c = conn.cursor()
        c.execute("SELECT session_id, otp, expiry, status, created_at FROM sessions WHERE session_id=?", (session_id,))
        result = c.fetchone()
        if result:
            expiry_str = result[2]
            expiry_time = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expiry_time:
                c.execute('''INSERT INTO scan_logs (email, scan_time, status) VALUES (?, ?, ?)''', (None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'expired'))
                conn.commit()
                conn.close()
                return render_template('expired.html')
            otp_db = result[1]
            if otp_input == otp_db:
                c.execute("UPDATE sessions SET status=? WHERE session_id=?", ('verified', session_id))
                c.execute('''INSERT INTO scan_logs (email, scan_time, status) VALUES (?, ?, ?)''', (None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'success'))
                conn.commit()
                conn.close()
                return render_template('success.html')
            else:
                c.execute('''INSERT INTO scan_logs (email, scan_time, status) VALUES (?, ?, ?)''', (None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'failed'))
                conn.commit()
                conn.close()
                return render_template('verify.html', session_id=encrypted_id, error="Invalid OTP")
        else:
            conn.close()
            return "Session not found."

@app.route('/view-logs')
def view_logs():
    conn = sqlite3.connect('sessions.db')
    c = conn.cursor()
    c.execute('SELECT * FROM scan_logs ORDER BY id DESC')
    logs = c.fetchall()
    conn.close()
    html = "<h2>Scan Logs</h2><table border='1'><tr><th>ID</th><th>Email</th><th>Scan Time</th><th>Status</th></tr>"
    for row in logs:
        html += "<tr>" + "".join(f"<td>{col}</td>" for col in row) + "</tr>"
    html += "</table>"
    return html

def check_url_safety(url):
    data = {
        "client": {
            "clientId": "quishshield-demo",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    response = requests.post(SAFE_BROWSING_API_URL, json=data)
    if response.status_code == 200:
        result = response.json()
        if 'matches' in result:
            return False  # Dangerous
        else:
            return True   # Safe
    else:
        return None  # Could not check

def scan_with_urlscan(url):
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    data = {'url': url, 'public': 'off'}
    response = requests.post(URLSCAN_API_URL, headers=headers, json=data)
    if response.status_code == 200:
        scan_id = response.json()['uuid']
        # Wait for scan to complete (10 seconds)
        time.sleep(10)
        result = requests.get(f'{URLSCAN_RESULT_URL}{scan_id}/').json()
        # Check for login forms or suspicious keywords
        verdict = 'safe'
        page_text = str(result).lower()
        if 'login' in page_text or 'phish' in page_text or 'password' in page_text:
            verdict = 'suspicious'
        screenshot_url = result.get('screenshotURL')
        report_url = f'https://urlscan.io/result/{scan_id}/'
        return verdict, screenshot_url, report_url
    else:
        return 'unknown', None, None

@app.route('/scan', methods=['GET', 'POST'])
def scan_qr():
    if request.method == 'POST':
        if 'qr_image' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['qr_image']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join('static', 'qrs', filename)
            file.save(filepath)
            # Decode QR code
            img = Image.open(filepath)
            decoded_objs = pyzbar.decode(img)
            url = None
            for obj in decoded_objs:
                url = obj.data.decode('utf-8')
                break
            if url:
                verdict = check_url_safety(url)
                urlscan_verdict, screenshot_url, report_url = scan_with_urlscan(url)
                return render_template('scan_result.html', url=url, verdict=verdict, urlscan_verdict=urlscan_verdict, screenshot_url=screenshot_url, report_url=report_url)
            else:
                flash('No QR code detected or QR does not contain a URL.')
                return redirect(request.url)
    return render_template('scan.html')

def send_email(to_email, otp):
    with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
        smtp.starttls()
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        subject = 'Your OTP Code'
        body = f'Your OTP is: {otp}'
        msg = f'Subject: {subject}\n\n{body}'
        smtp.sendmail(EMAIL_ADDRESS, to_email, msg)

if __name__ == '__main__':
    if not os.path.exists('static/qrs'):
        os.makedirs('static/qrs')
    app.run(host='0.0.0.0', port=5000)