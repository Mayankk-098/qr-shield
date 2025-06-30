from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
import sqlite3
import pyotp
from flask import Flask, render_template, request, redirect, url_for
import qrcode
import random
import smtplib
import os
from datetime import datetime, timedelta
import urllib.parse

# Initialize DB
def init_db():
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

def init_scan_logs():
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

init_db()
init_scan_logs()

# Encryption key
ENCRYPTION_KEY = b'PHVvRWaCRobnyHOMy3mD6o2Jpsm40Nk7SDgvkEe7L-Y='
f = Fernet(ENCRYPTION_KEY)

app = Flask(__name__)

# Deployment base URL (update if Render URL changes)
DEPLOYMENT_URL = 'https://qr-otp-project.onrender.com/'  # your Render URL with trailing /

EMAIL_ADDRESS = 'mayanktanwar2022@gmail.com'
EMAIL_PASSWORD = 'gxzu pvgz mpjp ofbs'  # App password

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
    # Use session_id directly in the QR code
    data = request.url_root + 'verify?sid=' + session_id
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
    totp_secret = "N2TMZ4ZGVLBMXLTY3YTDRVTOU3JHUI4X"  # Replace with your real secret

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
        session_id = request.args.get('sid')
        if not session_id:
            return "Missing or invalid link."
        conn = sqlite3.connect('sessions.db')
        c = conn.cursor()
        c.execute("SELECT session_id, otp, expiry, status, created_at FROM sessions WHERE session_id=?", (session_id,))
        result = c.fetchone()
        if result:
            expiry_str = result[2]
            expiry_time = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expiry_time:
                # Log expired scan
                c.execute('''INSERT INTO scan_logs (email, scan_time, status) VALUES (?, ?, ?)''', (None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'expired'))
                conn.commit()
                conn.close()
                return render_template('expired.html')
            conn.close()
            return render_template('verify.html', session_id=session_id)
        else:
            conn.close()
            return "Invalid or expired session."
    elif request.method == 'POST':
        otp_input = request.form['otp']
        session_id = request.form['session_id']
        conn = sqlite3.connect('sessions.db')
        c = conn.cursor()
        c.execute("SELECT session_id, otp, expiry, status, created_at FROM sessions WHERE session_id=?", (session_id,))
        result = c.fetchone()
        if result:
            expiry_str = result[2]
            expiry_time = datetime.strptime(expiry_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expiry_time:
                # Log expired scan
                c.execute('''INSERT INTO scan_logs (email, scan_time, status) VALUES (?, ?, ?)''', (None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'expired'))
                conn.commit()
                conn.close()
                return render_template('expired.html')
            otp_db = result[1]
            if otp_input == otp_db:
                # Update status to verified
                c.execute("UPDATE sessions SET status=? WHERE session_id=?", ('verified', session_id))
                # Log success
                c.execute('''INSERT INTO scan_logs (email, scan_time, status) VALUES (?, ?, ?)''', (None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'success'))
                conn.commit()
                conn.close()
                return render_template('success.html')
            else:
                # Log failed attempt
                c.execute('''INSERT INTO scan_logs (email, scan_time, status) VALUES (?, ?, ?)''', (None, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'failed'))
                conn.commit()
                conn.close()
                return render_template('verify.html', session_id=session_id, error="Invalid OTP")
        else:
            conn.close()
            return "Session not found."

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
