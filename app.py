from cryptography.fernet import Fernet
import sqlite3
import pyotp

from flask import Flask, render_template, request, redirect, url_for
import qrcode
import random
import smtplib
import os
from datetime import datetime, timedelta

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

# Call it once on startup
init_db()



# Encryption key (save securely)
ENCRYPTION_KEY = b'PHVvRWaCRobnyHOMy3mD6o2Jpsm40Nk7SDgvkEe7L-Y='  # Replace with your generated key
f = Fernet(ENCRYPTION_KEY)


app = Flask(__name__)

# Store sessions in memory (or file if needed)
sessions = {}

EMAIL_ADDRESS = 'mayanktanwar2022@gmail.com'
EMAIL_PASSWORD = 'gxzu pvgz mpjp ofbs'  # Use an app-specific password

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


    # Send OTP to email
    send_email(user_email, otp)
    encrypted_id = f.encrypt(session_id.encode()).decode()

    # Generate QR code pointing to verify URL
    data = request.url_root + 'verify/' + encrypted_id
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
    qr_path = f'static/qrs/totp_setup.png'
    qr.save(qr_path)

    return render_template('totp_setup.html', qr_path=qr_path, secret=totp_secret)

@app.route('/totp-verify', methods=['GET', 'POST'])
def totp_verify():
    totp_secret = "N2TMZ4ZGVLBMXLTY3YTDRVTOU3JHUI4X"  # Replace with your actual secret printed earlier

    totp = pyotp.TOTP(totp_secret)

    if request.method == 'POST':
        user_otp = request.form['otp']
        if totp.verify(user_otp):
            return '''
                <h1 style="color:green;">✅ OTP Verified Successfully!</h1>
                <a href="/">Go Home</a>
            '''
        else:
            return '''
                <h1 style="color:red;">❌ Invalid OTP.</h1>
                <a href="/totp-verify">Try Again</a>
            '''

    return '''
        <h1>TOTP Verification 🔑</h1>
        <form method="POST">
            <input type="text" name="otp" placeholder="Enter OTP">
            <button type="submit">Verify</button>
        </form>
    '''



@app.route('/verify/<encrypted_id>', methods=['GET', 'POST'])
def verify(encrypted_id):
    try:
        session_id = f.decrypt(encrypted_id.encode()).decode()
    except:
        return "Invalid or tampered QR code!"

    conn = sqlite3.connect('sessions.db')
    c = conn.cursor()
    c.execute('SELECT otp, expiry, status FROM sessions WHERE session_id = ?', (session_id,))
    result = c.fetchone()
    conn.close()

    if result:
        otp_db, expiry_db, status = result
        expiry_db = datetime.strptime(expiry_db, "%Y-%m-%d %H:%M:%S")

        if datetime.now() > expiry_db:
            return render_template('expired.html')

        if request.method == 'POST':
            user_otp = request.form['otp']
            if user_otp == otp_db:
                # Update status to 'verified'
                conn = sqlite3.connect('sessions.db')
                c = conn.cursor()
                c.execute('UPDATE sessions SET status = ? WHERE session_id = ?', ('verified', session_id))
                conn.commit()
                conn.close()
                return render_template('success.html')
            else:
                return render_template('verify.html', session_id=encrypted_id, error='Invalid OTP! Please try again.')

        return render_template('verify.html', session_id=encrypted_id)
    else:
        return "Invalid Session!"


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
