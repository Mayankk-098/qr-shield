from cryptography.fernet import Fernet
import sqlite3
import pyotp

from flask import Flask, render_template, request, redirect, url_for
import qrcode
import random
import smtplib
import os
from datetime import datetime, timedelta
@app.route('/totp-setup')
def totp_setup():
    totp_secret = pyotp.random_base32()
    print("Your secret key for Google Authenticator:", totp_secret)

    uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name="MayankQRProject", issuer_name="CyberSecurityDemo")
    qr = qrcode.make(uri)
    qr_path = f'static/qrs/totp_setup.png'
    qr.save(qr_path)

    return render_template('totp_setup.html', qr_path=qr_path, secret=totp_secret)