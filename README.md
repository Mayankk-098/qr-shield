# Dynamic QR OTP Authentication System

## Overview
This project is a secure, dynamic QR code authentication system with One-Time Password (OTP) and session expiry. It allows users to generate a unique QR code, receive an OTP via email, and verify their session within a limited time. All verification attempts are logged for audit and security purposes. The project also demonstrates optional support for Google Authenticator (TOTP).

## Features
- **Dynamic QR Code Generation:** Each session gets a unique QR code.
- **Email-based OTP:** OTP is sent to the user's email for verification.
- **Session Expiry:** OTPs and sessions expire after a set time (default: 5 minutes).
- **Logging:** All scan and verification attempts (success, failed, expired) are logged in the database.
- **Google Authenticator (TOTP) Demo:** Optional routes to set up and verify TOTP codes.
- **Modern UI:** Clean, responsive interface using Bootstrap.

## Real-World Applications
- Secure logins and access control (offices, events, visitor management)
- Event ticketing and check-in
- Two-factor authentication (2FA) setup
- Temporary access links (password resets, secure downloads)


## Project Structure
- `app.py` — Main Flask application
- `templates/` — HTML templates (frontend)
- `static/qrs/` — Generated QR code images
- `sessions.db` — SQLite database
- `requirements.txt` — Python dependencies
- `Procfile` — Deployment instructions for Render/Heroku

