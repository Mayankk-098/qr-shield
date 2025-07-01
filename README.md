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

## Setup & Installation
1. **Clone the repository:**
   ```sh
   git clone <your-repo-url>
   cd <project-folder>
   ```
2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
3. **Set up environment variables (optional):**
   - Update `EMAIL_ADDRESS` and `EMAIL_PASSWORD` in `app.py` with your email and app password.
4. **Run the app locally:**
   ```sh
   python app.py
   ```
5. **Access the app:**
   - Open [http://localhost:5000](http://localhost:5000) in your browser.

## Usage
- **Generate QR:** Enter your email and click "Generate QR" to receive an OTP and QR code.
- **Scan QR:** Scan the QR code or open the link to verify your session.
- **Enter OTP:** Enter the OTP received by email to complete verification.
- **View Logs:** Visit `/view-logs` to see all scan/verification attempts (for demo/testing).

## Google Authenticator (TOTP) Demo (Optional)
- Visit `/totp-setup` to generate a TOTP secret and QR code for Google Authenticator.
- Visit `/totp-verify` to test TOTP code verification.

## Project Structure
- `app.py` — Main Flask application
- `templates/` — HTML templates (frontend)
- `static/qrs/` — Generated QR code images
- `sessions.db` — SQLite database
- `requirements.txt` — Python dependencies
- `Procfile` — Deployment instructions for Render/Heroku

## Security Notes
- OTPs and sessions expire after a set time for security.
- All attempts are logged for auditing.
- For production, use environment variables for sensitive info and consider a managed database.

## Credits
- Built with [Flask](https://flask.palletsprojects.com/), [qrcode](https://pypi.org/project/qrcode/), [pyotp](https://pypi.org/project/pyotp/), and [Bootstrap](https://getbootstrap.com/).

---
**Demo-ready. Secure. Auditable.** 