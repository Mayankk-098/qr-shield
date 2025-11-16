from flask import Flask, render_template, request, redirect, flash, session, url_for, Response, send_file
from werkzeug.utils import secure_filename
from functools import wraps
import os
import cv2
from PIL import Image
import numpy as np
import requests
import time
import re
from urllib.parse import urlparse, urljoin
import uuid
import threading
import queue
from datetime import datetime, timedelta
import json
from bs4 import BeautifulSoup
import bleach
from playwright.sync_api import sync_playwright
from flask_socketio import SocketIO, emit
import base64

# Import authentication modules
from auth_manager import (
    supabase, login_required, get_current_user, login_user, 
    register_user, logout_user, google_login, get_user_scan_history,
    add_scan_to_history, update_user_profile
)

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key')

# Admin authentication
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')  # Change this in production!

SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY', '')
SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + SAFE_BROWSING_API_KEY if SAFE_BROWSING_API_KEY else None

URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
URLSCAN_API_URL = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT_URL = 'https://urlscan.io/api/v1/result/'

# Vault system storage
VAULT_SESSIONS = {}
VAULT_QUEUE = queue.Queue()

# Security monitoring
SECURITY_LOGS = []
MAX_LOG_ENTRIES = 1000

print("SAFE_BROWSING_API_KEY:", SAFE_BROWSING_API_KEY)

SCREENSHOT_DIR = 'static/vault_screenshots'
if not os.path.exists(SCREENSHOT_DIR):
    os.makedirs(SCREENSHOT_DIR)

socketio = SocketIO(app, cors_allowed_origins="*")
latest_frame = None

def take_screenshot(url, output_path):
    print(f"[DEBUG] Attempting screenshot: {url} -> {output_path}")
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=15000)
            page.screenshot(path=output_path, full_page=True)
            print(f"[DEBUG] Screenshot success: {output_path}")
            browser.close()
        except Exception as e:
            print(f"[ERROR] Screenshot failed: {e}")
            raise e

@app.route('/vault_screenshot/<vault_id>')
def vault_screenshot(vault_id):
    if vault_id not in VAULT_SESSIONS:
        print("[ERROR] Invalid vault session")
        return "Invalid vault session", 404
    session_data = VAULT_SESSIONS[vault_id]
    if not session_data['is_active'] or datetime.now() > session_data['expires_at']:
        print("[ERROR] Vault session expired")
        return "Vault session expired", 410
    target_url = session_data['url']
    screenshot_path = os.path.join(SCREENSHOT_DIR, f'{vault_id}.png')
    if not os.path.exists(screenshot_path):
        try:
            take_screenshot(target_url, screenshot_path)
        except Exception as e:
            print(f"[ERROR] Failed to generate screenshot: {e}")
            return f"<div style='padding:2em;text-align:center;color:#c00;'>Failed to generate screenshot: {e}</div>", 502
    return send_file(screenshot_path, mimetype='image/png')

@app.route('/test_playwright')
def test_playwright():
    try:
        take_screenshot('https://example.com', 'static/vault_screenshots/test.png')
        return send_file('static/vault_screenshots/test.png', mimetype='image/png')
    except Exception as e:
        return f"Playwright test failed: {e}"

@app.route('/vault_preview/<vault_id>')
def vault_preview(vault_id):
    if vault_id not in VAULT_SESSIONS:
        return "Invalid vault session", 404
    session_data = VAULT_SESSIONS[vault_id]
    if not session_data['is_active'] or datetime.now() > session_data['expires_at']:
        return "Vault session expired", 410
    screenshot_url = url_for('vault_screenshot', vault_id=vault_id)
    target_url = session_data['url']
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>QR Shield Vault Screenshot Preview</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ background: #f5f5f5; margin: 0; }}
            .vault-warning {{ background: #ffc107; color: #333; padding: 1em; text-align: center; font-weight: bold; }}
            .vault-frame {{ background: #fff; margin: 2em auto; max-width: 900px; box-shadow: 0 4px 32px rgba(0,0,0,0.08); border-radius: 1.5rem; padding: 2em; text-align: center; }}
            .vault-controls {{ text-align: right; margin-bottom: 1em; }}
            .vault-controls a {{ margin-left: 1em; }}
            img.screenshot {{ max-width: 100%; border-radius: 1rem; box-shadow: 0 2px 16px rgba(0,0,0,0.08); }}
        </style>
    </head>
    <body>
        <div class="vault-warning">⚠️ You are viewing a screenshot preview in QR Shield Vault. This is a safe, read-only image of the page.</div>
        <div class="vault-frame">
            <div class="vault-controls">
                <a href="{target_url}" target="_blank" rel="noopener noreferrer">Open Directly (Not Recommended)</a>
                <a href="/scan">Scan Another</a>
            </div>
            <img class="screenshot" src="{screenshot_url}" alt="Vault Screenshot Preview" />
        </div>
    </body>
    </html>
    '''

def cleanup_expired_sessions():
    """Clean up expired vault sessions"""
    current_time = datetime.now()
    expired_sessions = []
    
    for vault_id, session_data in VAULT_SESSIONS.items():
        if current_time > session_data['expires_at']:
            expired_sessions.append(vault_id)
    
    for vault_id in expired_sessions:
        del VAULT_SESSIONS[vault_id]
        log_security_event('session_expired', vault_id, 'Session automatically expired')
    
    if expired_sessions:
        print(f"Cleaned up {len(expired_sessions)} expired vault sessions")

def admin_required(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_authenticated'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def log_security_event(event_type, vault_id, description, additional_data=None):
    """Log security events for monitoring"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'vault_id': vault_id,
        'description': description,
        'ip_address': request.remote_addr if 'request' in globals() else 'Unknown',
        'user_agent': request.headers.get('User-Agent', 'Unknown') if 'request' in globals() else 'Unknown',
        'additional_data': additional_data or {}
    }
    
    SECURITY_LOGS.append(log_entry)
    
    # Keep only the latest logs
    if len(SECURITY_LOGS) > MAX_LOG_ENTRIES:
        SECURITY_LOGS.pop(0)
    
    print(f"SECURITY LOG: {json.dumps(log_entry, indent=2)}")

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login page"""
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            session['admin_authenticated'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid password!', 'error')
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_authenticated', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login'))

@app.route('/admin/vault-sessions')
@admin_required
def admin_vault_sessions():
    """Admin endpoint to view vault sessions (for monitoring)"""
    cleanup_expired_sessions()
    
    active_sessions = []
    for vault_id, session_data in VAULT_SESSIONS.items():
        if session_data['is_active'] and datetime.now() <= session_data['expires_at']:
            active_sessions.append({
                'vault_id': vault_id,
                'url': session_data['url'],
                'safety_label': session_data['safety_label'],
                'access_count': session_data['access_count'],
                'created_at': session_data['created_at'].isoformat(),
                'expires_at': session_data['expires_at'].isoformat()
            })
    
    return {
        'active_sessions': active_sessions,
        'total_sessions': len(VAULT_SESSIONS),
        'security_logs_count': len(SECURITY_LOGS)
    }

@app.route('/admin/security-logs')
@admin_required
def admin_security_logs():
    """Admin endpoint to view security logs"""
    return {
        'logs': SECURITY_LOGS[-50:],  # Last 50 logs
        'total_logs': len(SECURITY_LOGS)
    }

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard page"""
    return render_template('admin_dashboard.html')

@app.route('/')
def index():
    return redirect('/scan')

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        success, message = login_user(email, password)
        if success:
            flash('Login successful!', 'success')
            return redirect(request.args.get('next') or url_for('scan_qr'))
        else:
            flash(message, 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        success, message = register_user(email, password, full_name)
        if success:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash(message, 'error')
    return render_template('register.html')

@app.route('/logout')
def logout():
    success, message = logout_user()
    flash(message, 'success')
    return redirect(url_for('login'))

@app.route('/auth/google')
def google_auth():
    auth_url = google_login()
    if auth_url:
        return redirect(auth_url)
    flash('Google authentication failed', 'error')
    return redirect(url_for('login'))

@app.route('/auth/callback')
def auth_callback():
    # Handle OAuth callback
    code = request.args.get('code')
    if code:
        try:
            # Exchange code for session
            response = supabase.auth.exchange_code_for_session(code)
            if response.user:
                session['user'] = {
                    'id': response.user.id,
                    'email': response.user.email,
                    'full_name': response.user.user_metadata.get('full_name', ''),
                    'avatar_url': response.user.user_metadata.get('avatar_url', '')
                }
                flash('Google login successful!', 'success')
                return redirect(url_for('scan_qr'))
        except Exception as e:
            flash(f'Google authentication failed: {str(e)}', 'error')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    return render_template('profile.html', user=user)

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    user = get_current_user()
    full_name = request.form.get('full_name')
    avatar_url = request.form.get('avatar_url')
    
    success, message = update_user_profile(user['id'], full_name, avatar_url)
    if success:
        # Update session data
        user['full_name'] = full_name or user['full_name']
        user['avatar_url'] = avatar_url or user['avatar_url']
        session['user'] = user
        flash(message, 'success')
    else:
        flash(message, 'error')
    return redirect(url_for('profile'))

@app.route('/api/scan-history')
@login_required
def api_scan_history():
    user = get_current_user()
    scans = get_user_scan_history(user['id'])
    return jsonify(scans)

@app.route('/scan', methods=['GET', 'POST'])
def scan_qr():
    if request.method == 'POST':
        file = request.files.get('qr_image')
        qr_text = request.form.get('qr_image')
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            filepath = os.path.join('static', 'qrs', filename)
            file.save(filepath)
            # Decode QR code using OpenCV
            img = cv2.imread(filepath)
            print("Image loaded:", img is not None)
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(img)
            print("QR data:", data)
            url = data if data else None
        elif qr_text:
            url = qr_text
        else:
            flash('No file or QR code provided')
            return redirect(request.url)
        if url:
            verdict = check_url_safety(url)
            urlscan_verdict, screenshot_url, report_url = scan_with_urlscan(url)
            heuristic_reasons = heuristic_url_check(url)
            # --- Safety Score Calculation ---
            score = 10
            if verdict == False:
                score -= 6
            if urlscan_verdict == 'suspicious':
                score -= 3
            if heuristic_reasons:
                score -= min(len(heuristic_reasons), 3)  # up to -3 for heuristics
            score = max(0, min(10, score))
            if score >= 8:
                safety_label = 'Safe'
            elif score >= 5:
                safety_label = 'Suspicious'
            else:
                safety_label = 'Dangerous'
            
            # Create vault session for this URL
            vault_id = create_vault_session(url, safety_label, score)
            
            # Track scan for logged-in user
            current_user = get_current_user()
            if current_user:
                add_scan_to_history(
                    user_id=current_user['id'],
                    url=url,
                    safety_score=score,
                    safety_label=safety_label,
                    safe_browsing_verdict=verdict,
                    urlscan_verdict=urlscan_verdict,
                    heuristic_reasons=heuristic_reasons,
                    vault_id=vault_id
                )
            
            return render_template('scan_result.html', 
                                url=url, 
                                verdict=verdict, 
                                urlscan_verdict=urlscan_verdict, 
                                screenshot_url=screenshot_url, 
                                report_url=report_url, 
                                heuristic_reasons=heuristic_reasons, 
                                safety_score=score, 
                                safety_label=safety_label,
                                vault_id=vault_id)
        else:
            flash('No QR code detected or QR does not contain a URL.')
            return redirect(request.url)
    return render_template('scan.html')

def create_vault_session(url, safety_label, score):
    """Create a secure vault session for the URL"""
    vault_id = str(uuid.uuid4())
    session_data = {
        'url': url,
        'safety_label': safety_label,
        'safety_score': score,
        'created_at': datetime.now(),
        'expires_at': datetime.now() + timedelta(hours=1),
        'access_count': 0,
        'max_accesses': 5,
        'is_active': True
    }
    VAULT_SESSIONS[vault_id] = session_data
    
    # Log vault creation
    log_security_event('vault_created', vault_id, f'Vault created for {url}', {
        'safety_label': safety_label,
        'safety_score': score
    })
    
    return vault_id

@app.route('/vault/<vault_id>')
def vault_landing(vault_id):
    """Landing page for vault access"""
    if vault_id not in VAULT_SESSIONS:
        flash('Invalid or expired vault session')
        return redirect('/scan')
    
    session_data = VAULT_SESSIONS[vault_id]
    if not session_data['is_active'] or datetime.now() > session_data['expires_at']:
        flash('Vault session has expired')
        return redirect('/scan')
    
    return render_template('vault_landing.html', 
                         vault_id=vault_id, 
                         session_data=session_data)

@app.route('/vault/<vault_id>/proceed')
def vault_proceed(vault_id):
    """Proceed to the URL through the vault"""
    if vault_id not in VAULT_SESSIONS:
        log_security_event('vault_access_denied', vault_id, 'Invalid vault session')
        flash('Invalid vault session')
        return redirect('/scan')
    
    session_data = VAULT_SESSIONS[vault_id]
    if not session_data['is_active'] or datetime.now() > session_data['expires_at']:
        log_security_event('vault_access_denied', vault_id, 'Expired vault session')
        flash('Vault session has expired')
        return redirect('/scan')
    
    if session_data['access_count'] >= session_data['max_accesses']:
        log_security_event('vault_access_denied', vault_id, 'Maximum access limit reached')
        flash('Maximum access limit reached for this vault session')
        return redirect('/scan')
    
    # Increment access count
    session_data['access_count'] += 1
    
    # Log the access
    log_vault_access(vault_id, session_data)
    log_security_event('vault_accessed', vault_id, f'Vault accessed for {session_data["url"]}', {
        'access_count': session_data['access_count'],
        'safety_label': session_data['safety_label']
    })
    
    # Redirect to the secure proxy
    return redirect(url_for('vault_proxy', vault_id=vault_id))

@app.route('/vault/<vault_id>/proxy')
def vault_proxy(vault_id):
    """Secure proxy that serves the target URL"""
    if vault_id not in VAULT_SESSIONS:
        return "Invalid vault session", 404
    
    session_data = VAULT_SESSIONS[vault_id]
    if not session_data['is_active'] or datetime.now() > session_data['expires_at']:
        return "Vault session expired", 410
    
    target_url = session_data['url']
    
    try:
        # Fetch the target URL with security headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        response = requests.get(target_url, headers=headers, timeout=10, allow_redirects=True)
        
        # Create a secure iframe wrapper
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Secure Vault - {target_url}</title>
            <style>
                body {{
                    margin: 0;
                    padding: 0;
                    background: #f5f5f5;
                    font-family: Arial, sans-serif;
                }}
                .vault-header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 15px;
                    text-align: center;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .vault-header h1 {{
                    margin: 0;
                    font-size: 1.5em;
                }}
                .vault-header .safety-info {{
                    font-size: 0.9em;
                    opacity: 0.9;
                    margin-top: 5px;
                }}
                .vault-container {{
                    position: relative;
                    height: calc(100vh - 80px);
                }}
                .vault-iframe {{
                    width: 100%;
                    height: 100%;
                    border: none;
                    background: white;
                }}
                .vault-warning {{
                    background: #fff3cd;
                    border: 1px solid #ffeaa7;
                    color: #856404;
                    padding: 10px;
                    margin: 10px;
                    border-radius: 5px;
                    font-size: 0.9em;
                }}
                .vault-controls {{
                    position: fixed;
                    top: 10px;
                    right: 10px;
                    z-index: 1000;
                }}
                .vault-btn {{
                    background: #dc3545;
                    color: white;
                    border: none;
                    padding: 8px 15px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 0.8em;
                    margin-left: 5px;
                }}
                .vault-btn:hover {{
                    background: #c82333;
                }}
            </style>
        </head>
        <body>
            <div class="vault-header">
                <h1>🛡️ Secure Vault</h1>
                <div class="safety-info">
                    Safety: {session_data['safety_label']} ({session_data['safety_score']}/10) | 
                    Access: {session_data['access_count']}/{session_data['max_accesses']} | 
                    Expires: {session_data['expires_at'].strftime('%H:%M:%S')}
                </div>
            </div>
            
            <div class="vault-controls">
                <button class="vault-btn" onclick="window.close()">Close</button>
                <button class="vault-btn" onclick="window.open('{target_url}', '_blank')">Open Directly</button>
            </div>
            
            {f'<div class="vault-warning">⚠️ Warning: This link was marked as {session_data["safety_label"].lower()}. Proceed with caution.</div>' if session_data['safety_label'] != 'Safe' else ''}
            
            <div class="vault-container">
                <iframe class="vault-iframe" src="{target_url}" sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-top-navigation"></iframe>
            </div>
            
            <script>
                // Security monitoring
                window.addEventListener('beforeunload', function() {{
                    // Log when user leaves the vault
                    fetch('/vault/{vault_id}/log-exit', {{method: 'POST'}});
                }});
                
                // Prevent certain potentially dangerous operations
                window.addEventListener('message', function(event) {{
                    if (event.data && event.data.type === 'dangerous_operation') {{
                        console.warn('Blocked potentially dangerous operation');
                        return false;
                    }}
                }});
            </script>
        </body>
        </html>
        """
        
        return Response(html_content, content_type='text/html')
        
    except Exception as e:
        error_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vault Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .error {{ color: #dc3545; }}
            </style>
        </head>
        <body>
            <h1 class="error">⚠️ Vault Error</h1>
            <p>Unable to load the requested URL: {target_url}</p>
            <p>Error: {str(e)}</p>
            <button onclick="window.close()">Close</button>
        </body>
        </html>
        """
        return Response(error_html, content_type='text/html')

@app.route('/vault/<vault_id>/log-exit', methods=['POST'])
def log_vault_exit(vault_id):
    """Log when user exits the vault"""
    if vault_id in VAULT_SESSIONS:
        session_data = VAULT_SESSIONS[vault_id]
        session_data['last_exit'] = datetime.now()
    return '', 204

def log_vault_access(vault_id, session_data):
    """Log vault access for security monitoring"""
    log_entry = {
        'vault_id': vault_id,
        'url': session_data['url'],
        'safety_label': session_data['safety_label'],
        'access_time': datetime.now().isoformat(),
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'ip_address': request.remote_addr
    }
    
    # In a real implementation, you'd log to a database
    print(f"VAULT ACCESS LOG: {json.dumps(log_entry, indent=2)}")

@app.route('/vault/<vault_id>/status')
def vault_status(vault_id):
    """Check vault session status"""
    if vault_id not in VAULT_SESSIONS:
        return {'status': 'invalid'}, 404
    
    session_data = VAULT_SESSIONS[vault_id]
    if not session_data['is_active'] or datetime.now() > session_data['expires_at']:
        return {'status': 'expired'}, 410
    
    return {
        'status': 'active',
        'access_count': session_data['access_count'],
        'max_accesses': session_data['max_accesses'],
        'expires_at': session_data['expires_at'].isoformat(),
        'safety_label': session_data['safety_label']
    }

@app.route('/vault_proxy/<vault_id>')
def advanced_vault_proxy(vault_id):
    """Advanced server-side proxy vault: fetches, sanitizes, and rewrites the target page."""
    if vault_id not in VAULT_SESSIONS:
        return "Invalid vault session", 404
    session_data = VAULT_SESSIONS[vault_id]
    if not session_data['is_active'] or datetime.now() > session_data['expires_at']:
        return "Vault session expired", 410
    target_url = session_data['url']
    try:
        resp = requests.get(target_url, timeout=8, headers={
            'User-Agent': 'Mozilla/5.0 (VaultProxy)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        html = resp.text
        # Basic script/style sanitization
        soup = BeautifulSoup(html, 'html.parser')
        # Remove all script and iframe tags
        for tag in soup(['script', 'iframe', 'object', 'embed', 'form']):
            tag.decompose()
        # Remove all inline event handlers (onclick, onerror, etc.)
        for tag in soup.find_all(True):
            atts = list(tag.attrs.keys())
            for att in atts:
                if att.lower().startswith('on'):
                    del tag.attrs[att]
        # Rewrite relative resource links to absolute
        for tag in soup.find_all(['a', 'img', 'link', 'script']):
            attr = 'href' if tag.name in ['a', 'link'] else 'src'
            if tag.has_attr(attr):
                tag[attr] = urljoin(target_url, tag[attr])
        # Bleach sanitize (allow only safe tags/attributes)
        safe_tags = list(bleach.sanitizer.ALLOWED_TAGS) + ['html', 'head', 'body', 'meta', 'title', 'style']
        safe_html = bleach.clean(str(soup), tags=safe_tags, attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES, strip=True)
        # Wrap in a vault UI
        vault_html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>QR Shield Vault Proxy</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{ background: #f5f5f5; margin: 0; }}
                .vault-warning {{ background: #ffc107; color: #333; padding: 1em; text-align: center; font-weight: bold; }}
                .vault-frame {{ background: #fff; margin: 2em auto; max-width: 900px; box-shadow: 0 4px 32px rgba(0,0,0,0.08); border-radius: 1.5rem; padding: 2em; }}
                .vault-controls {{ text-align: right; margin-bottom: 1em; }}
                .vault-controls a {{ margin-left: 1em; }}
            </style>
        </head>
        <body>
            <div class="vault-warning">⚠️ You are viewing this link in QR Shield Vault Proxy. All scripts and forms have been disabled for your safety.</div>
            <div class="vault-frame">
                <div class="vault-controls">
                    <a href="{target_url}" target="_blank" rel="noopener noreferrer">Open Directly (Not Recommended)</a>
                    <a href="/scan">Scan Another</a>
                </div>
                {safe_html}
            </div>
        </body>
        </html>
        '''
        return Response(vault_html, content_type='text/html')
    except Exception as e:
        return f"<div style='padding:2em;text-align:center;color:#c00;'>Failed to load or sanitize URL: {e}</div>", 502

def check_url_safety(url):
    if not SAFE_BROWSING_API_URL or not SAFE_BROWSING_API_KEY:
        return None  # API key not configured
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
    try:
        response = requests.post(SAFE_BROWSING_API_URL, json=data, timeout=5)
        if response.status_code == 200:
            result = response.json()
            if 'matches' in result:
                return False  # Dangerous
            else:
                return True   # Safe
        else:
            return None  # Could not check
    except Exception as e:
        print(f"Error checking URL safety: {e}")
        return None  # Could not check

def scan_with_urlscan(url):
    if not URLSCAN_API_KEY:
        return 'unknown', None, None  # API key not configured
    try:
        headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
        data = {'url': url, 'public': 'off'}
        response = requests.post(URLSCAN_API_URL, headers=headers, json=data, timeout=10)
        if response.status_code == 200:
            scan_id = response.json()['uuid']
            # Wait for scan to complete (5 seconds)
            time.sleep(5)
            result = requests.get(f'{URLSCAN_RESULT_URL}{scan_id}/', timeout=10).json()
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
    except Exception as e:
        print(f"Error scanning with URLScan: {e}")
        return 'unknown', None, None

def heuristic_url_check(url):
    reasons = []
    parsed = urlparse(url)
    # 1. IP address in netloc
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', parsed.hostname or ''):
        reasons.append('URL uses an IP address instead of a domain name.')
    # 2. Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
    if parsed.hostname and any(parsed.hostname.endswith(tld) for tld in suspicious_tlds):
        reasons.append('URL uses a suspicious TLD (e.g., .tk, .ml, .ga, .cf, .gq).')
    # 3. No HTTPS
    if parsed.scheme != 'https':
        reasons.append('URL does not use HTTPS.')
    # 4. Excessive subdomains
    if parsed.hostname and len(parsed.hostname.split('.')) > 3:
        reasons.append('URL has excessive subdomains.')
    # 5. Punycode or lookalike domains
    if parsed.hostname and ('xn--' in parsed.hostname or re.search(r'\d', parsed.hostname)):
        reasons.append('URL may use punycode or lookalike domain (e.g., g00gle.com).')
    # 6. Long/random query string
    if parsed.query and len(parsed.query) > 40:
        reasons.append('URL has a long or suspicious query string.')
    return reasons

@app.route('/admin/live_camera_feed')
@admin_required
def admin_live_camera_feed():
    # Simple page to view the live feed
    return '''
    <html>
    <body>
        <h2>Live Camera Feed</h2>
        <img id="liveFeed" style="max-width:100%">
        <script src="https://cdn.socket.io/4.3.2/socket.io.min.js"></script>
        <script>
            var socket = io();
            function updateFrame() {
                socket.emit('get_latest_frame');
            }
            socket.on('latest_frame', function(data) {
                if (data) {
                    document.getElementById('liveFeed').src = data;
                }
                setTimeout(updateFrame, 100);
            });
            updateFrame();
        </script>
    </body>
    </html>
    '''

@socketio.on('camera_frame')
def handle_camera_frame(data):
    global latest_frame
    latest_frame = data  # data is a base64-encoded image string

@socketio.on('get_latest_frame')
def send_latest_frame():
    global latest_frame
    if latest_frame:
        emit('latest_frame', latest_frame)
    else:
        emit('latest_frame', None)

# Initialize directories
if not os.path.exists('static/qrs'):
    os.makedirs('static/qrs')
if not os.path.exists(SCREENSHOT_DIR):
    os.makedirs(SCREENSHOT_DIR)

# Start background cleanup task
def background_cleanup():
    while True:
        try:
            cleanup_expired_sessions()
            time.sleep(300)  # Run every 5 minutes
        except Exception as e:
            print(f"Background cleanup error: {e}")
            time.sleep(60)  # Wait 1 minute on error

cleanup_thread = threading.Thread(target=background_cleanup, daemon=True)
cleanup_thread.start()

if __name__ == '__main__':
    # For local development
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)