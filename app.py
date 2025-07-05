from flask import Flask, render_template, request, redirect, flash
from werkzeug.utils import secure_filename
import os
import pyzbar.pyzbar as pyzbar
from PIL import Image
import requests
import time
import re
from urllib.parse import urlparse

app = Flask(__name__)

SAFE_BROWSING_API_KEY = 'AIzaSyBsO1ix17GKlERDqujEy-ZX54_4SI7-KRo'
SAFE_BROWSING_API_URL = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + SAFE_BROWSING_API_KEY

URLSCAN_API_KEY = '0197da5d-6852-74fe-a72e-713b6c37259e'
URLSCAN_API_URL = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT_URL = 'https://urlscan.io/api/v1/result/'

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
                heuristic_reasons = heuristic_url_check(url)
                urlhaus_flag, urlhaus_data = check_urlhaus(url)
                return render_template('scan_result.html', url=url, verdict=verdict, urlscan_verdict=urlscan_verdict, screenshot_url=screenshot_url, report_url=report_url, heuristic_reasons=heuristic_reasons, urlhaus_flag=urlhaus_flag, urlhaus_data=urlhaus_data)
            else:
                flash('No QR code detected or QR does not contain a URL.')
                return redirect(request.url)
    return render_template('scan.html')

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

def check_urlhaus(url):
    try:
        response = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('query_status') == 'ok':
                return True, data  # URL is malicious
            else:
                return False, None  # Not found in URLhaus
        return None, None  # Error
    except Exception:
        return None, None

if __name__ == '__main__':
    if not os.path.exists('static/qrs'):
        os.makedirs('static/qrs')
    app.run(host='0.0.0.0', port=5000)