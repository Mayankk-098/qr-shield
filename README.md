# QR Code Security Scanner with Secure Vault System

A comprehensive QR code scanner with advanced security features including a secure vault system to protect users from potentially malicious links.

## 🛡️ Security Features

### Vault System
- **Sandboxed Browsing**: All links are opened in a controlled environment
- **Session Management**: Time-limited access with automatic cleanup
- **Access Monitoring**: Track all vault accesses and security events
- **Content Filtering**: Real-time malicious content detection
- **Session Isolation**: Each vault session is completely isolated

### URL Security Analysis
- **Google Safe Browsing**: Real-time threat detection
- **URLScan.io Integration**: Deep website analysis and screenshots
- **Heuristic Analysis**: Advanced pattern recognition for suspicious URLs
- **Safety Scoring**: 10-point safety rating system

## 🚀 Features

### Core Functionality
- QR code scanning from images and text input
- Real-time URL safety analysis
- Multiple security check layers
- Beautiful, responsive UI

### Vault Protection
- **Secure Proxy**: All traffic routed through secure proxy
- **Session Limits**: Maximum 5 access attempts per session
- **Time Limits**: 1-hour session timeout
- **Security Logging**: Comprehensive audit trail
- **Admin Dashboard**: Real-time monitoring and control

### Safety Levels
- **Safe (8-10/10)**: Green light for direct access
- **Suspicious (5-7/10)**: Warning with vault recommendation
- **Dangerous (0-4/10)**: Strong vault recommendation

## 📋 Requirements

```bash
pip install -r requirements.txt
```

### Environment Variables
```bash
SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
URLSCAN_API_KEY=your_urlscan_api_key
FLASK_SECRET_KEY=your_secret_key
```

## 🏃‍♂️ Quick Start

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Set Environment Variables**:
   ```bash
   export SAFE_BROWSING_API_KEY="your_key_here"
   export URLSCAN_API_KEY="your_key_here"
   export FLASK_SECRET_KEY="your_secret_here"
   ```

3. **Run the Application**:
   ```bash
   python app.py
   ```

4. **Access the Application**:
   - Main Scanner: `http://localhost:5000`
   - Admin Dashboard: `http://localhost:5000/admin/dashboard`

## 🛡️ Vault System Workflow

1. **Scan QR Code**: User scans QR code or enters URL
2. **Security Analysis**: Multiple security checks performed
3. **Vault Creation**: Secure vault session created with unique ID
4. **Landing Page**: User sees vault landing with safety information
5. **Secure Access**: User enters vault with sandboxed browsing
6. **Monitoring**: All activities logged and monitored
7. **Cleanup**: Automatic session cleanup after timeout

## 🔧 API Endpoints

### Public Endpoints
- `GET /` - Redirect to scanner
- `GET /scan` - QR code scanner page
- `POST /scan` - Process scanned QR code
- `GET /vault/<vault_id>` - Vault landing page
- `GET /vault/<vault_id>/proceed` - Enter vault
- `GET /vault/<vault_id>/proxy` - Secure proxy
- `GET /vault/<vault_id>/status` - Check vault status

### Admin Endpoints
- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/vault-sessions` - Active sessions
- `GET /admin/security-logs` - Security logs

## 🛡️ Security Features

### Vault Protection
- **Sandboxed iframe**: Isolated browsing environment
- **Content Security Policy**: Prevents malicious scripts
- **Session isolation**: Each vault session is independent
- **Access logging**: Complete audit trail
- **Automatic cleanup**: Expired sessions removed

### Monitoring
- **Real-time logs**: All security events logged
- **Admin dashboard**: Live monitoring interface
- **Export capabilities**: Log export for analysis
- **Session tracking**: Complete session lifecycle

### Threat Detection
- **Google Safe Browsing**: Real-time threat database
- **URLScan.io**: Deep website analysis
- **Heuristic analysis**: Pattern-based detection
- **Safety scoring**: Multi-factor risk assessment

## 📊 Admin Dashboard

The admin dashboard provides:
- **Live Statistics**: Active sessions, total sessions, security logs
- **Session Monitoring**: Real-time vault session status
- **Security Logs**: Recent security events and alerts
- **System Controls**: Manual cleanup and data export

## 🔒 Security Considerations

### Production Deployment
1. **Authentication**: Add proper admin authentication
2. **HTTPS**: Use SSL/TLS encryption
3. **Rate Limiting**: Implement request rate limiting
4. **Database**: Use persistent database for sessions
5. **Monitoring**: Set up alerting for security events

### Vault Security
- **Session isolation**: Each vault session is completely isolated
- **Time limits**: Automatic session expiration
- **Access limits**: Maximum access attempts per session
- **Content filtering**: Real-time malicious content detection
- **Audit logging**: Complete activity trail

## 🛡️ Advanced Server-Side Proxy Vault

The advanced proxy vault route (`/vault_proxy/<vault_id>`) fetches the target web page on the server, removes all scripts, forms, and potentially dangerous elements, rewrites resource links to absolute URLs, and serves the sanitized content to the user. This ensures:
- The user's IP and device are never exposed to the target site
- All scripts and forms are disabled, neutralizing most attacks
- The user can safely preview the content of any link, even if the site blocks iframes

This is the most secure way to view potentially dangerous links and is recommended for all suspicious or unknown URLs.

## 🚀 Deployment

### Local Development
```bash
python app.py
```

### Production (Heroku)
```bash
git push heroku main
```

### Docker
```bash
docker build -t qr-vault .
docker run -p 5000:5000 qr-vault
```

## 📝 License

This project is licensed under the MIT License.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📞 Support

For support and questions:
- Create an issue on GitHub
- Contact the development team
- Check the documentation

---

**⚠️ Security Notice**: This system provides enhanced security but should not be considered a complete security solution. Always exercise caution when accessing unknown URLs.

