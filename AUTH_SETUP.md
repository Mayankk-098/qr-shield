# QR Shield - User Authentication Setup Guide

## 🛡️ User Authentication System

QR Shield now includes a complete user authentication system with:
- Email/password registration and login
- Google OAuth integration
- User profiles with avatar support
- Scan history tracking
- Personalized dashboard

## 🔧 Setup Instructions

### 1. Environment Variables

Copy the example environment file and update it with your Supabase credentials:

```bash
cp .env.example .env
```

Edit `.env` with your Supabase project details:
```
# Flask Configuration
FLASK_SECRET_KEY=your_random_secret_key_here

# Supabase Configuration
SUPABASE_URL=your_supabase_project_url
SUPABASE_ANON_KEY=your_supabase_anon_key
SUPABASE_SERVICE_KEY=your_supabase_service_key

# API Keys (Optional - for enhanced safety checks)
SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key
URLSCAN_API_KEY=your_urlscan_api_key

# Admin Configuration
ADMIN_PASSWORD=your_admin_password
```

### 2. Get Your Supabase Credentials

1. Go to [Supabase](https://supabase.com) and create a new project
2. Once created, go to Settings → API
3. Copy your Project URL (for SUPABASE_URL)
4. Copy your anon key (for SUPABASE_ANON_KEY)
5. Copy your service role key (for SUPABASE_SERVICE_KEY)

### 3. Enable Authentication Providers

In your Supabase project:
1. Go to Authentication → Providers
2. Enable Email provider (already enabled by default)
3. Enable Google provider and add your OAuth credentials

### 4. Run the Application

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## 🚀 Features

### User Authentication
- **Login/Register**: Traditional email/password authentication
- **Google OAuth**: One-click login with Google account
- **Secure Sessions**: JWT-based authentication with Flask sessions

### User Profile
- **Personal Information**: Name, email, avatar
- **Profile Management**: Update name and avatar URL
- **Avatar Support**: Display user avatar or initials

### Scan History
- **Personal Dashboard**: Track all your QR scans
- **Safety Statistics**: View safe, suspicious, and dangerous link counts
- **Detailed History**: URL, safety score, timestamp for each scan
- **Quick Access**: Recent scans displayed on homepage

### Enhanced Security
- **Row Level Security**: Users can only access their own data
- **Session Management**: Secure user sessions with proper logout
- **Data Privacy**: User data is isolated and protected

## 📱 User Flow

1. **Landing Page**: Anonymous users see basic scanner
2. **Authentication**: Users can register/login with email or Google
3. **Personalized Experience**: Logged-in users see their scan history
4. **Profile Management**: Users can update their profile information
5. **Scan Tracking**: All scans are automatically saved to user history

## 🔍 API Endpoints

### Authentication
- `GET /login` - Login page
- `GET /register` - Registration page
- `POST /login` - Authenticate user
- `POST /register` - Create new user
- `GET /logout` - Logout user
- `GET /auth/google` - Google OAuth
- `GET /auth/callback` - OAuth callback

### User Profile
- `GET /profile` - User profile page
- `POST /profile/update` - Update profile information
- `GET /api/scan-history` - Get user's scan history

## 🛠️ Database Schema

### Users Table
- `id` (UUID): Primary key
- `email` (TEXT): User email (unique)
- `google_id` (TEXT): Google OAuth ID
- `full_name` (TEXT): User's full name
- `avatar_url` (TEXT): Profile picture URL
- `created_at` (TIMESTAMP): Account creation date
- `updated_at` (TIMESTAMP): Last update date
- `last_login` (TIMESTAMP): Last login date
- `is_active` (BOOLEAN): Account status

### Scan History Table
- `id` (UUID): Primary key
- `user_id` (UUID): Foreign key to users
- `url` (TEXT): Scanned URL
- `safety_score` (INTEGER): Safety score (0-10)
- `safety_label` (TEXT): Safe/Suspicious/Dangerous
- `safe_browsing_verdict` (BOOLEAN): Google Safe Browsing result
- `urlscan_verdict` (TEXT): URLScan.io result
- `heuristic_reasons` (TEXT[]): Array of heuristic warnings
- `vault_id` (TEXT): Associated vault session ID
- `created_at` (TIMESTAMP): Scan timestamp

## 🔒 Security Features

- **Password Hashing**: Secure password storage
- **JWT Tokens**: Secure authentication tokens
- **Row Level Security**: Database-level access control
- **Session Management**: Secure Flask sessions
- **Input Validation**: Proper form validation
- **CSRF Protection**: Built-in Flask protection

## 🎯 Next Steps

To complete the setup:

1. **Configure Supabase**: Set up your project and get credentials
2. **Enable Providers**: Configure Google OAuth if desired
3. **Test Authentication**: Register a test user and login
4. **Scan QR Codes**: Test the scan history functionality
5. **Customize**: Modify templates and styling as needed

## 📞 Support

If you encounter issues:
1. Check your environment variables are set correctly
2. Verify Supabase project is properly configured
3. Check browser console for JavaScript errors
4. Review Flask logs for server-side issues

For help with Supabase setup, visit [Supabase Documentation](https://supabase.com/docs)