import os
from functools import wraps
from flask import session, redirect, url_for, request, jsonify

# Supabase configuration
try:
    from supabase import create_client, Client
    SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
    SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', '')
    SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY', '')
    
    # Initialize Supabase client only if credentials are provided
    if SUPABASE_URL and SUPABASE_ANON_KEY:
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        SUPABASE_ENABLED = True
    else:
        supabase = None
        SUPABASE_ENABLED = False
except ImportError:
    supabase = None
    SUPABASE_ENABLED = False

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Get current user
def get_current_user():
    if 'user' in session:
        return session['user']
    return None

# Login user
def login_user(email, password):
    if not SUPABASE_ENABLED:
        return False, "Authentication system not configured. Please set up Supabase credentials."
    
    try:
        response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })
        if response.user:
            session['user'] = {
                'id': response.user.id,
                'email': response.user.email,
                'full_name': response.user.user_metadata.get('full_name', ''),
                'avatar_url': response.user.user_metadata.get('avatar_url', '')
            }
            return True, "Login successful"
        return False, "Invalid credentials"
    except Exception as e:
        return False, str(e)

# Register user
def register_user(email, password, full_name):
    if not SUPABASE_ENABLED:
        return False, "Authentication system not configured. Please set up Supabase credentials."
    
    try:
        response = supabase.auth.sign_up({
            "email": email,
            "password": password,
            "options": {
                "data": {
                    "full_name": full_name
                }
            }
        })
        if response.user:
            return True, "Registration successful"
        return False, "Registration failed"
    except Exception as e:
        return False, str(e)

# Logout user
def logout_user():
    if SUPABASE_ENABLED:
        try:
            supabase.auth.sign_out()
        except Exception as e:
            pass  # Ignore logout errors
    session.pop('user', None)
    return True, "Logout successful"

# Google OAuth login
def google_login():
    if not SUPABASE_ENABLED:
        return None, "Authentication system not configured. Please set up Supabase credentials."
    
    try:
        response = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": url_for('auth_callback', _external=True)
            }
        })
        return response.url
    except Exception as e:
        return None, str(e)

# Get user scan history
def get_user_scan_history(user_id, limit=50):
    if not SUPABASE_ENABLED:
        return []  # Return empty list if Supabase is not configured
    
    try:
        response = supabase.table('scan_history').select('*').eq('user_id', user_id).order('created_at', desc=True).limit(limit).execute()
        return response.data
    except Exception as e:
        return []

# Add scan to history
def add_scan_to_history(user_id, url, safety_score, safety_label, safe_browsing_verdict, urlscan_verdict, heuristic_reasons, vault_id):
    if not SUPABASE_ENABLED:
        return False  # Silently fail if Supabase is not configured
    
    try:
        response = supabase.table('scan_history').insert({
            'user_id': user_id,
            'url': url,
            'safety_score': safety_score,
            'safety_label': safety_label,
            'safe_browsing_verdict': safe_browsing_verdict,
            'urlscan_verdict': urlscan_verdict,
            'heuristic_reasons': heuristic_reasons,
            'vault_id': vault_id
        }).execute()
        return True
    except Exception as e:
        return False

# Update user profile
def update_user_profile(user_id, full_name=None, avatar_url=None):
    if not SUPABASE_ENABLED:
        # Fallback: Update session data only
        if 'user' in session:
            if full_name:
                session['user']['full_name'] = full_name
            if avatar_url:
                session['user']['avatar_url'] = avatar_url
            session.modified = True
            return True, "Profile updated successfully (demo mode)"
        return False, "No user session found"
    
    try:
        data = {}
        if full_name:
            data['full_name'] = full_name
        if avatar_url:
            data['avatar_url'] = avatar_url
            
        if data:
            response = supabase.table('users').update(data).eq('id', user_id).execute()
            return True, "Profile updated successfully"
        return True, "No changes to update"
    except Exception as e:
        return False, str(e)