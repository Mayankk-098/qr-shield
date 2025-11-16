# Test script for QR Shield authentication system
import os
from dotenv import load_dotenv
from supabase import create_client

# Load environment variables
load_dotenv()

# Test Supabase connection
SUPABASE_URL = os.environ.get('SUPABASE_URL', 'your_supabase_url')
SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', 'your_supabase_anon_key')

print("Testing Supabase connection...")
print(f"URL: {SUPABASE_URL}")
print(f"Key: {SUPABASE_ANON_KEY[:10]}...")

try:
    # Initialize Supabase client
    supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    
    # Test connection by getting tables
    response = supabase.table('users').select('*').limit(1).execute()
    print("✅ Supabase connection successful!")
    print(f"Users table exists: {len(response.data) >= 0}")
    
    # Test scan history table
    response = supabase.table('scan_history').select('*').limit(1).execute()
    print(f"Scan history table exists: {len(response.data) >= 0}")
    
except Exception as e:
    print(f"❌ Supabase connection failed: {e}")
    print("Make sure to set up your environment variables correctly!")

print("\nTo set up the authentication system:")
print("1. Copy .env.example to .env")
print("2. Update the SUPABASE_URL and SUPABASE_ANON_KEY with your Supabase project details")
print("3. Run: python app.py")
print("4. Visit http://localhost:5000 to test the authentication system")