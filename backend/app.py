# backend/app.py
from flask import Flask, request, jsonify
# REMOVE: from flask_cors import CORS (We are doing it manually now)
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests
import psycopg2
import smtplib
from email.message import EmailMessage
import random
import time

app = Flask(__name__)

# --- MANUAL CORS OVERRIDE (The Fix) ---
# This forces the headers onto every single response, bypassing library issues.
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'  # Allow anyone
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# --- CONFIGURATION ---
DB_HOST = "localhost"
DB_NAME = "sentra_db"
DB_USER = "postgres"
DB_PASS = "admin" # <--- CHECK THIS
SMTP_EMAIL = "sentramemorydump@gmail.com" # <--- CHECK THIS
SMTP_PASSWORD = "pjcn avud bbup yvaz" # <--- CHECK THIS
GOOGLE_CLIENT_ID = "199455383424-iai5kpl9402j9btrgl70uj0rer5f8quu.apps.googleusercontent.com" # <--- CHECK THIS

otp_storage = {}

def get_db_connection():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        return conn
    except Exception as e:
        print(f"❌ Database Error: {e}")
        return None

@app.route('/')
def home():
    return jsonify({"status": "active"})

# --- 1. SEND OTP API ---
@app.route('/api/send-otp', methods=['POST', 'OPTIONS'])
def send_otp():
    if request.method == 'OPTIONS': return jsonify({}), 200 # Handle Preflight manually

    data = request.json
    email = data.get('email')
    
    # ... (Your existing OTP Logic) ...
    # For testing, let's just simulate success if email is valid
    otp = str(random.randint(100000, 999999))
    otp_storage[email] = {"otp": otp, "expires_at": time.time() + 300}
    print(f"📧 OTP Generated for {email}: {otp}") 
    return jsonify({"status": "success", "message": "OTP sent"}), 200


# --- 2. SIGNUP API ---
@app.route('/api/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS': return jsonify({}), 200

    data = request.json
    # ... (Your existing Signup Logic) ...
    # Copy your previous logic here
    return jsonify({"status": "success"}), 201


# --- 3. LOGIN API (CRITICAL FIX) ---
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    # 1. Handle the Preflight Request explicitly
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        # 2. Connection Check
        conn = get_db_connection()
        if not conn:
            print("❌ DB Connection Failed")
            return jsonify({"error": "Database unavailable"}), 500
        
        cur = conn.cursor()
        cur.execute("SELECT password_hash, full_name, auth_provider FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            # 3. Validation Logic
            if check_password_hash(user[0], password):
                print(f"🔓 Login Success: {email}")
                return jsonify({"status": "success", "user": {"name": user[1]}}), 200
            else:
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        print(f"❌ Server Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# --- 4. GOOGLE API ---
@app.route('/api/google-login', methods=['POST', 'OPTIONS'])
def google_login():
    if request.method == 'OPTIONS': return jsonify({}), 200
    # ... (Your Google Logic) ...
    return jsonify({"status": "success"}), 200

if __name__ == '__main__':
    print("🛡️ Sentra Backend (Manual CORS) Active on Port 5000")
    app.run(debug=True, port=5000)