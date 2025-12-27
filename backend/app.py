# backend/app.py
import os
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from google.oauth2 import id_token
from google.auth.transport import requests
import psycopg2
import smtplib
from email.message import EmailMessage
import random
import time

app = Flask(__name__)

# --- 1. MANUAL CORS OVERRIDE ---
# Forces headers on every response to fix connection issues
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# --- 2. CONFIGURATION ---
DB_HOST = "localhost"
DB_NAME = "sentra_db"
DB_USER = "postgres"
DB_PASS = "admin" 

# Email Credentials
SMTP_EMAIL = "sentramemorydump@gmail.com"
SMTP_PASSWORD = "pjcn avud bbup yvaz" 

# Google Client ID
GOOGLE_CLIENT_ID = "199455383424-iai5kpl9402j9btrgl70uj0rer5f8quu.apps.googleusercontent.com" 

# Upload Configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# OTP Storage (In-Memory)
otp_storage = {}

# --- 3. HELPER FUNCTIONS ---
def get_db_connection():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        return conn
    except Exception as e:
        print(f"❌ Database Error: {e}")
        return None

def send_email_otp(to_email, otp):
    try:
        msg = EmailMessage()
        msg.set_content(f"Hello,\n\nYour Sentra Verification Code is: {otp}\n\nThis code expires in 5 minutes.\n\n- Sentra Security Team")
        msg['Subject'] = "Sentra Security Verification"
        msg['From'] = SMTP_EMAIL
        msg['To'] = to_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"❌ Email Sending Error: {e}")
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- 4. API ROUTES ---

@app.route('/')
def home():
    return jsonify({"status": "active", "system": "Sentra Core"})

# --- AUTH: SEND OTP ---
@app.route('/api/send-otp', methods=['POST', 'OPTIONS'])
def send_otp():
    if request.method == 'OPTIONS': return jsonify({}), 200

    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = str(random.randint(100000, 999999))
    otp_storage[email] = {
        "otp": otp,
        "expires_at": time.time() + 300 
    }

    if send_email_otp(email, otp):
        print(f"📧 OTP sent to {email}: {otp}")
        return jsonify({"status": "success", "message": "OTP sent"}), 200
    else:
        return jsonify({"error": "Failed to send email"}), 500

# --- AUTH: SIGNUP ---
@app.route('/api/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS': return jsonify({}), 200

    data = request.json
    full_name = data.get('fullname')
    email = data.get('email')
    password = data.get('password')
    user_otp = data.get('otp')

    # Verify OTP
    record = otp_storage.get(email)
    if not record or time.time() > record['expires_at'] or record['otp'] != user_otp:
        return jsonify({"error": "Invalid or Expired OTP"}), 400

    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    conn = get_db_connection()
    if not conn: return jsonify({"error": "Database error"}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({"error": "User already exists"}), 400

        cur.execute(
            "INSERT INTO users (full_name, email, password_hash, auth_provider) VALUES (%s, %s, %s, 'local')",
            (full_name, email, hashed_pw)
        )
        conn.commit()
        del otp_storage[email]
        return jsonify({"status": "success"}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn: conn.close()

# --- AUTH: LOGIN ---
@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS': return jsonify({}), 200

    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        conn = get_db_connection()
        if not conn: return jsonify({"error": "Database unavailable"}), 500
        
        cur = conn.cursor()
        # NOTE: This query assumes 'profile_photo' column exists. 
        # If you get an error, run: ALTER TABLE users ADD COLUMN profile_photo VARCHAR(255) DEFAULT NULL;
        cur.execute("SELECT password_hash, full_name, auth_provider, profile_photo FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            if user[2] == 'google':
                 return jsonify({"error": "Please use Google Sign-In"}), 400
            
            if check_password_hash(user[0], password):
                # Construct Photo URL
                photo_url = f"http://127.0.0.1:5000/static/uploads/{user[3]}" if user[3] else None
                return jsonify({
                    "status": "success", 
                    "user": {"name": user[1], "email": email, "photo": photo_url}
                }), 200
            else:
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        print(f"❌ Login Error: {e}")
        return jsonify({"error": "Server Error"}), 500

# --- AUTH: GOOGLE LOGIN ---
@app.route('/api/google-login', methods=['POST', 'OPTIONS'])
def google_login():
    if request.method == 'OPTIONS': return jsonify({}), 200

    try:
        data = request.json
        token = data.get('token')
        
        id_info = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        email = id_info.get('email')
        name = id_info.get('name')

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            cur.execute(
                "INSERT INTO users (full_name, email, auth_provider, last_login) VALUES (%s, %s, 'google', NOW())",
                (name, email)
            )
        else:
            cur.execute("UPDATE users SET last_login = NOW() WHERE email = %s", (email,))
        
        cur.execute("INSERT INTO audit_logs (user_email, action) VALUES (%s, 'GOOGLE_LOGIN')", (email,))
        conn.commit()
        
        # Fetch Photo
        cur.execute("SELECT profile_photo FROM users WHERE email = %s", (email,))
        photo_row = cur.fetchone()
        photo_url = f"http://127.0.0.1:5000/static/uploads/{photo_row[0]}" if photo_row and photo_row[0] else None

        cur.close()
        conn.close()

        return jsonify({
            "status": "success", 
            "user": {"email": email, "name": name, "photo": photo_url}
        }), 200

    except ValueError:
        return jsonify({"error": "Invalid Token"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- SETTINGS: GET PROFILE ---
@app.route('/api/profile', methods=['POST', 'OPTIONS'])
def get_profile():
    if request.method == 'OPTIONS': return jsonify({}), 200

    data = request.json
    email = data.get('email')
    
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB Error"}), 500

    cur = conn.cursor()
    cur.execute("SELECT full_name, email, profile_photo FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user:
        photo_url = f"http://127.0.0.1:5000/static/uploads/{user[2]}" if user[2] else None
        return jsonify({
            "status": "success", 
            "data": { "name": user[0], "email": user[1], "photo": photo_url }
        }), 200
    return jsonify({"error": "User not found"}), 404

# --- SETTINGS: UPLOAD PHOTO ---
@app.route('/api/upload-photo', methods=['POST', 'OPTIONS'])
def upload_photo():
    if request.method == 'OPTIONS': return jsonify({}), 200

    if 'file' not in request.files: return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    email = request.form.get('email')

    if file and allowed_file(file.filename):
        filename = secure_filename(f"{email}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET profile_photo = %s WHERE email = %s", (filename, email))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "status": "success", 
            "file_url": f"http://127.0.0.1:5000/static/uploads/{filename}"
        }), 200
    return jsonify({"error": "Invalid file type"}), 400

# --- SETTINGS: REMOVE PHOTO ---
@app.route('/api/remove-photo', methods=['POST', 'OPTIONS'])
def remove_photo():
    if request.method == 'OPTIONS': return jsonify({}), 200

    data = request.json
    email = data.get('email')

    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB Error"}), 500

    try:
        cur = conn.cursor()
        # Optional: Get filename to delete from disk
        cur.execute("SELECT profile_photo FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        
        # Set to NULL in DB
        cur.execute("UPDATE users SET profile_photo = NULL WHERE email = %s", (email,))
        conn.commit()

        # Optional: Delete file
        if row and row[0]:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], row[0])
            if os.path.exists(file_path):
                os.remove(file_path)

        cur.close()
        conn.close()
        return jsonify({"status": "success", "message": "Photo removed"}), 200
    except Exception as e:
        return jsonify({"error": "Failed to remove photo"}), 500

# --- SETTINGS: UPDATE PASSWORD ---
@app.route('/api/update-password', methods=['POST', 'OPTIONS'])
def update_password():
    if request.method == 'OPTIONS': return jsonify({}), 200

    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')
    otp_input = data.get('otp')

    record = otp_storage.get(email)
    if not record or time.time() > record['expires_at'] or record['otp'] != otp_input:
        return jsonify({"error": "Invalid or Expired OTP"}), 400

    hashed_pw = generate_password_hash(new_password, method='pbkdf2:sha256')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_pw, email))
    conn.commit()
    cur.close()
    conn.close()

    del otp_storage[email]
    return jsonify({"status": "success", "message": "Password updated"}), 200

# --- STATIC FILES ---
@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    print("🛡️ Sentra Backend Active on Port 5000")
    app.run(debug=True, port=5000)