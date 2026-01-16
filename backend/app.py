# backend/app.py
import os
import threading
import json
import re  # Required for parsing JSON in get_case_report
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
import uuid
from dotenv import load_dotenv  # NEW: Load env variables

# --- 0. LOAD ENVIRONMENT VARIABLES ---
load_dotenv() # This loads the variables from .env

# --- IMPORT THE MODULAR RUNNER ---
from analysis.volatility_runner import run_volatility_analysis

app = Flask(__name__)

# --- 1. MANUAL CORS OVERRIDE ---
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# --- 2. CONFIGURATION (SECURE) ---
# We now fetch these from the environment, with fallbacks for safety
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "sentra_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS", "admin") 

SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

UPLOAD_FOLDER = 'static/uploads'
DUMP_FOLDER = 'static/memory_dumps'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 * 1024 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DUMP_FOLDER'] = DUMP_FOLDER

ALLOWED_IMG_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_DUMP_EXTENSIONS = {'raw', 'mem', 'vmem', 'img'}

# Create directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DUMP_FOLDER, exist_ok=True)

otp_storage = {}
active_scans = {}

# --- 3. HELPER FUNCTIONS ---
def get_db_connection():
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        return conn
    except Exception as e:
        print(f"❌ Database Error: {e}")
        return None

def send_email_otp(to_email, otp, user_name="User", action="Verification"):
    try:
        if not SMTP_EMAIL or not SMTP_PASSWORD:
            print("❌ Email Config Missing in .env")
            return False
            
        msg = EmailMessage()
        content = f"""Dear {user_name},

Your Sentra Verification Code for {action} is {otp}

The code expires in 5 minutes.

Regards,
Sentra Security Team
"""
        msg.set_content(content)
        msg['Subject'] = f"Sentra {action} Verification"
        msg['From'] = SMTP_EMAIL
        msg['To'] = to_email

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"❌ Email Error: {e}")
        return False

def allowed_file(filename, extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions

# --- 4. API ROUTES ---

@app.route('/')
def home():
    return jsonify({"status": "active", "system": "Sentra Core"})

# --- AUTH & OTP ---
@app.route('/api/send-otp', methods=['POST', 'OPTIONS'])
def send_otp():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    email = data.get('email')
    req_type = data.get('type', 'signup') 
    full_name = "User"

    if req_type in ['login', 'delete']:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT full_name FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        conn.close()
        if not row: return jsonify({"error": "Email not registered"}), 404
        full_name = row[0]
    elif req_type == 'signup':
        full_name = data.get('fullname', 'User')

    otp = str(random.randint(100000, 999999))
    otp_storage[email] = {"otp": otp, "expires_at": time.time() + 300}
    action_label = "Deletion Authorization" if req_type == 'delete' else req_type.capitalize()
    send_email_otp(email, otp, full_name, action_label)
    return jsonify({"status": "success"}), 200

@app.route('/api/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    record = otp_storage.get(data.get('email'))
    if not record or record['otp'] != data.get('otp'): 
        return jsonify({"error": "Invalid OTP"}), 400
    hashed_pw = generate_password_hash(data.get('password'), method='pbkdf2:sha256')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (full_name, email, password_hash, auth_provider) VALUES (%s, %s, %s, 'local')", 
                    (data.get('fullname'), data.get('email'), hashed_pw))
        conn.commit()
        del otp_storage[data.get('email')]
        return jsonify({"status": "success"}), 201
    except: return jsonify({"error": "User exists"}), 400
    finally: conn.close()

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    email = data.get('email')
    password = data.get('password')
    otp = data.get('otp')

    record = otp_storage.get(email)
    if not record or record['otp'] != otp: return jsonify({"error": "Invalid or Expired OTP"}), 400
    if time.time() > record['expires_at']:
        del otp_storage[email]
        return jsonify({"error": "OTP Expired"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, full_name, auth_provider, profile_photo FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    conn.close()
    
    if user and check_password_hash(user[0], password):
        del otp_storage[email]
        photo = f"http://127.0.0.1:5000/static/uploads/{user[3]}" if user[3] else None
        return jsonify({"status": "success", "user": {"name": user[1], "email": email, "photo": photo}}), 200
    return jsonify({"error": "Invalid Password"}), 401

@app.route('/api/google-login', methods=['POST', 'OPTIONS'])
def google_login():
    if request.method == 'OPTIONS': return jsonify({}), 200
    try:
        data = request.json
        id_info = id_token.verify_oauth2_token(data.get('token'), requests.Request(), GOOGLE_CLIENT_ID)
        email = id_info.get('email')
        name = id_info.get('name')
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        if not cur.fetchone():
            cur.execute("INSERT INTO users (full_name, email, auth_provider) VALUES (%s, %s, 'google')", (name, email))
        cur.execute("SELECT profile_photo FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        photo = f"http://127.0.0.1:5000/static/uploads/{row[0]}" if row and row[0] else None
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "user": {"email": email, "name": name, "photo": photo}}), 200
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/profile', methods=['POST', 'OPTIONS'])
def get_profile():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT full_name, email, profile_photo FROM users WHERE email = %s", (data.get('email'),))
    user = cur.fetchone()
    conn.close()
    if user:
        photo = f"http://127.0.0.1:5000/static/uploads/{user[2]}" if user[2] else None
        return jsonify({"status": "success", "data": {"name": user[0], "email": user[1], "photo": photo}}), 200
    return jsonify({"error": "Not found"}), 404

@app.route('/api/upload-photo', methods=['POST', 'OPTIONS'])
def upload_photo():
    if request.method == 'OPTIONS': return jsonify({}), 200
    file = request.files['file']
    email = request.form.get('email')
    if file and allowed_file(file.filename, ALLOWED_IMG_EXTENSIONS):
        fname = secure_filename(f"{email}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], fname))
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET profile_photo = %s WHERE email = %s", (fname, email))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "file_url": f"http://127.0.0.1:5000/static/uploads/{fname}"}), 200
    return jsonify({"error": "Invalid file"}), 400

@app.route('/api/remove-photo', methods=['POST', 'OPTIONS'])
def remove_photo():
    if request.method == 'OPTIONS': return jsonify({}), 200
    email = request.json.get('email')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET profile_photo = NULL WHERE email = %s", (email,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"}), 200

@app.route('/api/update-password', methods=['POST', 'OPTIONS'])
def update_password():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    record = otp_storage.get(data.get('email'))
    if not record or record['otp'] != data.get('otp'): return jsonify({"error": "Invalid OTP"}), 400
    hashed = generate_password_hash(data.get('new_password'), method='pbkdf2:sha256')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed, data.get('email')))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"}), 200

# --- CORE: MEMORY DUMP UPLOAD ---
@app.route('/api/upload-dump', methods=['POST', 'OPTIONS'])
def upload_dump():
    if request.method == 'OPTIONS': return jsonify({}), 200
    if 'file' not in request.files: return jsonify({"error": "No file"}), 400
    file = request.files['file']
    email = request.form.get('email')
    analysis_type = request.form.get('analysis_type', 'standard')

    if file and allowed_file(file.filename, ALLOWED_DUMP_EXTENSIONS):
        try:
            original_name = secure_filename(file.filename)
            unique_id = str(uuid.uuid4())[:8]
            stored_name = f"{unique_id}_{original_name}"
            save_path = os.path.join(app.config['DUMP_FOLDER'], stored_name)
            file.save(save_path)
            
            size_mb = f"{round(os.path.getsize(save_path) / (1024 * 1024), 2)} MB"
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO cases (user_email, file_name, file_stored_name, file_size, status, analysis_mode) VALUES (%s, %s, %s, %s, 'queued', %s) RETURNING case_id",
                (email, original_name, stored_name, size_mb, analysis_type)
            )
            case_id = cur.fetchone()[0]
            conn.commit()
            conn.close()

            # --- THREADED ANALYSIS EXECUTION ---
            thread = threading.Thread(
                target=run_volatility_analysis, 
                args=(case_id, save_path, analysis_type, active_scans)
            )
            thread.start()
            
            return jsonify({"status": "success", "case_id": case_id, "file_name": original_name, "analysis_type": analysis_type}), 200
        except Exception as e: return jsonify({"error": str(e)}), 500
    return jsonify({"error": "Invalid file type"}), 400

# --- STOP ANALYSIS ---
@app.route('/api/stop-analysis/<int:case_id>', methods=['POST', 'OPTIONS'])
def stop_analysis(case_id):
    if request.method == 'OPTIONS': return jsonify({}), 200
    print(f"🛑 Stop Request received for Case #{case_id}")
    if case_id in active_scans:
        active_scans[case_id]['stopped'] = True
        proc = active_scans[case_id]['process']
        if proc and proc.poll() is None:
            proc.terminate()
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE cases SET status = 'cancelled', analysis_result = 'Analysis stopped by user.' WHERE case_id = %s", (case_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "success", "message": "Analysis stopped"}), 200
    return jsonify({"error": "Analysis not active"}), 400

# --- DELETE CASE ---
@app.route('/api/delete-case', methods=['POST', 'OPTIONS'])
def delete_case():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    email = data.get('email')
    case_id = data.get('case_id')
    otp = data.get('otp')

    record = otp_storage.get(email)
    if not record or record['otp'] != otp: return jsonify({"error": "Invalid or Expired OTP"}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM cases WHERE case_id = %s AND user_email = %s RETURNING file_stored_name", (case_id, email))
        row = cur.fetchone()
        if row:
            file_path = os.path.join(app.config['DUMP_FOLDER'], row[0])
            if os.path.exists(file_path): 
                try: os.remove(file_path)
                except: pass
            conn.commit()
            del otp_storage[email]
            return jsonify({"status": "success"}), 200
        else: return jsonify({"error": "Case not found"}), 404
    except Exception as e: return jsonify({"error": str(e)}), 500
    finally: conn.close()

# --- HISTORY & STATS ---
@app.route('/api/cases', methods=['POST', 'OPTIONS'])
def get_user_cases():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB Error"}), 500
    try:
        cur = conn.cursor()
        cur.execute("SELECT case_id, file_name, upload_date, file_size, status, risk_score, analysis_mode FROM cases WHERE user_email = %s ORDER BY upload_date DESC", (data.get('email'),))
        rows = cur.fetchall()
        cases = [{"case_id": r[0], "file_name": r[1], "date": r[2].strftime("%Y-%m-%d %H:%M:%S"), "size": r[3], "status": r[4], "risk_score": r[5], "analysis_mode": r[6]} for r in rows]
        conn.close()
        return jsonify({"status": "success", "cases": cases}), 200
    except: return jsonify({"error": "Failed to fetch cases"}), 500

@app.route('/api/dashboard-stats', methods=['POST', 'OPTIONS'])
def dashboard_stats():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM cases WHERE user_email = %s", (data.get('email'),))
    count = cur.fetchone()[0]
    conn.close()
    return jsonify({"status": "success", "total_cases": count}), 200

@app.route('/api/case-report/<int:case_id>', methods=['GET'])
def get_case_report(case_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT file_name, upload_date, status, risk_score, analysis_result, analysis_mode FROM cases WHERE case_id = %s", (case_id,))
    case = cur.fetchone()
    conn.close()

    if case:
        raw_report = case[4] if case[4] else ""
        threats_data = []
        clean_report = raw_report

        # --- ATS EXTRACTION LOGIC ---
        DELIMITER_START = "<<<JSON_START>>>"
        DELIMITER_END = "<<<JSON_END>>>"

        if DELIMITER_START in raw_report and DELIMITER_END in raw_report:
            try:
                # Split the string to isolate the JSON part
                parts = raw_report.split(DELIMITER_START, 1)
                if len(parts) > 1:
                    json_part, rest = parts[1].split(DELIMITER_END, 1)
                    threats_data = json.loads(json_part) # Convert string to JSON object
                    
                    # Remove the JSON from the text shown to user (clean view)
                    clean_report = parts[0] + rest.strip()
            except Exception as e:
                print(f"JSON Parsing Error: {e}")

        return jsonify({
            "status": "success",
            "data": {
                "file_name": case[0],
                "date": case[1].strftime("%Y-%m-%d %H:%M:%S"),
                "status": case[2],
                "risk_score": case[3],
                "report_content": clean_report, # Raw text (logs)
                "threats": threats_data,        # Structured JSON (ATS Table)
                "analysis_mode": case[5]
            }
        }), 200
    return jsonify({"error": "Case not found"}), 404

@app.route('/api/case-status/<int:case_id>', methods=['GET'])
def check_status(case_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT status, risk_score FROM cases WHERE case_id = %s", (case_id,))
    row = cur.fetchone()
    conn.close()
    if row: return jsonify({"status": row[0], "risk": row[1]}), 200
    return jsonify({"error": "Not found"}), 404

@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    print("🛡️ Sentra Backend Active on Port 5000 (Modular Engine)")
    app.run(debug=True, port=5000)