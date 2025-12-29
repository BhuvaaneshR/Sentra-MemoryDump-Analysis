# backend/app.py
import os
import threading
import subprocess
import json
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

app = Flask(__name__)

# --- 1. MANUAL CORS OVERRIDE ---
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

SMTP_EMAIL = "sentramemorydump@gmail.com"
SMTP_PASSWORD = "pjcn avud bbup yvaz" 

GOOGLE_CLIENT_ID = "199455383424-iai5kpl9402j9btrgl70uj0rer5f8quu.apps.googleusercontent.com" 

UPLOAD_FOLDER = 'static/uploads'
DUMP_FOLDER = 'static/memory_dumps'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 * 1024 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DUMP_FOLDER'] = DUMP_FOLDER

ALLOWED_IMG_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_DUMP_EXTENSIONS = {'raw', 'mem', 'vmem', 'img'}

# --- VOLATILITY CONFIGURATION ---
PYTHON_EXEC = "python"
# Path to Volatility 3 (Use raw string for Windows path safety)
VOL_PATH = os.path.join(os.getcwd(), "volatility3", "vol.py") 

# Create directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DUMP_FOLDER, exist_ok=True)

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
        msg.set_content(f"Sentra Verification Code: {otp}\nExpires in 5 minutes.")
        msg['Subject'] = "Sentra Security Verification"
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

# --- 🚀 MULTI-MODE ANALYSIS ENGINE ---
def run_volatility_analysis(case_id, file_path, analysis_type='standard'):
    print(f"⚙️ [Case #{case_id}] Starting {analysis_type.upper()} Analysis on {file_path}...")
    
    conn = get_db_connection()
    if not conn:
        print(f"❌ [Case #{case_id}] DB Connection Failed in Thread")
        return
        
    cur = conn.cursor()

    try:
        # 1. Update Status
        cur.execute("UPDATE cases SET status = 'processing' WHERE case_id = %s", (case_id,))
        conn.commit()

        # 2. Define Plugin Chains based on Analysis Type
        plugin_chains = {
            'quick': [
                {'name': 'windows.info', 'desc': 'System Information'},
                {'name': 'windows.pslist', 'desc': 'Process List Analysis'}
            ],
            'standard': [
                {'name': 'windows.info', 'desc': 'System Information'},
                {'name': 'windows.pslist', 'desc': 'Process List Analysis'},
                {'name': 'windows.malfind', 'desc': 'Malware Injection Scan'}
            ],
            'deep': [
                {'name': 'windows.info', 'desc': 'System Information'},
                {'name': 'windows.pslist', 'desc': 'Process List Analysis'},
                {'name': 'windows.malfind', 'desc': 'Malware Injection Scan'},
                {'name': 'windows.netscan', 'desc': 'Active Network Connections'},
                {'name': 'windows.ldrmodules', 'desc': 'Unlinked DLL Check'} # Extra deep check
            ]
        }

        # Default to standard if invalid type passed
        selected_plugins = plugin_chains.get(analysis_type, plugin_chains['standard'])
        
        full_report_text = f"ANALYSIS TYPE: {analysis_type.upper()}\n" + "="*50 + "\n"
        risk_score = 0
        findings = []

        # 3. Execute Plugin Chain
        for plugin in selected_plugins:
            print(f"--> Running Plugin: {plugin['name']}...")
            
            command = [PYTHON_EXEC, VOL_PATH, '-f', file_path, plugin['name']]
            
            # Run Subprocess (Timeout varies by depth)
            timeout_limit = 600 if analysis_type == 'quick' else 1800
            
            process = subprocess.run(
                command, 
                capture_output=True, 
                text=True,
                timeout=timeout_limit 
            )

            output = process.stdout
            
            if process.returncode == 0:
                full_report_text += f"\n\n=== [ {plugin['desc']} ] ===\n{output}"
                
                # --- ADVANCED THREAT SCORING LOGIC ---
                
                # A. Malfind Logic (Injection Detection)
                if plugin['name'] == 'windows.malfind':
                    # High Risk: RWX Permissions (Executable/Writable memory)
                    if "PAGE_EXECUTE_READWRITE" in output:
                        if "Detected Memory Injection (RWX)" not in findings:
                            risk_score += 40
                            findings.append("Detected Memory Injection (RWX Permissions)")
                    
                    # High Risk: Shellcode patterns (VadS tag without MZ header)
                    if "VadS" in output and "MZ" not in output:
                        if "Potential Raw Shellcode" not in findings:
                            risk_score += 15
                            findings.append("Potential Raw Shellcode Detected")
                    
                    # High Risk: Hidden Executables (MZ header inside VadS)
                    if "MZ" in output and "VadTag" in output:
                        risk_score += 30
                        findings.append("Detected Hidden Executable (Reflective DLL)")

                # B. Process List Logic
                if plugin['name'] == 'windows.pslist':
                    # Medium Risk: Known bad process names
                    bad_procs = ['powershell.exe', 'cmd.exe', 'psexec.exe', 'vssadmin.exe'] 
                    for proc in bad_procs:
                        if f" {proc} " in output:
                            risk_score += 5 # Just a warning, context matters

                # C. Netscan Logic (C2 Detection)
                if plugin['name'] == 'windows.netscan':
                    # Medium Risk: High/Suspicious Ports often used for C2/Reverse Shells
                    suspicious_ports = [':8808', ':4444', ':6667', ':31337', ':8080', ':1337']
                    for port in suspicious_ports:
                        if port in output:
                            if f"Suspicious Port {port}" not in findings:
                                risk_score += 20
                                findings.append(f"Suspicious Network Port {port}")
                    
                    # Low Risk: Active Established Connections (Persistence)
                    if "ESTABLISHED" in output:
                        risk_score += 5

            else:
                full_report_text += f"\n\n=== [ {plugin['name']} FAILED ] ===\n{process.stderr}"

        # Cap Risk Score at 100
        risk_score = min(risk_score, 100)
        
        # Create Summary Header
        summary_header = f"RISK VERDICT: {risk_score}/100\n"
        if findings:
            summary_header += "THREATS FOUND:\n" + "\n".join([f"- {f}" for f in findings])
        else:
            summary_header += "STATUS: Clean / No obvious threats detected."
            
        full_report_text = summary_header + "\n" + "="*50 + full_report_text

        print(f"✅ [Case #{case_id}] Analysis Complete. Score: {risk_score}")

        # 4. Save Final Report to Database
        cur.execute(
            """
            UPDATE cases 
            SET status = 'completed', analysis_result = %s, risk_score = %s 
            WHERE case_id = %s
            """,
            (full_report_text, risk_score, case_id)
        )

    except Exception as e:
        print(f"❌ [Case #{case_id}] Critical Failure: {str(e)}")
        cur.execute("UPDATE cases SET status = 'failed', analysis_result = %s WHERE case_id = %s", (str(e), case_id))
    
    finally:
        conn.commit()
        cur.close()
        conn.close()

# --- 4. API ROUTES ---

@app.route('/')
def home():
    return jsonify({"status": "active", "system": "Sentra Core"})

# --- AUTH ROUTES ---
@app.route('/api/send-otp', methods=['POST', 'OPTIONS'])
def send_otp():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    otp = str(random.randint(100000, 999999))
    otp_storage[data.get('email')] = {"otp": otp, "expires_at": time.time() + 300}
    send_email_otp(data.get('email'), otp)
    return jsonify({"status": "success"}), 200

@app.route('/api/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    record = otp_storage.get(data.get('email'))
    if not record or record['otp'] != data.get('otp'): return jsonify({"error": "Invalid OTP"}), 400
    
    hashed_pw = generate_password_hash(data.get('password'), method='pbkdf2:sha256')
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (full_name, email, password_hash, auth_provider) VALUES (%s, %s, %s, 'local')", 
                    (data.get('fullname'), data.get('email'), hashed_pw))
        conn.commit()
        return jsonify({"status": "success"}), 201
    except: return jsonify({"error": "User exists"}), 400
    finally: conn.close()

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS': return jsonify({}), 200
    data = request.json
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, full_name, auth_provider, profile_photo FROM users WHERE email = %s", (data.get('email'),))
    user = cur.fetchone()
    conn.close()
    
    if user and check_password_hash(user[0], data.get('password')):
        photo = f"http://127.0.0.1:5000/static/uploads/{user[3]}" if user[3] else None
        return jsonify({"status": "success", "user": {"name": user[1], "email": data.get('email'), "photo": photo}}), 200
    return jsonify({"error": "Invalid"}), 401

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

# --- SETTINGS ROUTES ---
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
    
    # Get Analysis Type (Default to 'standard' if missing)
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
                "INSERT INTO cases (user_email, file_name, file_stored_name, file_size, status) VALUES (%s, %s, %s, %s, 'queued') RETURNING case_id",
                (email, original_name, stored_name, size_mb)
            )
            case_id = cur.fetchone()[0]
            conn.commit()
            conn.close()

            # TRIGGER BACKGROUND ANALYSIS (Pass Analysis Type)
            thread = threading.Thread(target=run_volatility_analysis, args=(case_id, save_path, analysis_type))
            thread.start()

            return jsonify({
                "status": "success", 
                "case_id": case_id, 
                "file_name": original_name,
                "analysis_type": analysis_type
            }), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    return jsonify({"error": "Invalid file type"}), 400

# --- HISTORY: GET ALL CASES ---
@app.route('/api/cases', methods=['POST', 'OPTIONS'])
def get_user_cases():
    if request.method == 'OPTIONS': return jsonify({}), 200

    data = request.json
    email = data.get('email')

    if not email: return jsonify({"error": "Email required"}), 400

    conn = get_db_connection()
    if not conn: return jsonify({"error": "DB Error"}), 500

    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT case_id, file_name, upload_date, file_size, status, risk_score 
            FROM cases 
            WHERE user_email = %s 
            ORDER BY upload_date DESC
        """, (email,))
        
        rows = cur.fetchall()
        cases = []
        for row in rows:
            cases.append({
                "case_id": row[0],
                "file_name": row[1],
                "date": row[2].strftime("%Y-%m-%d %H:%M:%S"),
                "size": row[3],
                "status": row[4],
                "risk_score": row[5]
            })

        cur.close()
        conn.close()
        return jsonify({"status": "success", "cases": cases}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- NEW: GET FULL REPORT ---
@app.route('/api/case-report/<int:case_id>', methods=['GET'])
def get_case_report(case_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT file_name, upload_date, status, risk_score, analysis_result FROM cases WHERE case_id = %s", (case_id,))
    case = cur.fetchone()
    conn.close()

    if case:
        return jsonify({
            "status": "success",
            "data": {
                "file_name": case[0],
                "date": case[1],
                "status": case[2],
                "risk_score": case[3],
                "report_content": case[4]
            }
        }), 200
    return jsonify({"error": "Case not found"}), 404

# --- STATUS CHECK (For History Page Polling) ---
@app.route('/api/case-status/<int:case_id>', methods=['GET'])
def check_status(case_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT status, risk_score FROM cases WHERE case_id = %s", (case_id,))
    row = cur.fetchone()
    conn.close()
    if row: return jsonify({"status": row[0], "risk": row[1]}), 200
    return jsonify({"error": "Not found"}), 404

# --- STATIC ---
@app.route('/static/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    print("🛡️ Sentra Backend Active on Port 5000 (Multi-Mode Analysis Ready)")
    app.run(debug=True, port=5000)