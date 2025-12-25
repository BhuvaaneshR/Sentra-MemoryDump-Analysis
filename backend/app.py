# backend/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from google.oauth2 import id_token
from google.auth.transport import requests
import secrets

app = Flask(__name__)

# Enable CORS so your Frontend (Port 5500/LiveServer) can talk to Backend (Port 5000)
CORS(app) 

# CONFIGURATION (In production, load these from .env file)
GOOGLE_CLIENT_ID="199455383424-iai5kpl9402j9btrgl70uj0rer5f8quu.apps.googleusercontent.com"
SECRET_KEY = secrets.token_hex(32) # For session security

@app.route('/')
def home():
    return jsonify({"status": "active", "message": "Sentra Security Core Online"})

# --- SECURE GOOGLE LOGIN ROUTE ---
@app.route('/api/google-login', methods=['POST'])
def google_login():
    try:
        data = request.json
        token = data.get('token')

        if not token:
            return jsonify({"error": "Missing token"}), 400

        # 1. VERIFY TOKEN WITH GOOGLE SERVERS
        # This checks: Is the token valid? Is it for THIS app? Has it expired?
        id_info = id_token.verify_oauth2_token(
            token, 
            requests.Request(), 
            GOOGLE_CLIENT_ID
        )

        # 2. Extract User Info securely
        user_email = id_info.get('email')
        user_name = id_info.get('name')
        
        # 3. (Future) Check if user exists in Database, if not, create them.
        
        print(f"✅ Secure Login Verified: {user_email}")

        return jsonify({
            "status": "success",
            "message": "Authentication Successful",
            "user": {
                "email": user_email,
                "name": user_name
            }
        }), 200

    except ValueError as e:
        # Token is invalid (forged or expired)
        print(f"❌ Security Alert: Invalid Token Attempt - {str(e)}")
        return jsonify({"error": "Invalid Token"}), 401

if __name__ == '__main__':
    print("🛡️  Sentra Backend Initialized on Port 5000")
    app.run(debug=True, port=5000)