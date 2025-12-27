/* frontend/js/auth.js */

document.addEventListener('DOMContentLoaded', () => {
    
    const BACKEND_URL = "http://127.0.0.1:5000"; 
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    // Note: We NO LONGER generate OTP here. The server does it.

    const signupForm = document.getElementById('signupForm');
    const sendOtpBtn = document.getElementById('send-otp-btn');
    const otpSection = document.getElementById('otp-section');

    // --- 1. SIGNUP: REQUEST OTP FROM PYTHON BACKEND ---
    if (sendOtpBtn) {
        sendOtpBtn.addEventListener('click', () => {
            const fullname = document.getElementById('fullname').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const confirmPass = document.getElementById('confirm-password').value;

            hideError();

            // Client-Side Validation
            if (!fullname || !email || !password || !confirmPass) {
                showError('Please fill in all details before generating OTP.');
                return;
            }
            if (!emailRegex.test(email)) {
                showError('Please enter a valid email address.');
                return;
            }
            const validationResult = validateSecurityPassword(password, confirmPass, email);
            if (!validationResult.isValid) {
                showError(validationResult.message);
                return;
            }

            // --- CALL BACKEND TO SEND OTP ---
            sendOtpBtn.textContent = "Sending...";
            sendOtpBtn.disabled = true;

            fetch(`${BACKEND_URL}/api/send-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success") {
                    // Success UI Transition
                    console.log("Server:", data.message);
                    
                    document.getElementById('fullname').readOnly = true;
                    document.getElementById('email').readOnly = true;
                    document.getElementById('password').readOnly = true;
                    document.getElementById('confirm-password').readOnly = true;

                    sendOtpBtn.classList.add('hidden');
                    otpSection.classList.remove('hidden');
                } else {
                    // Backend Error (e.g., User already exists)
                    showError(data.error);
                    sendOtpBtn.textContent = "Generate OTP";
                    sendOtpBtn.disabled = false;
                }
            })
            .catch(err => {
                console.error("Error:", err);
                showError("Could not connect to server.");
                sendOtpBtn.textContent = "Generate OTP";
                sendOtpBtn.disabled = false;
            });
        });
    }

    // --- 2. SIGNUP: SUBMIT OTP & DATA TO BACKEND ---
    if (signupForm) {
        signupForm.addEventListener('submit', (e) => {
            e.preventDefault();

            if (!otpSection.classList.contains('hidden')) {
                const userOtp = document.getElementById('otp-input').value.trim();
                const fullname = document.getElementById('fullname').value.trim();
                const email = document.getElementById('email').value.trim();
                const password = document.getElementById('password').value;

                if (userOtp.length < 6) {
                    showError("Please enter the 6-digit code.");
                    return;
                }

                // Send EVERYTHING to Backend for Final Verification & Creation
                fetch(`${BACKEND_URL}/api/signup`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        fullname: fullname, 
                        email: email, 
                        password: password,
                        otp: userOtp // <--- Backend will verify this
                    })
                })
                .then(res => res.json())
                .then(data => {
                    if (data.status === "success") {
                        alert("Account Verified & Created! Redirecting...");
                        window.location.href = "signin.html";
                    } else {
                        showError(data.error); // e.g., "Invalid OTP"
                    }
                })
                .catch(err => {
                    console.error("Signup Error:", err);
                    showError("Server error during registration.");
                });
            }
        });
    }

    // ... (Keep your existing Login and Google Handler code below) ...
    
    // --- LOGIN FORM HANDLER ---
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;

            if (!email || !password) { showError("Please fill in all fields."); return; }

            fetch(`${BACKEND_URL}/api/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success") {
                    alert(`Welcome back, ${data.user.name}!`);
                    // window.location.href = "dashboard.html";
                } else {
                    showError(data.error || "Invalid credentials.");
                }
            })
            .catch(err => showError("Could not connect to server."));
        });
    }

    // --- GOOGLE OAUTH ---
    window.handleCredentialResponse = (response) => {
        fetch(`${BACKEND_URL}/api/google-login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: response.credential })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                alert(`Login Successful!`);
                // window.location.href = "dashboard.html";
            } else {
                showError("Auth Failed: " + data.error);
            }
        });
    };
});

// --- HELPER FUNCTIONS ---
function validateSecurityPassword(password, confirmPassword, email) {
    if (password.length < 8 || password.length > 32) return { isValid: false, message: "Password must be 8-32 chars." };
    if (password !== confirmPassword) return { isValid: false, message: "Passwords do not match." };
    const complexityRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&^()[\]{}|\\,.<>~`_+\-=])/;
    if (!complexityRegex.test(password)) return { isValid: false, message: "Must have 1 Letter, 1 Number, 1 Special Char." };
    if (password.toLowerCase().includes("password")) return { isValid: false, message: "Cannot contain 'password'." };
    if (email.split('@')[0].length > 3 && password.includes(email.split('@')[0])) return { isValid: false, message: "Cannot contain email parts." };
    return { isValid: true, message: "" };
}

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    if (errorDiv) { errorDiv.textContent = message; errorDiv.style.display = 'block'; }
}

function hideError() {
    const errorMsg = document.getElementById('error-message');
    if(errorMsg) errorMsg.style.display = 'none';
}

function togglePassword(fieldId) {
    const input = document.getElementById(fieldId);
    if (input) input.type = input.type === "password" ? "text" : "password";
}