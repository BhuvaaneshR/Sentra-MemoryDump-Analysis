/* frontend/js/auth.js */

document.addEventListener('DOMContentLoaded', () => {
    
    const BACKEND_URL = "http://127.0.0.1:5000"; 
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    // Elements
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
                    // Backend Error
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

                // Send EVERYTHING to Backend
                fetch(`${BACKEND_URL}/api/signup`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        fullname: fullname, 
                        email: email, 
                        password: password,
                        otp: userOtp 
                    })
                })
                .then(res => res.json())
                .then(data => {
                    if (data.status === "success") {
                        alert("Account Verified & Created! Redirecting to Login...");
                        window.location.href = "signin.html";
                    } else {
                        showError(data.error); 
                    }
                })
                .catch(err => {
                    console.error("Signup Error:", err);
                    showError("Server error during registration.");
                });
            }
        });
    }

    // --- 3. LOGIN FORM HANDLER (UPDATED FOR DASHBOARD) ---
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
            .then(async res => {
                // Robust JSON check
                const contentType = res.headers.get("content-type");
                if (!contentType || !contentType.includes("application/json")) {
                    throw new Error("Server returned non-JSON response (Check Python logs).");
                }
                return res.json();
            })
            .then(data => {
                if (data.status === "success") {
                    // 1. Save Session
                    localStorage.setItem("sentra_user", JSON.stringify(data.user));
                    
                    // 2. Redirect to Dashboard
                    alert(`Welcome back, ${data.user.name}!`);
                    window.location.href = "home.html";
                } else {
                    showError(data.error || "Invalid credentials.");
                }
            })
            .catch(err => {
                console.error("Login Error:", err);
                showError("Connection Error: " + err.message);
            });
        });
    }

    // --- 4. GOOGLE OAUTH (UPDATED FOR DASHBOARD) ---
    window.handleCredentialResponse = (response) => {
        fetch(`${BACKEND_URL}/api/google-login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: response.credential })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                // 1. Save Session
                localStorage.setItem("sentra_user", JSON.stringify(data.user));

                // 2. Redirect to Dashboard
                alert(`Login Successful! Welcome, ${data.user.name}`);
                window.location.href = "home.html";
            } else {
                showError("Auth Failed: " + data.error);
            }
        })
        .catch(err => {
             console.error("Google Auth Error:", err);
             showError("Server Connection Failed.");
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
    const iconSvg = document.getElementById(`eye-icon-${fieldId}`);
    
    if (input) {
        if (input.type === "password") {
            input.type = "text";
            if (iconSvg) iconSvg.style.stroke = "#00ff88"; // Green when visible
        } else {
            input.type = "password";
            if (iconSvg) iconSvg.style.stroke = "currentColor"; // Default when hidden
        }
    }
}