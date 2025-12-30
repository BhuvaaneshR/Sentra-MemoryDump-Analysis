/* frontend/js/auth.js */

document.addEventListener('DOMContentLoaded', () => {
    
    const BACKEND_URL = "http://127.0.0.1:5000"; 
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    // --- COMMON HELPERS ---
    function showError(message) {
        // Try to find error container on either page
        const errorDiv = document.getElementById('error-message') || document.getElementById('error-msg');
        if (errorDiv) { errorDiv.textContent = message; errorDiv.style.display = 'block'; }
    }

    function hideError() {
        const errorDiv = document.getElementById('error-message') || document.getElementById('error-msg');
        if (errorDiv) { errorDiv.style.display = 'none'; }
    }

    function validateSecurityPassword(password, confirmPassword, email) {
        if (password.length < 8 || password.length > 32) return { isValid: false, message: "Password must be 8-32 chars." };
        if (password !== confirmPassword) return { isValid: false, message: "Passwords do not match." };
        const complexityRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&^()[\]{}|\\,.<>~`_+\-=])/;
        if (!complexityRegex.test(password)) return { isValid: false, message: "Must have 1 Letter, 1 Number, 1 Special Char." };
        if (password.toLowerCase().includes("password")) return { isValid: false, message: "Cannot contain 'password'." };
        if (email.split('@')[0].length > 3 && password.includes(email.split('@')[0])) return { isValid: false, message: "Cannot contain email parts." };
        return { isValid: true, message: "" };
    }

    // ==========================================
    //  PAGE 1: SIGNUP LOGIC
    // ==========================================
    const signupForm = document.getElementById('signupForm');
    const signupOtpBtn = document.getElementById('send-otp-btn'); // Button on Signup Page
    const otpSection = document.getElementById('otp-section');

    if (signupForm) {
        // 1. REQUEST OTP (SIGNUP)
        if (signupOtpBtn) {
            signupOtpBtn.addEventListener('click', () => {
                const fullname = document.getElementById('fullname').value.trim();
                const email = document.getElementById('email').value.trim();
                const password = document.getElementById('password').value;
                const confirmPass = document.getElementById('confirm-password').value;

                hideError();

                // Validation
                if (!fullname || !email || !password || !confirmPass) { showError('Please fill in all details.'); return; }
                if (!emailRegex.test(email)) { showError('Invalid email address.'); return; }
                const valResult = validateSecurityPassword(password, confirmPass, email);
                if (!valResult.isValid) { showError(valResult.message); return; }

                // Call Backend
                signupOtpBtn.textContent = "Sending...";
                signupOtpBtn.disabled = true;

                fetch(`${BACKEND_URL}/api/send-otp`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email, type: 'signup', fullname: fullname })
                })
                .then(res => res.json())
                .then(data => {
                    if (data.status === "success") {
                        // Lock fields & Show OTP Input
                        document.getElementById('fullname').readOnly = true;
                        document.getElementById('email').readOnly = true;
                        document.getElementById('password').readOnly = true;
                        document.getElementById('confirm-password').readOnly = true;
                        signupOtpBtn.classList.add('hidden');
                        otpSection.classList.remove('hidden');
                    } else {
                        showError(data.error);
                        signupOtpBtn.textContent = "Generate OTP";
                        signupOtpBtn.disabled = false;
                    }
                })
                .catch(err => {
                    console.error("Error:", err);
                    showError("Connection Error.");
                    signupOtpBtn.textContent = "Generate OTP";
                    signupOtpBtn.disabled = false;
                });
            });
        }

        // 2. SUBMIT SIGNUP (With OTP)
        signupForm.addEventListener('submit', (e) => {
            e.preventDefault();
            if (otpSection.classList.contains('hidden')) return; // Don't submit if OTP not sent

            const userOtp = document.getElementById('otp-input').value.trim();
            const fullname = document.getElementById('fullname').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;

            if (userOtp.length < 6) { showError("Enter 6-digit code."); return; }

            fetch(`${BACKEND_URL}/api/signup`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ fullname, email, password, otp: userOtp })
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success") {
                    alert("Account Created! Redirecting to Login...");
                    window.location.href = "signin.html";
                } else {
                    showError(data.error);
                }
            })
            .catch(err => {
                console.error("Signup Error:", err);
                showError("Server Error.");
            });
        });
    }

    // ==========================================
    //  PAGE 2: LOGIN LOGIC (UPDATED WITH OTP)
    // ==========================================
    const loginForm = document.getElementById('loginForm');
    const loginOtpBtn = document.getElementById('get-code-btn'); // Button on Login Page
    const otpMsg = document.getElementById('otp-msg');

    if (loginForm) {
        
        // 1. REQUEST OTP (LOGIN)
        if (loginOtpBtn) {
            loginOtpBtn.addEventListener('click', async () => {
                const email = document.getElementById('email').value.trim();
                
                if (!email) { showError("Enter email address first."); return; }
                if (!emailRegex.test(email)) { showError("Invalid email address."); return; }

                try {
                    loginOtpBtn.disabled = true;
                    loginOtpBtn.textContent = '...';
                    hideError();
                    if(otpMsg) otpMsg.style.display = 'none';

                    const res = await fetch(`${BACKEND_URL}/api/send-otp`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: email, type: 'login' })
                    });

                    const data = await res.json();

                    if (res.ok) {
                        // Success Feedback
                        if(otpMsg) {
                            otpMsg.style.display = 'block';
                            otpMsg.style.color = '#00ff88';
                            otpMsg.textContent = `Code sent to ${email}`;
                        }
                        
                        // Simple 60s cooldown
                        let timeLeft = 60;
                        const timer = setInterval(() => {
                            if (timeLeft <= 0) {
                                clearInterval(timer);
                                loginOtpBtn.textContent = "Get Code";
                                loginOtpBtn.disabled = false;
                            } else {
                                loginOtpBtn.textContent = `${timeLeft}s`;
                                timeLeft--;
                            }
                        }, 1000);
                        
                        // Focus OTP field
                        const otpField = document.getElementById('otp');
                        if(otpField) otpField.focus();

                    } else {
                        showError(data.error || "Failed to send code.");
                        loginOtpBtn.textContent = "Get Code";
                        loginOtpBtn.disabled = false;
                    }
                } catch (e) {
                    console.error(e);
                    showError("Connection Error.");
                    loginOtpBtn.textContent = "Get Code";
                    loginOtpBtn.disabled = false;
                }
            });
        }

        // 2. SUBMIT LOGIN (Email + Pass + OTP)
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault(); // Stop default form submit
            
            // Note: Use 'otp' because that's the ID in your signin.html
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const otp = document.getElementById('otp').value.trim();
            const loginBtn = document.getElementById('login-btn'); // Ensure your button has ID login-btn

            if (!email || !password || !otp) { 
                showError("Please enter Email, Password, and Verification Code."); 
                return; 
            }

            // UI Loading
            if(loginBtn) {
                loginBtn.disabled = true;
                loginBtn.textContent = 'Verifying...';
            }

            fetch(`${BACKEND_URL}/api/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, otp })
            })
            .then(res => res.json())
            .then(data => {
                if (data.status === "success") {
                    localStorage.setItem("sentra_user", JSON.stringify(data.user));
                    alert(`Login Successful! Welcome, ${data.user.name}`);
                    window.location.href = "home.html";
                } else {
                    showError(data.error || "Login Failed.");
                    if(loginBtn) {
                        loginBtn.disabled = false;
                        loginBtn.textContent = 'SIGN IN';
                    }
                }
            })
            .catch(err => {
                console.error("Login Error:", err);
                showError("Connection Error.");
                if(loginBtn) {
                    loginBtn.disabled = false;
                    loginBtn.textContent = 'SIGN IN';
                }
            });
        });
    }

    // --- GOOGLE OAUTH HANDLER ---
    window.handleCredentialResponse = (response) => {
        fetch(`${BACKEND_URL}/api/google-login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: response.credential })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                localStorage.setItem("sentra_user", JSON.stringify(data.user));
                alert(`Login Successful! Welcome, ${data.user.name}`);
                window.location.href = "home.html";
            } else {
                showError("Google Auth Failed: " + data.error);
            }
        })
        .catch(err => {
             console.error("Google Auth Error:", err);
             showError("Server Connection Failed.");
        });
    };
});

// --- GLOBAL HELPERS (Outside DOMContentLoaded) ---
// Necessary for onclick="" attributes in HTML (like togglePassword)

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