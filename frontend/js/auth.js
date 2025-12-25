/* frontend/js/auth.js */

document.addEventListener('DOMContentLoaded', () => {
    
    // --- CONFIGURATION ---
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    let generatedOTP = null; // Store the OTP locally

    // --- ELEMENTS ---
    const signupForm = document.getElementById('signupForm');
    const sendOtpBtn = document.getElementById('send-otp-btn');
    const userDetailsSection = document.getElementById('user-details-section');
    const otpSection = document.getElementById('otp-section');

    // --- 1. SIGNUP: HANDLE "GENERATE OTP" CLICK ---
    if (sendOtpBtn) {
        sendOtpBtn.addEventListener('click', () => {
            // Get form values
            const fullname = document.getElementById('fullname').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const confirmPass = document.getElementById('confirm-password').value;

            hideError();

            // --- VALIDATION PHASE ---
            
            // Empty check
            if (!fullname || !email || !password || !confirmPass) {
                showError('Please fill in all details before generating OTP.');
                return;
            }

            // Email check
            if (!emailRegex.test(email)) {
                showError('Please enter a valid email address.');
                return;
            }

            // Security Password Check (7 Constraints)
            const validationResult = validateSecurityPassword(password, confirmPass, email);
            if (!validationResult.isValid) {
                showError(validationResult.message);
                return;
            }

            // --- SEND OTP PHASE ---
            
            // 1. Generate Secure 6-digit OTP
            generatedOTP = generateSecureOTP();
            console.log("DEV DEBUG (Remove in Prod): OTP is", generatedOTP);

            // 2. Disable button to prevent spam
            sendOtpBtn.textContent = "Sending...";
            sendOtpBtn.disabled = true;

            // 3. Send via EmailJS
            const templateParams = {
                to_email: email,
                to_name: fullname,
                otp: generatedOTP
            };

            // Using your specific Service & Template IDs
            emailjs.send('service_khhjwvc', 'template_tn5l1e3', templateParams)
                .then(function(response) {
                    console.log('SUCCESS!', response.status, response.text);
                    
                    // 4. UI Transition: Hide Inputs, Show OTP
                    document.getElementById('fullname').readOnly = true;
                    document.getElementById('email').readOnly = true;
                    document.getElementById('password').readOnly = true;
                    document.getElementById('confirm-password').readOnly = true;

                    // Hide the "Generate" button and show OTP section
                    sendOtpBtn.classList.add('hidden');
                    otpSection.classList.remove('hidden');

                }, function(error) {
                    console.log('FAILED...', error);
                    showError('Failed to send OTP. Please check your internet or email address.');
                    sendOtpBtn.textContent = "Generate OTP";
                    sendOtpBtn.disabled = false;
                });
        });
    }

    // --- 2. SIGNUP: HANDLE "VERIFY & REGISTER" (FORM SUBMIT) ---
    if (signupForm) {
        signupForm.addEventListener('submit', (e) => {
            e.preventDefault();

            // If we are in the OTP phase (OTP section is visible)
            if (!otpSection.classList.contains('hidden')) {
                const userOtp = document.getElementById('otp-input').value.trim();

                if (userOtp === generatedOTP) {
                    // SUCCESS
                    alert("Verification Successful! Account Created.");
                    console.log("Redirecting to dashboard...");
                    // window.location.href = "dashboard.html"; 
                } else {
                    // FAILURE
                    showError("Invalid OTP. Please try again.");
                }
            }
        });
    }

    // --- LOGIN FORM HANDLER (Keep existing login logic) ---
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            alert("Standard Login Simulation (Backend pending for Email/Pass).");
        });
    }

    // --- GOOGLE OAUTH HANDLER (CONNECTED TO BACKEND) ---
    // This function is called automatically by the Google Sign-In button
    window.handleCredentialResponse = (response) => {
        console.log("Google JWT Received. Verifying with Sentra Backend...");

        // Send the token to your Python Flask Backend
        fetch('http://127.0.0.1:5000/api/google-login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token: response.credential })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                // Success: Backend verified the user
                alert(`Login Successful!\nWelcome, ${data.user.name}`);
                console.log("Server Response:", data);
                
                // TODO: Store session token (data.token) if you implement JWT later
                // window.location.href = "dashboard.html";
            } else {
                showError("Authentication Failed: " + data.error);
            }
        })
        .catch(err => {
            console.error("Backend Error:", err);
            showError("Could not connect to Sentra Backend. Ensure 'app.py' is running.");
        });
    };
});

// --- HELPER FUNCTIONS ---

function generateSecureOTP() {
    // Generates a cryptographically strong 6-digit string
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    const otp = (array[0] % 900000) + 100000; 
    return otp.toString();
}

/**
 * Validates password against 7-point strict security constraints
 */
function validateSecurityPassword(password, confirmPassword, email) {
    if (password.length < 8 || password.length > 32) return { isValid: false, message: "Password must be between 8 and 32 characters." };
    if (password !== confirmPassword) return { isValid: false, message: "Passwords do not match." };
    
    const complexityRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&^()[\]{}|\\,.<>~`_+\-=])/;
    if (!complexityRegex.test(password)) return { isValid: false, message: "Password must contain at least 1 letter, 1 number, and 1 special character." };

    const lowerPwd = password.toLowerCase();
    if (lowerPwd.includes("password") || lowerPwd.includes("pwd")) return { isValid: false, message: "Password cannot contain 'password' or 'pwd'." };

    const vulnerableList = ["admin", "root", "user", "guest", "1234", "qwerty", "test"];
    for (let word of vulnerableList) {
        if (lowerPwd.includes(word)) return { isValid: false, message: `Password contains vulnerable sequence: '${word}'.` };
    }

    const emailParts = email.toLowerCase().split(/[@.]/);
    for (let part of emailParts) {
        if (part.length >= 3 && lowerPwd.includes(part)) return { isValid: false, message: `Password cannot contain parts of your email ('${part}').` };
    }

    if (hasSequentialOrRepeatedChars(password)) return { isValid: false, message: "No character sequences (e.g., '123') or repeats (e.g., 'aaa')." };

    return { isValid: true, message: "" };
}

function hasSequentialOrRepeatedChars(password) {
    if (/(.)\1{2,}/.test(password)) return true; // Repeats
    for (let i = 0; i < password.length - 2; i++) {
        const c1 = password.charCodeAt(i), c2 = password.charCodeAt(i+1), c3 = password.charCodeAt(i+2);
        if ((c1 + 1 === c2 && c2 + 1 === c3) || (c1 - 1 === c2 && c2 - 1 === c3)) return true; // Sequential
    }
    return false;
}

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
}

function hideError() {
    const errorMsg = document.getElementById('error-message');
    if(errorMsg) errorMsg.style.display = 'none';
}

function togglePassword(fieldId) {
    const input = document.getElementById(fieldId);
    const iconSvg = document.getElementById(`eye-icon-${fieldId}`);
    if (!input) return;
    if (input.type === "password") {
        input.type = "text";
        if (iconSvg) iconSvg.style.stroke = "#00ff88";
    } else {
        input.type = "password";
        if (iconSvg) iconSvg.style.stroke = "currentColor";
    }
}