/* frontend/js/settings.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    
    // Get basic user info stored during login
    const localUser = JSON.parse(localStorage.getItem("sentra_user") || "{}");
    if (!localUser.email) {
        window.location.href = "signin.html"; // Safety redirect
        return;
    }

    // --- 1. LOAD PROFILE DATA (Req #1 & #4) ---
    loadProfileData(localUser.email);

    // --- 2. PHOTO UPLOAD HANDLER (Req #4) ---
    const photoTrigger = document.getElementById('photo-upload-trigger');
    const fileInput = document.getElementById('file-input-hidden');

    photoTrigger.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);
        formData.append('email', localUser.email);

        // Visual Feedback
        photoTrigger.style.opacity = "0.5";

        try {
            const res = await fetch(`${BACKEND_URL}/api/upload-photo`, {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (data.status === 'success') {
                // Update UI immediately
                updateProfileUI(data.file_url);
                showSuccess("Profile photo updated successfully.");
            } else {
                showError(data.error);
            }
        } catch (err) {
            showError("Upload failed. Check server.");
        } finally {
            photoTrigger.style.opacity = "1";
        }
    });

    // --- 3. PASSWORD UPDATE FLOW (Req #2) ---
    const btnRequestOtp = document.getElementById('btn-request-otp');
    const btnConfirmChange = document.getElementById('btn-confirm-change');
    const otpContainer = document.getElementById('otp-container');

    // Step A: Validate Password & Request OTP
    btnRequestOtp.addEventListener('click', async () => {
        const newPass = document.getElementById('new-password').value;
        const confirmPass = document.getElementById('confirm-password').value;

        hideError();

        // 7-Point Security Check
        const validation = validateSecurityPassword(newPass, confirmPass, localUser.email);
        if (!validation.isValid) {
            showError(validation.message);
            return;
        }

        // Disable button while sending
        btnRequestOtp.textContent = "Sending Verification Code...";
        btnRequestOtp.disabled = true;

        try {
            const res = await fetch(`${BACKEND_URL}/api/send-otp`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: localUser.email })
            });
            const data = await res.json();

            if (data.status === 'success') {
                showSuccess("OTP Sent! Please check your email.");
                btnRequestOtp.classList.add('hidden'); // Hide request button
                otpContainer.classList.remove('hidden'); // Show OTP inputs
            } else {
                showError(data.error);
                btnRequestOtp.textContent = "Verify & Update Password";
                btnRequestOtp.disabled = false;
            }
        } catch (err) {
            showError("Connection Error: Could not send OTP.");
            btnRequestOtp.disabled = false;
        }
    });

    // Step B: Submit OTP & Update Password
    btnConfirmChange.addEventListener('click', async () => {
        const otp = document.getElementById('otp-input').value.trim();
        const newPass = document.getElementById('new-password').value;

        if (otp.length < 6) {
            showError("Please enter the 6-digit OTP.");
            return;
        }

        try {
            const res = await fetch(`${BACKEND_URL}/api/update-password`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    email: localUser.email, 
                    new_password: newPass, 
                    otp: otp 
                })
            });
            const data = await res.json();

            if (data.status === 'success') {
                alert("Password changed successfully! Please login again.");
                localStorage.removeItem("sentra_user");
                window.location.href = "signin.html";
            } else {
                showError(data.error);
            }
        } catch (err) {
            showError("Failed to update password.");
        }
    });

    // --- 4. THEME TOGGLE (Req #3) ---
    const themeSelect = document.getElementById('theme-selector');
    
    // Load saved preference
    const savedTheme = localStorage.getItem('sentra_theme') || 'dark';
    themeSelect.value = savedTheme;
    applyTheme(savedTheme);

    themeSelect.addEventListener('change', (e) => {
        applyTheme(e.target.value);
    });

    // --- FUNCTIONS ---

    async function loadProfileData(email) {
        try {
            const res = await fetch(`${BACKEND_URL}/api/profile`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            });
            const data = await res.json();

            if (data.status === 'success') {
                // Populate Inputs
                document.getElementById('display-name').value = data.data.name;
                document.getElementById('display-email').value = data.data.email;
                document.getElementById('sidebar-name').textContent = data.data.name;

                // Populate Photo if exists
                if (data.data.photo) {
                    updateProfileUI(data.data.photo);
                }
            }
        } catch (err) {
            console.error("Profile Load Error:", err);
        }
    }

    function updateProfileUI(url) {
        // Update Settings Page Preview
        const img = document.getElementById('profile-image-preview');
        const icon = document.getElementById('default-camera-icon');
        
        img.src = url;
        img.style.display = 'block';
        icon.style.display = 'none';

        // Update Sidebar Avatar
        const sidebarContainer = document.getElementById('sidebar-avatar-container');
        sidebarContainer.innerHTML = `<img src="${url}" style="width:100%; height:100%; object-fit:cover; border-radius:50%;">`;
    }

    function applyTheme(theme) {
        localStorage.setItem('sentra_theme', theme);
        const root = document.documentElement;

        if (theme === 'light') {
            root.style.setProperty('--bg-color', '#f0f2f5');
            root.style.setProperty('--card-bg', '#ffffff');
            root.style.setProperty('--text-color', '#1f1f1f');
            root.style.setProperty('--primary-color', '#009f5d'); 
        } else {
            // Dark Mode (Default)
            root.style.setProperty('--bg-color', '#0d1117');
            root.style.setProperty('--card-bg', '#161b22');
            root.style.setProperty('--text-color', '#c9d1d9');
            root.style.setProperty('--primary-color', '#00ff88');
        }
    }

    function showError(msg) {
        const el = document.getElementById('error-message');
        el.textContent = msg;
        el.style.display = 'block';
        setTimeout(() => el.style.display = 'none', 5000);
    }

    function showSuccess(msg) {
        const el = document.getElementById('success-message');
        el.textContent = msg;
        el.style.display = 'block';
        setTimeout(() => el.style.display = 'none', 5000);
    }

    function hideError() {
        document.getElementById('error-message').style.display = 'none';
    }

    /**
     * STRICT PASSWORD VALIDATION (Copied from Signup Phase)
     */
    function validateSecurityPassword(password, confirmPassword, email) {
        if (password.length < 8 || password.length > 32) 
            return { isValid: false, message: "Password must be between 8 and 32 characters." };
        
        if (password !== confirmPassword) 
            return { isValid: false, message: "Passwords do not match." };
        
        const complexityRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&^()[\]{}|\\,.<>~`_+\-=])/;
        if (!complexityRegex.test(password)) 
            return { isValid: false, message: "Password must contain 1 Letter, 1 Number, 1 Special Char." };

        const lowerPwd = password.toLowerCase();
        if (lowerPwd.includes("password") || lowerPwd.includes("pwd")) 
            return { isValid: false, message: "Password cannot contain 'password' or 'pwd'." };

        // Check against Email parts
        const emailParts = email.toLowerCase().split(/[@.]/);
        for (let part of emailParts) {
            if (part.length >= 3 && lowerPwd.includes(part)) 
                return { isValid: false, message: `Password cannot contain parts of your email ('${part}').` };
        }

        // Sequential/Repeated Check
        if (/(.)\1{2,}/.test(password)) 
            return { isValid: false, message: "No repeated characters (e.g. 'aaa')." };

        return { isValid: true, message: "" };
    }
});