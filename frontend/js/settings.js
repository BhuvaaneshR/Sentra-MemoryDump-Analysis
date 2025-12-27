/* frontend/js/settings.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    
    // Get basic user info stored during login
    const user = JSON.parse(localStorage.getItem("sentra_user") || "{}");
    if (!user.email) {
        window.location.href = "signin.html"; // Safety redirect
        return;
    }

    // UI Elements
    const photoTrigger = document.getElementById('photo-upload-trigger');
    const fileInput = document.getElementById('file-input-hidden');
    const removeBtn = document.getElementById('remove-photo-btn');
    const themeSelect = document.getElementById('theme-selector');

    // --- 1. INITIALIZE PAGE ---
    loadProfileData(user.email);
    
    // Initialize Theme
    const savedTheme = localStorage.getItem('sentra_theme') || 'dark';
    themeSelect.value = savedTheme;
    // We don't need to call applyTheme here because dashboard.js does it globally on load,
    // but doing it here ensures the selector matches the current state.

    // --- 2. THEME TOGGLE HANDLER (Req #3) ---
    themeSelect.addEventListener('change', (e) => {
        const newTheme = e.target.value;
        // 1. Set Attribute for CSS
        document.documentElement.setAttribute('data-theme', newTheme);
        // 2. Save Preference
        localStorage.setItem('sentra_theme', newTheme);
    });

    // --- 3. PHOTO UPLOAD HANDLER (Req #4) ---
    photoTrigger.addEventListener('click', (e) => {
        // Prevent clicking the trigger if we clicked the remove button
        if(e.target.closest('.remove-overlay')) return;
        fileInput.click();
    });

    fileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);
        formData.append('email', user.email);

        // Visual Feedback
        photoTrigger.style.opacity = "0.5";

        try {
            const res = await fetch(`${BACKEND_URL}/api/upload-photo`, {
                method: 'POST',
                body: formData
            });
            const data = await res.json();

            if (data.status === 'success') {
                // 1. Update LocalStorage (So other pages know)
                user.photo = data.file_url;
                localStorage.setItem("sentra_user", JSON.stringify(user));

                // 2. Update UI
                updateProfileUI(data.file_url);
                updateGlobalAvatar(data.file_url); // Sync sidebar immediately
                
                showSuccess("Profile photo updated successfully.");
            } else {
                showError(data.error);
            }
        } catch (err) {
            showError("Upload failed. Check server.");
        } finally {
            photoTrigger.style.opacity = "1";
            fileInput.value = ""; // Reset input
        }
    });

    // --- 4. PHOTO REMOVE HANDLER (Req #1) ---
    if(removeBtn) {
        removeBtn.addEventListener('click', async (e) => {
            e.stopPropagation(); // Stop event bubbling to upload trigger
            
            if(!confirm("Are you sure you want to remove your profile photo?")) return;

            try {
                const res = await fetch(`${BACKEND_URL}/api/remove-photo`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: user.email })
                });

                if (res.ok) {
                    // 1. Update LocalStorage
                    user.photo = null;
                    localStorage.setItem("sentra_user", JSON.stringify(user));

                    // 2. Reset UI
                    updateProfileUI(null);
                    updateGlobalAvatar(null); // Sync sidebar immediately
                    
                    showSuccess("Photo removed.");
                } else {
                    showError("Failed to remove photo.");
                }
            } catch (err) {
                showError("Connection error.");
            }
        });
    }

    // --- 5. PASSWORD UPDATE FLOW (Req #2) ---
    const btnRequestOtp = document.getElementById('btn-request-otp');
    const btnConfirmChange = document.getElementById('btn-confirm-change');
    const otpContainer = document.getElementById('otp-container');

    // Step A: Validate Password & Request OTP
    if(btnRequestOtp) {
        btnRequestOtp.addEventListener('click', async () => {
            const newPass = document.getElementById('new-password').value;
            const confirmPass = document.getElementById('confirm-password').value;

            hideError();

            // 7-Point Security Check
            const validation = validateSecurityPassword(newPass, confirmPass, user.email);
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
                    body: JSON.stringify({ email: user.email })
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
    }

    // Step B: Submit OTP & Update Password
    if(btnConfirmChange) {
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
                        email: user.email, 
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
    }

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

                // Sync LocalStorage if backend has different photo (e.g. login sync issue)
                if (data.data.photo !== user.photo) {
                    user.photo = data.data.photo;
                    localStorage.setItem("sentra_user", JSON.stringify(user));
                }

                // Update UI
                updateProfileUI(data.data.photo);
                updateGlobalAvatar(data.data.photo);
            }
        } catch (err) {
            console.error("Profile Load Error:", err);
        }
    }

    function updateProfileUI(url) {
        // Update Settings Page Preview
        const img = document.getElementById('profile-image-preview');
        const icon = document.getElementById('default-camera-icon');
        const rmBtn = document.getElementById('remove-photo-btn');
        
        if (url) {
            img.src = url;
            img.style.display = 'block';
            icon.style.display = 'none';
            if(rmBtn) rmBtn.style.display = 'flex'; // Show remove button
        } else {
            img.style.display = 'none';
            icon.style.display = 'block';
            if(rmBtn) rmBtn.style.display = 'none'; // Hide remove button
        }
    }

    // Helper to update Sidebar Avatar immediately (duplicated logic from dashboard.js for instant feedback)
    function updateGlobalAvatar(url) {
        const sidebarAvatar = document.querySelector('.sidebar .user-profile .avatar');
        if(!sidebarAvatar) return;

        if (url) {
            sidebarAvatar.innerHTML = `<img src="${url}" style="width:100%; height:100%; object-fit:cover; border-radius:50%;">`;
        } else {
            sidebarAvatar.innerHTML = `<i class="fa-solid fa-user-secret"></i>`;
        }
    }

    function showError(msg) {
        const el = document.getElementById('error-message');
        if(el) {
            el.textContent = msg;
            el.style.display = 'block';
            setTimeout(() => el.style.display = 'none', 5000);
        }
    }

    function showSuccess(msg) {
        const el = document.getElementById('success-message');
        if(el) {
            el.textContent = msg;
            el.style.display = 'block';
            setTimeout(() => el.style.display = 'none', 5000);
        }
    }

    function hideError() {
        const el = document.getElementById('error-message');
        if(el) el.style.display = 'none';
    }

    /**
     * STRICT PASSWORD VALIDATION
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