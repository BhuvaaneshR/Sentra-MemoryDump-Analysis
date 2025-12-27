/* frontend/js/dashboard.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    
    // 1. THEME INITIALIZATION (Immediate apply to prevent flashing)
    const savedTheme = localStorage.getItem('sentra_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);

    // 2. SECURITY CHECK: Is the user logged in?
    const storedUser = localStorage.getItem("sentra_user");
    
    if (!storedUser) {
        // Not logged in? Redirect to login.
        window.location.href = "signin.html";
        return;
    }

    const userData = JSON.parse(storedUser);
    
    // 3. UI INITIALIZATION (Sidebar & Header Data)
    
    // Update Sidebar Name (Handles different IDs across pages)
    const nameEl = document.getElementById('analyst-name') || document.getElementById('sidebar-name');
    if (nameEl) nameEl.textContent = userData.name || "Analyst";

    // Update Sidebar Email (if element exists)
    const emailEl = document.getElementById('analyst-email');
    if (emailEl) emailEl.textContent = userData.email || "";

    // CRITICAL: Update Sidebar Avatar (Persist photo across all pages)
    updateGlobalAvatar(userData.photo);

    // 4. SYSTEM HEALTH CHECK
    checkSystemStatus(BACKEND_URL);

    // 5. LOGOUT LISTENER
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
});

/**
 * Updates the Sidebar Avatar on any page.
 * Checks for the generic .avatar class inside .user-profile
 */
function updateGlobalAvatar(photoUrl) {
    // Select the avatar container in the sidebar
    // We use a specific selector to ensure we target the sidebar avatar, not the settings upload preview
    const avatarContainer = document.querySelector('.sidebar .user-profile .avatar');
    
    if (!avatarContainer) return;

    if (photoUrl) {
        // If photo exists, replace icon with Image
        avatarContainer.innerHTML = `<img src="${photoUrl}" style="width:100%; height:100%; border-radius:50%; object-fit:cover;">`;
    } else {
        // If no photo, revert to Default Icon
        avatarContainer.innerHTML = `<i class="fa-solid fa-user-secret"></i>`;
    }
}

async function checkSystemStatus(url) {
    const statusIndicator = document.getElementById('system-status-dot');
    const statusText = document.getElementById('system-status-text');

    // Only run this if the status elements exist (e.g., on Dashboard Home)
    if (!statusIndicator || !statusText) return;

    try {
        // Ping the root route of backend
        const response = await fetch(url + "/");
        if (response.ok) {
            statusIndicator.style.backgroundColor = "#00ff88"; // Green
            statusIndicator.style.boxShadow = "0 0 10px #00ff88";
            statusText.textContent = "System Online";
        } else {
            throw new Error("Backend Error");
        }
    } catch (error) {
        statusIndicator.style.backgroundColor = "#ff7b72"; // Red
        statusText.textContent = "System Offline";
        console.error("Sentra Core Disconnected:", error);
    }
}

function handleLogout() {
    if(confirm("End active session?")) {
        // Clear session data
        localStorage.removeItem("sentra_user");
        // Optional: Keep theme preference even after logout? 
        // If no, add: localStorage.removeItem("sentra_theme");
        
        window.location.href = "signin.html";
    }
}