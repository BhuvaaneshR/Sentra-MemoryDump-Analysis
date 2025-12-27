/* frontend/js/dashboard.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    
    // 1. SECURITY CHECK: Is the user logged in?
    // We check if "sentra_user" exists in LocalStorage (set during login)
    const storedUser = localStorage.getItem("sentra_user");
    
    if (!storedUser) {
        // Not logged in? Get out.
        window.location.href = "signin.html";
        return;
    }

    const userData = JSON.parse(storedUser);
    
    // 2. UI INITIALIZATION
    document.getElementById('analyst-name').textContent = userData.name || "Analyst";
    document.getElementById('analyst-email').textContent = userData.email || "";

    // 3. SYSTEM HEALTH CHECK
    checkSystemStatus(BACKEND_URL);

    // 4. EVENT LISTENERS
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
});

async function checkSystemStatus(url) {
    const statusIndicator = document.getElementById('system-status-dot');
    const statusText = document.getElementById('system-status-text');

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
        localStorage.removeItem("sentra_user");
        window.location.href = "signin.html";
    }
}