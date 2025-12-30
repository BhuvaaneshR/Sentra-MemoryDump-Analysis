/* frontend/js/history.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    const user = JSON.parse(localStorage.getItem("sentra_user") || "{}");

    if (!user.email) {
        window.location.href = "signin.html";
        return;
    }

    const tableBody = document.getElementById('history-body');
    const refreshBtn = document.getElementById('refresh-btn');
    const searchInput = document.getElementById('search-input');

    // Load Data
    loadCases();

    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            const icon = refreshBtn.querySelector('i');
            if(icon) icon.classList.add('fa-spin');
            loadCases().then(() => { if(icon) icon.classList.remove('fa-spin'); });
        });
    }
    
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const term = e.target.value.toLowerCase();
            const rows = tableBody.querySelectorAll('tr');
            rows.forEach(row => {
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(term) ? '' : 'none';
            });
        });
    }

    // --- FUNCTIONS ---

    async function loadCases() {
        try {
            const res = await fetch(`${BACKEND_URL}/api/cases`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: user.email })
            });
            const data = await res.json();

            if (data.status === 'success') {
                renderTable(data.cases);
            } else {
                tableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:20px; color:#ff7b72;">Error: ${data.error}</td></tr>`;
            }
        } catch (err) {
            console.error(err);
            tableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:20px; color:#ff7b72;">Connection Error</td></tr>`;
        }
    }

    function renderTable(cases) {
        if (cases.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:30px; color:#8b949e;">No cases found.</td></tr>`;
            return;
        }

        tableBody.innerHTML = cases.map(c => {
            let statusBadge = '';
            let actionBtn = '';
            
            // --- STATUS LOGIC ---
            if (c.status === 'completed') {
                statusBadge = `<span class="badge clean" style="background:rgba(0,255,136,0.1); color:#00ff88; border:1px solid rgba(0,255,136,0.2);">Completed</span>`;
                actionBtn = `<button class="icon-btn" onclick="viewReport(${c.case_id})" title="View Report"><i class="fa-solid fa-file-contract" style="color:#00ff88;"></i></button>`;
            } 
            else if (c.status === 'processing') {
                statusBadge = `<span class="badge" style="background:rgba(255,200,0,0.1); color:#ffdd00; border:1px solid rgba(255,200,0,0.2);"><i class="fa-solid fa-circle-notch fa-spin"></i> Processing</span>`;
                
                // NEW: STOP BUTTON instead of disabled hourglass
                actionBtn = `<button class="icon-btn" onclick="stopCase(${c.case_id})" title="Stop Analysis" style="color:#ff7b72; border:1px solid #ff7b72;">
                                <i class="fa-solid fa-stop"></i>
                             </button>`;
            } 
            else if (c.status === 'failed' || c.status === 'cancelled') {
                statusBadge = `<span class="badge danger" style="background:rgba(255, 123, 114, 0.1); color:#ff7b72; border:1px solid rgba(255, 123, 114, 0.2);">${c.status.toUpperCase()}</span>`;
                actionBtn = `<button class="icon-btn" onclick="viewReport(${c.case_id})" title="View Log"><i class="fa-solid fa-triangle-exclamation" style="color:#ff7b72;"></i></button>`;
            } 
            else {
                statusBadge = `<span class="badge">Queued</span>`;
                actionBtn = `<button class="icon-btn" disabled><i class="fa-solid fa-clock"></i></button>`;
            }

            // Score Logic
            let scoreDisplay = (c.status === 'completed') ? (c.risk_score + '/100') : 'N/A';
            let scoreColor = '#c9d1d9';
            if (c.risk_score > 70) scoreColor = '#ff7b72'; 
            else if (c.risk_score > 30) scoreColor = '#d29922'; 
            else if (c.status === 'completed') scoreColor = '#00ff88';

            const mode = c.analysis_mode ? c.analysis_mode.toUpperCase() : 'STD';

            return `
                <tr>
                    <td style="font-family:monospace; color:#8b949e;">#${c.case_id}</td>
                    <td style="font-weight:bold;">${c.file_name}</td>
                    <td style="color:#8b949e; font-size:0.85rem;">${c.date}</td>
                    <td style="color:#8b949e; font-size:0.85rem;">${c.size}</td>
                    <td>${statusBadge}</td>
                    <td><span class="mode-badge ${c.analysis_mode}">${mode}</span></td>
                    <td style="color:${scoreColor}; font-weight:bold;">${scoreDisplay}</td>
                    <td>${actionBtn}</td>
                </tr>
            `;
        }).join('');
    }
});

// --- GLOBAL FUNCTIONS (Accessible by HTML) ---

function viewReport(caseId) {
    window.location.href = `report.html?id=${caseId}`;
}

// NEW FUNCTION: Handles the API call to stop analysis
async function stopCase(caseId) {
    if(!confirm(`Are you sure you want to stop analysis for Case #${caseId}?`)) return;

    try {
        const BACKEND_URL = "http://127.0.0.1:5000";
        const res = await fetch(`${BACKEND_URL}/api/stop-analysis/${caseId}`, { method: 'POST' });
        
        if(res.ok) {
            alert("Analysis Stopped.");
            location.reload(); // Refresh list to show "Cancelled"
        } else {
            alert("Failed to stop. It might have already finished.");
            location.reload();
        }
    } catch(e) {
        console.error(e);
        alert("Connection Error.");
    }
}