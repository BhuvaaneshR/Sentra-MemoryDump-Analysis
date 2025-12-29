/* frontend/js/history.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    const user = JSON.parse(localStorage.getItem("sentra_user") || "{}");

    // Auth Check
    if (!user.email) {
        window.location.href = "signin.html";
        return;
    }

    const tableBody = document.getElementById('history-body');
    const refreshBtn = document.getElementById('refresh-btn');
    const searchInput = document.getElementById('search-input');

    // 1. Load Data on Init
    loadCases();

    // 2. Event Listeners
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            // Add spin animation to icon for visual feedback
            const icon = refreshBtn.querySelector('i');
            icon.classList.add('fa-spin');
            loadCases().then(() => icon.classList.remove('fa-spin'));
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
                tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:#ff7b72;">Error: ${data.error}</td></tr>`;
            }
        } catch (err) {
            console.error(err);
            tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:#ff7b72;">Connection Error to Backend</td></tr>`;
        }
    }

    function renderTable(cases) {
        if (cases.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:#8b949e;">
                <i class="fa-solid fa-folder-open" style="font-size: 2rem; margin-bottom: 10px; display:block;"></i>
                No cases found. Start a new investigation.
            </td></tr>`;
            return;
        }

        tableBody.innerHTML = cases.map(c => {
            let statusBadge = '';
            let actionBtn = '';
            let rowClass = '';

            // Status Logic
            if (c.status === 'completed') {
                statusBadge = `<span class="badge clean" style="background:rgba(0,255,136,0.1); color:#00ff88; border:1px solid rgba(0,255,136,0.2);">Completed</span>`;
                actionBtn = `<button class="icon-btn" onclick="viewReport(${c.case_id})" title="View Forensic Report">
                                <i class="fa-solid fa-file-contract" style="color:#00ff88;"></i>
                             </button>`;
            } else if (c.status === 'processing') {
                statusBadge = `<span class="badge" style="background:rgba(255,200,0,0.1); color:#ffdd00; border:1px solid rgba(255,200,0,0.2);">
                                <i class="fa-solid fa-circle-notch fa-spin"></i> Processing
                               </span>`;
                // Disable report button while processing
                actionBtn = `<button class="icon-btn" disabled style="opacity:0.5; cursor:wait;"><i class="fa-solid fa-hourglass"></i></button>`;
            } else if (c.status === 'failed') {
                statusBadge = `<span class="badge danger" style="background:rgba(255, 123, 114, 0.1); color:#ff7b72; border:1px solid rgba(255, 123, 114, 0.2);">Failed</span>`;
                actionBtn = `<button class="icon-btn" onclick="viewReport(${c.case_id})" title="View Error Log">
                                <i class="fa-solid fa-triangle-exclamation" style="color:#ff7b72;"></i>
                             </button>`;
            } else {
                statusBadge = `<span class="badge">Queued</span>`;
                actionBtn = `<button class="icon-btn" disabled><i class="fa-solid fa-clock"></i></button>`;
            }

            // Risk Score Logic
            let scoreDisplay = 'N/A';
            let scoreColor = '#c9d1d9'; // Default Grey

            if (c.risk_score !== null && c.status === 'completed') {
                scoreDisplay = c.risk_score + '/100';
                if (c.risk_score > 70) scoreColor = '#ff7b72'; // Red (High Risk)
                else if (c.risk_score > 30) scoreColor = '#d29922'; // Orange (Med Risk)
                else scoreColor = '#00ff88'; // Green (Low Risk)
            }

            return `
                <tr class="${rowClass}">
                    <td style="font-family:monospace; color:#8b949e;">#${c.case_id}</td>
                    <td style="font-weight:bold;">${c.file_name}</td>
                    <td style="color:#8b949e; font-size:0.85rem;">${c.date}</td>
                    <td style="color:#8b949e; font-size:0.85rem;">${c.size}</td>
                    <td>${statusBadge}</td>
                    <td style="color:${scoreColor}; font-weight:bold; font-family:monospace;">${scoreDisplay}</td>
                    <td>${actionBtn}</td>
                </tr>
            `;
        }).join('');
    }
});

// Global Function for HTML onclick access
function viewReport(caseId) {
    window.location.href = `report.html?id=${caseId}`;
}