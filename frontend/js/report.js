/* frontend/js/report.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    const params = new URLSearchParams(window.location.search);
    const caseId = params.get('id');
    const user = JSON.parse(localStorage.getItem("sentra_user") || "{}");

    // 1. Auth & ID Check
    if (!user.email) {
        window.location.href = "signin.html";
        return;
    }

    if (!caseId) {
        alert("No Case ID specified.");
        window.location.href = "history.html";
        return;
    }

    // 2. UI Elements
    const elFilename = document.getElementById('r-filename');
    const elDate = document.getElementById('r-date');
    const elId = document.getElementById('r-id');
    const elMode = document.getElementById('r-mode');
    const elLog = document.getElementById('analysis-log');
    
    // Threat Table Elements
    const threatSection = document.getElementById('threat-summary-section');
    const threatBody = document.getElementById('threat-table-body');
    const printBtn = document.getElementById('print-report-btn');

    // 3. Load Data
    fetchReport();

    // 4. Print Handler
    if (printBtn) {
        printBtn.addEventListener('click', () => {
            // Populate hidden print header fields
            const printAnalyst = document.getElementById('print-analyst');
            const printDate = document.getElementById('print-date');
            
            if(printAnalyst) printAnalyst.textContent = user.name || user.email;
            if(printDate) printDate.textContent = new Date().toLocaleString();

            window.print();
        });
    }

    async function fetchReport() {
        try {
            const res = await fetch(`${BACKEND_URL}/api/case-report/${caseId}`);
            const response = await res.json();

            if (response.status === 'success') {
                const data = response.data;
                
                // A. Populate Header Info
                if(elFilename) elFilename.textContent = data.file_name;
                if(elDate) elDate.textContent = data.date; 
                if(elId) elId.textContent = `#${caseId}`;
                
                const mode = data.analysis_mode ? data.analysis_mode.toUpperCase() : 'STD';
                if(elMode) elMode.textContent = mode;
                
                // B. Populate Score UI
                updateScoreUI(data.risk_score, getVerdict(data.risk_score));

                // C. RENDER THREAT TABLE
                // Backend now handles the splitting/parsing. We just read the object.
                if (data.threats && Array.isArray(data.threats) && data.threats.length > 0) {
                    renderThreatTable(data.threats);
                } else {
                    // Hide section if no threats returned or if list is empty
                    if(threatSection) threatSection.style.display = 'none';
                }

                // D. Populate Logs
                if(elLog) elLog.textContent = data.report_content || "No analysis logs available.";

            } else {
                if(elLog) elLog.textContent = "Error: " + response.error;
            }
        } catch (err) {
            console.error(err);
            if(elLog) elLog.textContent = "Failed to load report data. Please check connection.";
        }
    }

    function renderThreatTable(threats) {
        if (!threatSection || !threatBody) return;

        // Show the section
        threatSection.style.display = 'block';
        
        // Build Rows
        threatBody.innerHTML = threats.map(t => {
            // Styling based on severity
            let severityStyle = 'color: #d29922; font-weight: bold;'; // Medium (Orange)
            let actionStyle = 'background: rgba(210, 153, 34, 0.1); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.3);';

            if (t.severity === 'CRITICAL' || t.severity === 'HIGH') {
                severityStyle = 'color: #ff7b72; font-weight: bold;'; // Red
                actionStyle = 'background: rgba(255, 123, 114, 0.1); color: #ff7b72; border: 1px solid rgba(255, 123, 114, 0.3);';
            }

            return `
                <tr style="border-bottom: 1px solid #30363d;">
                    <td style="font-weight: bold; color: #e6edf3; padding: 12px;">${t.process}</td>
                    <td style="font-family: monospace; color: #8b949e;">${t.pid}</td>
                    <td style="color: #c9d1d9;">${t.issue}</td>
                    <td style="${severityStyle}">${t.severity}</td>
                    <td>
                        <span style="${actionStyle} padding: 4px 10px; border-radius: 4px; font-size: 0.8rem; font-weight: 600;">
                            ${t.action}
                        </span>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function getVerdict(score) {
        if (score > 75) return "CRITICAL THREAT";
        if (score > 30) return "SUSPICIOUS";
        return "CLEAN";
    }

    function updateScoreUI(score, verdict) {
        const scoreText = document.getElementById('score-text');
        const verdictLabel = document.getElementById('verdict-text');

        let color = '#8b949e'; // Default Grey

        if (score > 70) color = '#ff7b72'; // Red
        else if (score > 30) color = '#d29922'; // Orange
        else if (score >= 0) color = '#00ff88'; // Green

        if(scoreText) {
            scoreText.textContent = score + "/100";
            scoreText.style.color = color;
        }
        
        if(verdictLabel) {
            verdictLabel.textContent = verdict;
            verdictLabel.style.color = color;
        }
    }
});