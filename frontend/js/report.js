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
    const elements = {
        filename: document.getElementById('r-filename'),
        date: document.getElementById('r-date'),
        id: document.getElementById('r-id'),
        mode: document.getElementById('r-mode'),
        log: document.getElementById('analysis-log'),
        scoreText: document.getElementById('score-text'),
        verdictText: document.getElementById('verdict-text'),
        threatSection: document.getElementById('threat-summary-section'),
        threatBody: document.getElementById('threat-table-body'),
        printBtn: document.getElementById('print-report-btn'),
        exportBtn: document.getElementById('export-btn') // The CSV Export Button
    };

    // Store raw logs here for the export button to access
    let rawReportContent = ""; 

    // 3. Load Data
    fetchReport();

    // 4. Print Handler
    if (elements.printBtn) {
        elements.printBtn.addEventListener('click', () => {
            const printAnalyst = document.getElementById('print-analyst');
            const printDate = document.getElementById('print-date');
            
            if(printAnalyst) printAnalyst.textContent = user.name || user.email;
            if(printDate) printDate.textContent = new Date().toLocaleString();

            window.print();
        });
    }

    // 5. EXPORT CSV HANDLER (Video-Style Export)
    if (elements.exportBtn) {
        elements.exportBtn.addEventListener('click', () => {
            if (!rawReportContent) {
                alert("Analysis logs are not loaded yet.");
                return;
            }

            // Create a Blob from the raw text (which is already CSV formatted by backend)
            const blob = new Blob([rawReportContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            
            // Create temporary link to trigger download
            const link = document.createElement("a");
            link.setAttribute("href", url);
            link.setAttribute("download", `Sentra_Report_${caseId}.csv`);
            link.style.visibility = 'hidden';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    }

    // --- CORE LOGIC ---

    async function fetchReport() {
        try {
            const res = await fetch(`${BACKEND_URL}/api/case-report/${caseId}`);
            const response = await res.json();

            if (response.status === 'success') {
                const data = response.data;
                
                // Store raw content for the Export button
                rawReportContent = data.report_content || "No Data";

                // A. Populate Header Info
                if(elements.filename) elements.filename.textContent = data.file_name;
                if(elements.date) elements.date.textContent = data.date; 
                if(elements.id) elements.id.textContent = `#${caseId}`;
                
                const mode = data.analysis_mode ? data.analysis_mode.toUpperCase() : 'STD';
                if(elements.mode) elements.mode.textContent = mode;
                
                // B. Populate Score UI
                updateScoreUI(data.risk_score, getVerdict(data.risk_score));

                // C. RENDER THREAT TABLE (Guaranteed Visibility)
                // We pass the threats array (or empty array) to the renderer regardless of size
                const threats = data.threats || [];
                renderThreatTable(threats);

                // D. Populate Logs (Visual)
                if(elements.log) elements.log.textContent = rawReportContent;

            } else {
                if(elements.log) elements.log.textContent = "Error: " + response.error;
            }
        } catch (err) {
            console.error(err);
            if(elements.log) elements.log.textContent = "Failed to load report data. Please check connection.";
        }
    }

    function renderThreatTable(threats) {
        if (!elements.threatSection || !elements.threatBody) return;

        // ALWAYS show the section so the user knows the check was performed
        elements.threatSection.style.display = 'block';
        elements.threatBody.innerHTML = '';

        // 1. Handle Clean State
        if (threats.length === 0) {
            elements.threatBody.innerHTML = `
                <tr style="border-bottom: 1px solid #30363d;">
                    <td colspan="5" style="text-align:center; padding:30px; color:#00ff88;">
                        <i class="fa-solid fa-check-circle" style="font-size: 1.5rem; margin-bottom: 10px; display:block;"></i>
                        <strong>System Clean</strong><br>
                        <span style="font-size:0.85rem; color:#8b949e;">No active threats detected in memory dump.</span>
                    </td>
                </tr>
            `;
            return;
        }

        // 2. Render Threats
        elements.threatBody.innerHTML = threats.map(t => {
            // Styling based on severity
            let color = '#d29922'; // Default Orange (Medium)
            let bgStyle = 'background: rgba(210, 153, 34, 0.1); border: 1px solid rgba(210, 153, 34, 0.3);';

            if (t.severity === 'CRITICAL') {
                color = '#ff7b72'; // Red
                bgStyle = 'background: rgba(255, 123, 114, 0.1); border: 1px solid rgba(255, 123, 114, 0.3);';
            } else if (t.severity === 'HIGH') {
                color = '#ff7b72'; 
                bgStyle = 'background: rgba(255, 123, 114, 0.1); border: 1px solid rgba(255, 123, 114, 0.3);';
            }

            return `
                <tr style="border-bottom: 1px solid #30363d;">
                    <td style="font-weight: bold; color: #e6edf3; padding: 12px;">
                        <i class="fa-solid fa-bug" style="margin-right:8px; color:${color};"></i>
                        ${t.process}
                    </td>
                    <td style="font-family: monospace; color: #8b949e;">${t.pid}</td>
                    <td style="color: #c9d1d9;">${t.issue}</td>
                    <td style="color:${color}; font-weight:bold;">${t.severity}</td>
                    <td>
                        <button onclick="copyToClipboard('${t.pid}')" title="Copy Kill Command" 
                                style="${bgStyle} color:${color}; padding: 6px 12px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; cursor: pointer; transition: all 0.2s;">
                            <i class="fa-solid fa-skull"></i> ${t.action}
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function getVerdict(score) {
        if (score > 75) return "CRITICAL THREAT";
        if (score > 30) return "SUSPICIOUS";
        return "CLEAN SYSTEM";
    }

    function updateScoreUI(score, verdict) {
        const { scoreText, verdictText } = elements;
        let color = '#8b949e'; // Default Grey

        if (score > 70) color = '#ff7b72'; // Red
        else if (score > 30) color = '#d29922'; // Orange
        else if (score >= 0) color = '#00ff88'; // Green

        if(scoreText) {
            scoreText.textContent = score + "/100";
            scoreText.style.color = color;
        }
        
        if(verdictText) {
            verdictText.textContent = verdict;
            verdictText.style.color = color;
            verdictText.style.borderColor = color; 
        }
    }

    // --- HELPER: COPY TO CLIPBOARD ---
    // Exposed to window so the HTML onclick="" can find it
    window.copyToClipboard = (pid) => {
        if (!pid || pid === '?' || pid === 'N/A') {
            alert("No valid Process ID to kill.");
            return;
        }
        
        // Command to kill process in Windows
        const command = `taskkill /F /PID ${pid}`;
        
        navigator.clipboard.writeText(command).then(() => {
            alert(`[COPIED] Run this in CMD/PowerShell:\n\n${command}`);
        }).catch(err => {
            console.error('Failed to copy: ', err);
        });
    };
});