/* frontend/js/report.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    const params = new URLSearchParams(window.location.search);
    const caseId = params.get('id');
    const user = JSON.parse(localStorage.getItem("sentra_user") || "{}");

    if (!user.email) {
        window.location.href = "signin.html";
        return;
    }

    if (!caseId) {
        alert("No Case ID specified.");
        window.location.href = "history.html";
        return;
    }

    // UI Elements
    const elFilename = document.getElementById('r-filename');
    const elDate = document.getElementById('r-date');
    const elId = document.getElementById('r-id');
    const elMode = document.getElementById('r-mode');
    const elLog = document.getElementById('analysis-log');
    const printBtn = document.getElementById('print-report-btn'); // NEW

    // Load Data
    fetchReport();

    // Print Handler
    if (printBtn) {
        printBtn.addEventListener('click', () => {
            // Populate Print Header with Analyst Name & Current Time
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
                
                // Populate Header
                elFilename.textContent = data.file_name;
                elDate.textContent = data.date; // Now uses corrected backend format
                elId.textContent = `#${caseId}`;
                
                // Populate Mode
                const mode = data.analysis_mode ? data.analysis_mode.toUpperCase() : 'STD';
                elMode.textContent = mode;
                
                // Populate Score UI
                updateScoreUI(data.risk_score, getVerdict(data.risk_score));

                // Populate Logs
                elLog.textContent = data.report_content || "No analysis data available.";
            } else {
                elLog.textContent = "Error: " + response.error;
            }
        } catch (err) {
            console.error(err);
            elLog.textContent = "Failed to load report data.";
        }
    }

    function getVerdict(score) {
        if (score > 75) return "CRITICAL THREAT";
        if (score > 30) return "SUSPICIOUS";
        return "CLEAN";
    }

    function updateScoreUI(score, verdict) {
        const scoreText = document.getElementById('score-text');
        const verdictLabel = document.getElementById('verdict-text');

        let color = '#8b949e'; // Default

        if (score > 70) color = '#ff7b72'; // Red
        else if (score > 30) color = '#d29922'; // Orange
        else if (score >= 0) color = '#00ff88'; // Green

        scoreText.textContent = score + "/100";
        scoreText.style.color = color;
        
        verdictLabel.textContent = verdict;
        verdictLabel.style.color = color;
    }
});