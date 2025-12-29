document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    
    // Get Case ID from URL (e.g., report.html?id=5)
    const urlParams = new URLSearchParams(window.location.search);
    const caseId = urlParams.get('id');

    if (!caseId) {
        alert("No Case ID specified.");
        window.location.href = "history.html";
        return;
    }

    // Fetch Report Data
    fetch(`${BACKEND_URL}/api/case-report/${caseId}`)
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                renderReport(data.data, caseId);
            } else {
                alert("Error loading report: " + data.error);
            }
        })
        .catch(err => console.error("Connection Error:", err));

    function renderReport(caseData, id) {
        document.getElementById('loading-indicator').classList.add('hidden');
        document.getElementById('report-content').classList.remove('hidden');

        // Fill Details
        document.getElementById('r-filename').textContent = caseData.file_name;
        document.getElementById('r-date').textContent = new Date(caseData.date).toLocaleString();
        document.getElementById('r-id').textContent = "#" + id;

        // Threat Score UI
        const scoreEl = document.getElementById('r-score');
        const verdictEl = document.getElementById('r-verdict');
        const score = caseData.risk_score || 0;

        scoreEl.textContent = score + "/100";
        
        if (score > 70) {
            scoreEl.style.color = "#ff7b72"; // Red
            scoreEl.style.borderColor = "#ff7b72";
            verdictEl.textContent = "CRITICAL THREAT DETECTED";
            verdictEl.style.color = "#ff7b72";
        } else if (score > 30) {
            scoreEl.style.color = "#d29922"; // Orange
            scoreEl.style.borderColor = "#d29922";
            verdictEl.textContent = "SUSPICIOUS ACTIVITY";
            verdictEl.style.color = "#d29922";
        } else {
            scoreEl.style.color = "#00ff88"; // Green
            scoreEl.style.borderColor = "#00ff88";
            verdictEl.textContent = "CLEAN / LOW RISK";
            verdictEl.style.color = "#00ff88";
        }

        // Fill Terminal Log
        document.getElementById('r-log-output').textContent = caseData.report_content || "No analysis data available yet.";
    }
});