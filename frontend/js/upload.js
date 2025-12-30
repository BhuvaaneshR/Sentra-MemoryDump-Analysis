/* frontend/js/upload.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    const user = JSON.parse(localStorage.getItem("sentra_user") || "{}");

    // 1. Auth Check
    if (!user.email) {
        window.location.replace("signin.html");
        return;
    }

    // 2. Element Selection
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const filePreview = document.getElementById('file-preview');
    const fileName = document.getElementById('file-name');
    const fileSize = document.getElementById('file-size');
    const removeBtn = document.getElementById('remove-file');
    const startBtn = document.getElementById('start-analysis-btn');
    // Stop Button Element (Ensure this exists in your HTML)
    const stopBtn = document.getElementById('stop-analysis-btn'); 
    const configSection = document.getElementById('analysis-config'); 
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    
    let selectedFile = null;
    let activeCaseId = null; // Track current case for stopping

    // --- DRAG & DROP HANDLERS ---
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#00ff88';
        dropZone.style.backgroundColor = 'rgba(0, 255, 136, 0.05)';
    });

    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = '#30363d';
        dropZone.style.backgroundColor = 'transparent';
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        handleFileSelect(e.dataTransfer.files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        handleFileSelect(e.target.files[0]);
    });

    // --- FILE SELECTION LOGIC ---
    function handleFileSelect(file) {
        if (!file) return;

        // Validation
        const allowedExts = ['raw', 'mem', 'vmem', 'img'];
        const ext = file.name.split('.').pop().toLowerCase();
        
        if (!allowedExts.includes(ext)) {
            showError("Security Alert: Invalid file type.");
            return;
        }

        const maxSize = 16 * 1024 * 1024 * 1024; // 16GB
        if (file.size > maxSize) {
            showError("File too large. Maximum size is 16GB.");
            return;
        }

        selectedFile = file;

        // Update UI
        fileName.textContent = file.name;
        fileSize.textContent = (file.size / (1024*1024)).toFixed(2) + " MB";
        
        dropZone.classList.add('hidden');
        filePreview.classList.remove('hidden');
        if(configSection) configSection.classList.remove('hidden'); 
        startBtn.disabled = false;
        hideError();
    }

    if (removeBtn) {
        removeBtn.addEventListener('click', () => {
            // Reset Page
            window.location.reload();
        });
    }

    // --- STOP ANALYSIS LOGIC ---
    if (stopBtn) {
        stopBtn.addEventListener('click', async () => {
            if(!activeCaseId) return;
            if(!confirm("Are you sure you want to stop the analysis?")) return;

            try {
                stopBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Stopping...';
                stopBtn.disabled = true;

                const res = await fetch(`${BACKEND_URL}/api/stop-analysis/${activeCaseId}`, {
                    method: 'POST'
                });
                
                if(res.ok) {
                    progressBar.style.backgroundColor = "#ff7b72"; // Red
                    startBtn.style.display = 'inline-block';
                    startBtn.innerHTML = '<i class="fa-solid fa-ban"></i> Cancelled';
                    stopBtn.style.display = 'none';
                    showError("Analysis stopped by user.");
                    
                    // Redirect to history to see "Cancelled" status
                    setTimeout(() => window.location.replace("history.html"), 1000);
                }
            } catch(e) {
                console.error(e);
                showError("Failed to stop analysis.");
            }
        });
    }

    // --- UPLOAD START LOGIC ---
    startBtn.addEventListener('click', () => {
        if (!selectedFile) return;

        // Get Mode
        let mode = 'standard';
        const modeInput = document.querySelector('input[name="analysis_type"]:checked');
        if (modeInput) mode = modeInput.value;

        // UI Prep
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';
        progressContainer.classList.remove('hidden');
        hideError();

        // Prepare Data
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('email', user.email);
        formData.append('analysis_type', mode); 

        const xhr = new XMLHttpRequest();
        xhr.open('POST', `${BACKEND_URL}/api/upload-dump`, true);

        // Progress Handler
        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percentComplete + '%';
                progressText.textContent = percentComplete + '%';
            }
        };

        // Completion Handler
        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    console.log("Upload Success:", response); 
                    activeCaseId = response.case_id;

                    // Update UI to Processing State
                    progressBar.style.backgroundColor = "#ffdd00"; // Yellow
                    progressText.textContent = "Processing...";
                    startBtn.style.display = 'none'; // Hide Start
                    
                    if(stopBtn) stopBtn.style.display = 'inline-block'; // Show Stop

                    showSuccess(`Case #${activeCaseId} Started. Redirecting to History...`);
                    
                    // --- REDIRECT LOGIC ---
                    console.log("Redirecting to history.html in 1.5 seconds...");
                    setTimeout(() => {
                        window.location.replace("history.html");
                    }, 1500);

                } catch (e) {
                    console.error("JSON Parse Error:", e);
                    handleError("Invalid server response.");
                }
            } else {
                console.error("Server Error:", xhr.responseText);
                handleError("Upload Failed. Check console.");
            }
        };

        xhr.onerror = function() {
            console.error("Network Error");
            handleError("Network Connection Error.");
        };

        function handleError(msg) {
            progressBar.style.backgroundColor = "#ff7b72";
            startBtn.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Retry';
            startBtn.style.display = 'inline-block';
            if(stopBtn) stopBtn.style.display = 'none';
            startBtn.disabled = false;
            showError(msg);
        }

        xhr.send(formData);
    });

    // Helpers
    function showError(msg) {
        const el = document.getElementById('upload-error');
        if (el) { el.textContent = msg; el.style.display = 'block'; }
    }
    function hideError() {
        const el = document.getElementById('upload-error');
        if(el) el.style.display = 'none';
    }
    function showSuccess(msg) {
        const el = document.getElementById('upload-success');
        if (el) { el.textContent = msg; el.style.display = 'block'; }
    }
    function hideSuccess() {
        const el = document.getElementById('upload-success');
        if(el) el.style.display = 'none';
    }
});