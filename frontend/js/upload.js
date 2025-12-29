/* frontend/js/upload.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    const user = JSON.parse(localStorage.getItem("sentra_user") || "{}");

    // Auth Check
    if (!user.email) {
        window.location.href = "signin.html";
        return;
    }

    // Elements
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const filePreview = document.getElementById('file-preview');
    const fileName = document.getElementById('file-name');
    const fileSize = document.getElementById('file-size');
    const removeBtn = document.getElementById('remove-file');
    const startBtn = document.getElementById('start-analysis-btn');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    
    let selectedFile = null;

    // --- 1. DRAG & DROP HANDLERS ---
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
        dropZone.style.borderColor = '#30363d'; // Reset border
        dropZone.style.backgroundColor = 'transparent'; // Reset background
        const files = e.dataTransfer.files;
        handleFileSelect(files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        handleFileSelect(e.target.files[0]);
    });

    // --- 2. FILE SELECTION LOGIC ---
    function handleFileSelect(file) {
        if (!file) return;

        // Security: Extension Validation
        const allowedExts = ['raw', 'mem', 'vmem', 'img'];
        const ext = file.name.split('.').pop().toLowerCase();
        
        if (!allowedExts.includes(ext)) {
            showError("Security Alert: Invalid file type. Only .raw, .mem, .vmem, .img allowed.");
            return;
        }

        // Size Validation (Client-Side Check for 16GB limit)
        const maxSize = 16 * 1024 * 1024 * 1024; // 16GB in bytes
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
        startBtn.disabled = false;
        hideError();
    }

    // Remove File Handler
    if (removeBtn) {
        removeBtn.addEventListener('click', () => {
            selectedFile = null;
            fileInput.value = ""; // Clear input
            dropZone.classList.remove('hidden');
            filePreview.classList.add('hidden');
            startBtn.disabled = true;
            progressContainer.classList.add('hidden');
            hideError();
            hideSuccess();
        });
    }

    // --- 3. UPLOAD LOGIC (AJAX) ---
    startBtn.addEventListener('click', () => {
        if (!selectedFile) return;

        // Prepare UI
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';
        progressContainer.classList.remove('hidden');
        hideError();

        // Prepare Data
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('email', user.email);

        // Create Request
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
                    
                    // Success UI
                    progressBar.style.backgroundColor = "#00ff88"; 
                    startBtn.innerHTML = '<i class="fa-solid fa-check"></i> Analysis Started';
                    showSuccess(`Case #${response.case_id} Submitted. Analysis running in background.`);
                    
                    // Delay redirect to let user see success message
                    setTimeout(() => {
                        // In next phase, redirect to analysis.html?case_id=...
                        alert("File Uploaded Successfully! (Analysis Module Pending)");
                        window.location.href = "history.html";
                        location.reload(); 
                    }, 2000);

                } catch (e) {
                    handleError("Invalid server response.");
                }
            } else {
                let errorMsg = "Upload Failed.";
                try {
                    const errRes = JSON.parse(xhr.responseText);
                    if(errRes.error) errorMsg = errRes.error;
                } catch(e) {}
                handleError(errorMsg);
            }
        };

        // Network Error Handler
        xhr.onerror = function() {
            handleError("Network Error. Check backend connection.");
        };

        function handleError(msg) {
            progressBar.style.backgroundColor = "#ff7b72"; // Red
            startBtn.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Retry';
            startBtn.disabled = false;
            showError(msg || "Upload Failed. Check file size or connection.");
        }

        // Send Request
        xhr.send(formData);
    });

    // --- HELPERS ---
    function showError(msg) {
        const el = document.getElementById('upload-error');
        if (el) {
            el.textContent = msg;
            el.style.display = 'block';
        }
    }
    
    function hideError() {
        const el = document.getElementById('upload-error');
        if(el) el.style.display = 'none';
    }

    function showSuccess(msg) {
        const el = document.getElementById('upload-success');
        if (el) {
            el.textContent = msg;
            el.style.display = 'block';
        }
    }

    function hideSuccess() {
        const el = document.getElementById('upload-success');
        if(el) el.style.display = 'none';
    }
});