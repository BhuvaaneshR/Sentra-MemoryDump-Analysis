/* frontend/js/upload.js */

document.addEventListener('DOMContentLoaded', () => {
    const BACKEND_URL = "http://127.0.0.1:5000";
    const user = JSON.parse(localStorage.getItem("sentra_user") || "{}");

    if (!user.email) {
        window.location.href = "signin.html";
        return;
    }

    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const filePreview = document.getElementById('file-preview');
    const fileName = document.getElementById('file-name');
    const fileSize = document.getElementById('file-size');
    const removeBtn = document.getElementById('remove-file');
    const startBtn = document.getElementById('start-analysis-btn');
    const configSection = document.getElementById('analysis-config'); // NEW
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    
    let selectedFile = null;

    // --- 1. DRAG & DROP ---
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

    // --- 2. FILE SELECTION ---
    function handleFileSelect(file) {
        if (!file) return;

        const allowedExts = ['raw', 'mem', 'vmem', 'img'];
        const ext = file.name.split('.').pop().toLowerCase();
        
        if (!allowedExts.includes(ext)) {
            showError("Security Alert: Invalid file type.");
            return;
        }

        const maxSize = 16 * 1024 * 1024 * 1024;
        if (file.size > maxSize) {
            showError("File too large. Maximum size is 16GB.");
            return;
        }

        selectedFile = file;

        // UI Updates
        fileName.textContent = file.name;
        fileSize.textContent = (file.size / (1024*1024)).toFixed(2) + " MB";
        
        dropZone.classList.add('hidden');
        filePreview.classList.remove('hidden');
        configSection.classList.remove('hidden'); // SHOW CONFIG OPTIONS
        startBtn.disabled = false;
        hideError();
    }

    if (removeBtn) {
        removeBtn.addEventListener('click', () => {
            selectedFile = null;
            fileInput.value = "";
            dropZone.classList.remove('hidden');
            filePreview.classList.add('hidden');
            configSection.classList.add('hidden'); // HIDE CONFIG
            startBtn.disabled = true;
            progressContainer.classList.add('hidden');
            hideError();
            hideSuccess();
        });
    }

    // --- 3. UPLOAD LOGIC ---
    startBtn.addEventListener('click', () => {
        if (!selectedFile) return;

        // GET SELECTED MODE
        const mode = document.querySelector('input[name="analysis_type"]:checked').value;

        // UI Prep
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Uploading...';
        progressContainer.classList.remove('hidden');
        hideError();

        // Prepare Data
        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('email', user.email);
        formData.append('analysis_type', mode); // SEND MODE TO BACKEND

        const xhr = new XMLHttpRequest();
        xhr.open('POST', `${BACKEND_URL}/api/upload-dump`, true);

        xhr.upload.onprogress = function(e) {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percentComplete + '%';
                progressText.textContent = percentComplete + '%';
            }
        };

        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    progressBar.style.backgroundColor = "#00ff88";
                    startBtn.innerHTML = '<i class="fa-solid fa-check"></i> Analysis Started';
                    showSuccess(`Case #${response.case_id} Created (${mode.toUpperCase()} Mode). Redirecting...`);
                    
                    setTimeout(() => {
                        window.location.href = "history.html";
                    }, 2000);
                } catch (e) {
                    handleError("Invalid server response.");
                }
            } else {
                handleError("Upload Failed.");
            }
        };

        xhr.onerror = function() {
            handleError("Network Error.");
        };

        function handleError(msg) {
            progressBar.style.backgroundColor = "#ff7b72";
            startBtn.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Retry';
            startBtn.disabled = false;
            showError(msg);
        }

        xhr.send(formData);
    });

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