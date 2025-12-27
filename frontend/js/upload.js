document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const filePreview = document.getElementById('file-preview');
    const startBtn = document.getElementById('start-analysis-btn');

    // Drag & Drop Effects
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
        const files = e.dataTransfer.files;
        handleFileSelect(files[0]);
    });

    fileInput.addEventListener('change', (e) => {
        handleFileSelect(e.target.files[0]);
    });

    function handleFileSelect(file) {
        if (!file) return;

        // Security: Client-Side Extension Validation
        const allowedExts = ['raw', 'mem', 'vmem', 'img'];
        const ext = file.name.split('.').pop().toLowerCase();
        
        if (!allowedExts.includes(ext)) {
            alert("Security Alert: Invalid file type. Only raw memory dumps allowed.");
            return;
        }

        // Show Preview
        document.getElementById('file-name').textContent = file.name;
        document.getElementById('file-size').textContent = (file.size / (1024*1024)).toFixed(2) + " MB";
        dropZone.classList.add('hidden');
        filePreview.classList.remove('hidden');
        startBtn.disabled = false;
    }

    // TODO: Add 'click' listener to startBtn to trigger Backend Upload API
}); 