document.addEventListener('DOMContentLoaded', () => {
    // Footer quick links functionality
    const footerLinks = document.querySelectorAll('.footer-section a[data-target]');
    footerLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const target = link.getAttribute('data-target');
            showSection(target);
            
            // Scroll to the section
            const section = document.querySelector(`.scan-section[data-type="${target}"]`);
            if (section) {
                section.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });

    // Theme switching functionality
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    
    // Initialize theme - always start with dark mode unless explicitly set to light
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'light') {
        document.documentElement.setAttribute('data-theme', 'light');
        updateThemeIcon('light');
    } else {
        document.documentElement.setAttribute('data-theme', 'dark');
        updateThemeIcon('dark');
        localStorage.setItem('theme', 'dark'); // Ensure dark theme is saved
    }
    
    // Theme toggle button click handler
    themeToggleBtn.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(newTheme);
    });
    
    // Update theme icon
    function updateThemeIcon(theme) {
        const icon = themeToggleBtn.querySelector('i');
        if (theme === 'light') {
            icon.className = 'fas fa-sun';
        } else {
            icon.className = 'fas fa-moon';
        }
    }

    // Initialize variables
    const scanOptions = document.querySelectorAll('.option-card');
    const scanSections = document.querySelectorAll('.scan-section');
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.querySelector('#file-input');
    const urlInput = document.querySelector('#url-input');
    const hashInput = document.querySelector('#hash-input');
    const scanButtons = document.querySelectorAll('.scan-button');
    const resultContainers = document.querySelectorAll('.result-container');
    const loader = document.querySelector('.loader');

    // Add ripple effect to buttons
    document.querySelectorAll('.scan-button, .option-card').forEach(button => {
        button.addEventListener('click', createRipple);
    });

    // Initialize scan options
    scanOptions.forEach(option => {
        option.addEventListener('click', () => {
            const target = option.getAttribute('data-target');
            showSection(target);
            animateTransition(option);
        });
    });

    // Initialize file upload
    if (uploadArea && fileInput) {
        // Click to upload
        uploadArea.addEventListener('click', () => {
            fileInput.click();
        });

        // File input change
        fileInput.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (file) {
                handleFileUpload(file);
            }
        });

        // Drag and drop
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const file = e.dataTransfer.files[0];
            if (file) {
                handleFileUpload(file);
            }
        });
    }

    // Initialize scan buttons
    scanButtons.forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault(); // Prevent default button behavior
            const section = button.closest('.scan-section');
            const type = section.getAttribute('data-type');
            
            try {
                let result;
                
                switch(type) {
                    case 'file':
                        if (!fileInput.files[0]) {
                            throw new Error('Please select a file first');
                        }
                        result = await scanFile();
                        break;
                    case 'url':
                        if (!urlInput.value.trim()) {
                            throw new Error('Please enter a URL');
                        }
                        showLoader();
                        result = await scanUrl();
                        break;
                    case 'hash':
                        if (!hashInput.value.trim()) {
                            throw new Error('Please enter a hash');
                        }
                        showLoader();
                        result = await scanHash();
                        break;
                }
                
                if (result) {
                    displayResult(result, type);
                    showNotification('Scan completed successfully!', 'success');
                }
            } catch (error) {
                showNotification(error.message || 'An error occurred during scanning', 'error');
            } finally {
                if (type !== 'file') { // Only hide loader for non-file scans here
                    hideLoader();
                }
            }
        });
    });

    // Helper Functions
    function createRipple(event) {
        const button = event.currentTarget;
        const ripple = document.createElement('span');
        const rect = button.getBoundingClientRect();
        
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        ripple.style.width = ripple.style.height = `${size}px`;
        ripple.style.left = `${x}px`;
        ripple.style.top = `${y}px`;
        ripple.className = 'ripple';
        
        button.appendChild(ripple);
        setTimeout(() => ripple.remove(), 600); // Remove ripple after animation
    }

    function showSection(target) {
        scanSections.forEach(section => {
            if (section.getAttribute('data-type') === target) {
                section.classList.add('active');
                animateTransition(section);
            } else {
                section.classList.remove('active');
            }
        });
    }

    function animateTransition(element) {
        element.style.animation = 'none';
        element.offsetHeight; // Trigger reflow
        element.style.animation = 'slideIn 0.5s ease';
    }

    async function handleFileUpload(file) {
        if (!file) return;
        
        // Check file size (10MB limit)
        if (file.size > 10 * 1024 * 1024) {
            showNotification('File size exceeds 16MB limit', 'error');
            return;
        }

        // Check file extension
        const allowedExtensions = ['exe', 'dll', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar', '7z', 'txt', 'js', 'py', 'php'];
        const fileExtension = file.name.split('.').pop().toLowerCase();
        if (!allowedExtensions.includes(fileExtension)) {
            showNotification(`File type not allowed. Supported types: ${allowedExtensions.join(', ')}`, 'error');
            return;
        }
        
        // Update UI to show selected file
        const uploadContent = uploadArea.querySelector('.upload-content');
        if (uploadContent) {
            uploadContent.innerHTML = `
                <i class="fas fa-file"></i>
                <p>${file.name}</p>
                <p class="upload-hint">${(file.size / 1024).toFixed(2)} KB</p>
            `;
        }
        
        // Add success animation
        uploadArea.classList.add('upload-success');
        setTimeout(() => {
            uploadArea.classList.remove('upload-success');
        }, 1000);

        // Enable scan button
        const scanButton = document.querySelector('#file-scan-button');
        if (scanButton) {
            scanButton.disabled = false;
        }
    }

    async function scanFile() {
        const file = fileInput.files[0];
        if (!file) {
            throw new Error('Please select a file first');
        }

        const formData = new FormData();
        formData.append('file', file);

        try {
            showLoader(); // Show loader before starting the scan
            
            // Add a minimum display time of 1.5 seconds
            const startTime = Date.now();
            
            const response = await fetch('/scan/file', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to scan file');
            }

            const result = await response.json();
            
            // Ensure loader is shown for at least 1.5 seconds
            const elapsedTime = Date.now() - startTime;
            if (elapsedTime < 1500) {
                await new Promise(resolve => setTimeout(resolve, 1500 - elapsedTime));
            }
            
            return result;
        } catch (error) {
            console.error('Scan error:', error);
            throw error;
        } finally {
            hideLoader(); // Hide loader after scan completes or fails
        }
    }

    async function scanUrl() {
        const url = urlInput.value.trim();
        if (!url) {
            throw new Error('Please enter a URL');
        }

        const formData = new FormData();
        formData.append('url', url);

        try {
            const response = await fetch('/scan_url', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to scan URL');
            }

            const result = await response.json();
            return result;
        } catch (error) {
            console.error('Scan error:', error);
            throw error;
        }
    }

    async function scanHash() {
        const hash = hashInput.value.trim();
        if (!hash) {
            throw new Error('Please enter a hash');
        }

        try {
            showLoader(); // Show loader before starting the scan
            
            // Add a minimum display time of 1.5 seconds
            const startTime = Date.now();

            const response = await fetch('/scan/hash', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ hash })
            });

            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.error || 'Failed to scan hash');
            }

            // Ensure loader is shown for at least 1.5 seconds
            const elapsedTime = Date.now() - startTime;
            if (elapsedTime < 1500) {
                await new Promise(resolve => setTimeout(resolve, 1500 - elapsedTime));
            }

            return result;
        } catch (error) {
            console.error('Scan error:', error);
            throw error;
        } finally {
            hideLoader(); // Hide loader after scan completes or fails
        }
    }

    function displayResult(result, type) {
        const container = document.querySelector(`.result-container[data-type="${type}"]`);
        if (!container) return;

        let html = '';
        
        switch(type) {
            case 'file':
                html = generateFileResultHTML(result);
                break;
            case 'url':
                html = `
                    <div class="result-box ${result.is_malicious ? 'malware-detected' : 'clean'}">
                        <h3>Scan Results</h3>
                        <div class="result-details">
                            <p><strong>URL:</strong> ${result.url}</p>
                            <p><strong>Status:</strong> ${result.is_malicious ? 'Potentially Harmful' : 'Safe'}</p>
                        </div>
                    </div>
                `;
                
                if (result.is_malicious) {
                    html += `
                        <div class="malware-details">
                            <h4>Threat Details</h4>
                            <div class="malware-list">
                                <div class="malware-item">
                                    <div class="malware-header">
                                        <i class="fas fa-exclamation-triangle"></i>
                                        <span class="malware-name">${result.threat_type || 'Unknown Threat'}</span>
                                        <span class="severity-badge high">High</span>
                                    </div>
                                    <div class="malware-info">
                                        <p><strong>Platform:</strong> ${result.platform || 'Unknown'}</p>
                                        <p><strong>Description:</strong> Malicious URL detected. This URL has been flagged as potentially harmful.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }
                break;

            case 'hash':
                html = `
                    <div class="result-box ${result.malware_detected ? 'malware-detected' : 'clean'}">
                        <h3>Scan Results</h3>
                        <div class="result-details">
                            <p><strong>Hash:</strong> ${result.hash}</p>
                            <p><strong>Status:</strong> ${result.malware_detected ? 'Malware Detected' : 'Clean'}</p>
                        </div>
                    </div>
                `;
                
                if (result.malware_detected && result.detection_details) {
                    html += `
                        <div class="malware-details">
                            <h4>Threat Details</h4>
                            <div class="malware-list">
                                <div class="malware-item">
                                    <div class="malware-header">
                                        <i class="fas fa-exclamation-triangle"></i>
                                        <span class="malware-name">${result.detection_details.type || 'Unknown Malware'}</span>
                                        <span class="severity-badge high">High</span>
                                    </div>
                                    <div class="malware-info">
                                        <p><strong>Type:</strong> ${result.detection_details.type || 'Unknown'}</p>
                                        <p><strong>Description:</strong> This hash has been identified as malicious in our database.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                }
                break;
        }

        container.innerHTML = html;
        container.classList.add('active');
        animateTransition(container);
    }

    function generateFileResultHTML(result) {
        let html = `
            <div class="result-box ${result.malware_detected ? 'malware-detected' : 'clean'}">
                <h3>Scan Results</h3>
                <div class="result-details">
                    <p><strong>File Name:</strong> ${result.file_name}</p>
                    <p><strong>File Size:</strong> ${result.file_size}</p>
                    <p><strong>File Type:</strong> ${result.file_type}</p>
                    <p><strong>SHA-256 Hash:</strong> ${result.sha256_hash}</p>
                    <p><strong>Status:</strong> ${result.malware_detected ? 'Malware Detected' : 'Clean'}</p>
                </div>
            </div>
        `;

        if (result.malware_detected && result.detection_details && result.detection_details.length > 0) {
            html += `
                <div class="malware-details">
                    <h4>Detected Malware Details</h4>
                    <div class="malware-list">
                        ${result.detection_details.map(detail => `
                            <div class="malware-item">
                                <div class="malware-header">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    <span class="malware-name">${detail.rule}</span>
                                    <span class="severity-badge ${detail.severity.toLowerCase()}">${detail.severity}</span>
                                </div>
                                <div class="malware-info">
                                    <p><strong>Type:</strong> ${detail.malware_type}</p>
                                    <p><strong>Description:</strong> ${detail.description}</p>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        return html;
    }

    function showLoader() {
        const loaderContent = document.querySelector('.loader-content');
        if (loaderContent) {
            loaderContent.innerHTML = `
                <div class="spinner"></div>
                <div class="loader-text">Scanning...</div>
            `;
        }
        loader.classList.add('active');
        document.body.style.overflow = 'hidden'; // Prevent scrolling while loading
    }

    function hideLoader() {
        loader.classList.remove('active');
        document.body.style.overflow = ''; // Restore scrolling
    }

    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        // Trigger reflow
        notification.offsetHeight;
        
        notification.classList.add('show');
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

    function showScanResult(result) {
        const malwareTypeBox = document.getElementById('malware-type-box');
        const malwareTypeList = document.getElementById('malware-type-list');
        
        // Clear previous results
        malwareTypeList.innerHTML = '';
        
        if (result.malware_detected && result.malware_types && result.malware_types.length > 0) {
            // Show the malware type box
            malwareTypeBox.style.display = 'block';
            
            // Add each malware type to the list
            result.malware_types.forEach(type => {
                const li = document.createElement('li');
                li.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${type}`;
                malwareTypeList.appendChild(li);
            });
        } else {
            // Hide the malware type box if no malware detected
            malwareTypeBox.style.display = 'none';
        }
    }
});