// Main JavaScript for Cybersecurity Threat Analyzer

// Initialize tooltips and popovers
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    const popoverList = popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Auto-hide alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
});

// Handle packet filter form
document.addEventListener('DOMContentLoaded', function() {
    const packetFilterForm = document.getElementById('packetFilterForm');
    if (packetFilterForm) {
        packetFilterForm.addEventListener('submit', function(e) {
            const scanId = document.getElementById('scan_id').value;
            const protocol = document.getElementById('protocol').value;
            const sourceIp = document.getElementById('source_ip').value;
            const destIp = document.getElementById('destination_ip').value;
            
            // Build query string
            let queryParams = [];
            if (scanId) queryParams.push(`scan_id=${scanId}`);
            if (protocol) queryParams.push(`protocol=${protocol}`);
            if (sourceIp) queryParams.push(`source_ip=${sourceIp}`);
            if (destIp) queryParams.push(`destination_ip=${destIp}`);
            
            // Redirect with query parameters
            if (queryParams.length > 0) {
                window.location.href = `${window.location.pathname}?${queryParams.join('&')}`;
            } else {
                window.location.href = window.location.pathname;
            }
            
            e.preventDefault();
        });
    }
});

// Handle threat filter form
document.addEventListener('DOMContentLoaded', function() {
    const threatFilterForm = document.getElementById('threatFilterForm');
    if (threatFilterForm) {
        threatFilterForm.addEventListener('submit', function(e) {
            const severity = document.getElementById('severity').value;
            const status = document.getElementById('status').value;
            
            // Build query string
            let queryParams = [];
            if (severity) queryParams.push(`severity=${severity}`);
            if (status) queryParams.push(`status=${status}`);
            
            // Redirect with query parameters
            if (queryParams.length > 0) {
                window.location.href = `${window.location.pathname}?${queryParams.join('&')}`;
            } else {
                window.location.href = window.location.pathname;
            }
            
            e.preventDefault();
        });
    }
});

// Handle real-time updates for network scan status
function pollScanStatus(scanId) {
    if (!scanId) return;
    
    const statusElement = document.getElementById('scan-status');
    const packetCountElement = document.getElementById('packet-count');
    const threatCountElement = document.getElementById('threat-count');
    
    if (!statusElement) return;
    
    function updateStatus() {
        fetch(`/api/network/scan_status/${scanId}/`)
            .then(response => response.json())
            .then(data => {
                // Update status badge
                statusElement.textContent = data.status;
                statusElement.className = `badge ${data.status === 'completed' ? 'bg-success' : data.status === 'running' ? 'bg-primary' : data.status === 'failed' ? 'bg-danger' : 'bg-secondary'}`;
                
                // Update counts
                if (packetCountElement) packetCountElement.textContent = data.packet_count;
                if (threatCountElement) threatCountElement.textContent = data.threat_count;
                
                // Continue polling if scan is running
                if (data.status === 'running') {
                    setTimeout(updateStatus, 3000);
                }
            })
            .catch(error => {
                console.error('Error polling scan status:', error);
                setTimeout(updateStatus, 5000);
            });
    }
    
    // Start polling
    updateStatus();
}

// Function to acknowledge an alert
function acknowledgeAlert(alertId) {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/dashboard/alerts/';
    
    const csrfInput = document.createElement('input');
    csrfInput.type = 'hidden';
    csrfInput.name = 'csrfmiddlewaretoken';
    csrfInput.value = document.querySelector('[name=csrfmiddlewaretoken]').value;
    
    const alertIdInput = document.createElement('input');
    alertIdInput.type = 'hidden';
    alertIdInput.name = 'alert_id';
    alertIdInput.value = alertId;
    
    form.appendChild(csrfInput);
    form.appendChild(alertIdInput);
    document.body.appendChild(form);
    
    form.submit();
}

// Function to mitigate a threat
function mitigateThreat(threatId, status) {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = `/dashboard/threat/${threatId}/`;
    
    const csrfInput = document.createElement('input');
    csrfInput.type = 'hidden';
    csrfInput.name = 'csrfmiddlewaretoken';
    csrfInput.value = document.querySelector('[name=csrfmiddlewaretoken]').value;
    
    const statusInput = document.createElement('input');
    statusInput.type = 'hidden';
    statusInput.name = 'status';
    statusInput.value = status;
    
    form.appendChild(csrfInput);
    form.appendChild(statusInput);
    document.body.appendChild(form);
    
    form.submit();
}

// Function to copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        // Show success toast or tooltip
        const toast = new bootstrap.Toast(document.getElementById('clipboardToast'));
        toast.show();
    }).catch(function(err) {
        console.error('Could not copy text: ', err);
    });
} 