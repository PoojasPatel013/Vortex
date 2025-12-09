const API_BASE = "";

// Navigation
function switchView(viewName) {
    document.querySelectorAll('.content-view').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));

    document.getElementById(`view-${viewName}`).style.display = 'block';
    // Highlight nav (simple hack)
    if (viewName === 'dashboard') document.querySelector('.nav-item:nth-child(1)').classList.add('active');
    if (viewName === 'history') document.querySelector('.nav-item:nth-child(2)').classList.add('active');

    if (viewName === 'history') {
        loadHistory();
    }
}

// Sidebar Toggle
function toggleSidebar() {
    document.querySelector('.sidebar').classList.toggle('collapsed');
}

// Delete Scan
async function deleteScan(id) {
    if (!confirm('Are you sure you want to delete this scan?')) return;

    try {
        const res = await fetch(`${API_BASE}/scans/${id}`, { method: 'DELETE' });
        if (res.ok) {
            loadHistory();
        } else {
            alert('Failed to delete scan');
        }
    } catch (e) {
        console.error(e);
        alert('Error deleting scan');
    }
}

// Submit Scan
async function submitScan(event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const options = {
        cloud: formData.get('cloud') === 'on',
        iot: formData.get('iot') === 'on',
        graphql: formData.get('graphql') === 'on',
        auto_exploit: formData.get('auto_exploit') === 'on',
        // Integrations
        defect_dojo_url: formData.get('defect_dojo_url'),
        defect_dojo_key: formData.get('defect_dojo_key'),
        engagement_id: formData.get('engagement_id')
    };

    const payload = {
        target: formData.get('target'),
        scan_type: "full",
        options: options
    };

    try {
        const btn = event.target.querySelector('button');
        const originalText = btn.innerHTML;
        btn.innerHTML = 'Starting...';
        btn.disabled = true;

        const res = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            // alert('Scan launched successfully!'); // Removed annoying alert
            switchView('history');
        } else {
            alert('Error launching scan');
        }

        btn.innerHTML = originalText;
        btn.disabled = false;
        event.target.reset();

    } catch (e) {
        console.error(e);
        alert('Network error');
    }
}

// Load History
async function loadHistory() {
    try {
        const res = await fetch(`${API_BASE}/scans?limit=50`);
        const scans = await res.json();

        const tbody = document.getElementById('history-table-body');
        tbody.innerHTML = '';

        scans.reverse().forEach(scan => {
            const tr = document.createElement('tr');

            // Format Type
            let typeBadge = `<span class="type-badge">${scan.scan_type || 'Full'}</span>`;

            // Format Status
            let statusClass = scan.status;
            if (statusClass === 'pending') statusClass = 'running'; // grouping

            tr.innerHTML = `
                <td>#${scan.id}</td>
                <td style="font-weight: bold; color: white;">${scan.target}</td>
                <td>${typeBadge}</td>
                <td>${new Date(scan.created_at).toLocaleString()}</td>
                <td><span class="status-badge ${statusClass}">${scan.status.toUpperCase()}</span></td>
                <td>
                    ${scan.status === 'completed' || scan.status === 'failed' ?
                    `<button onclick="viewResults(${scan.id})" class="btn-sm">View Report</button>` :
                    '<span style="opacity:0.5; font-size:0.8rem;">Running...</span>'}
                    <button onclick="deleteScan(${scan.id})" class="btn-sm btn-danger" title="Delete">🗑️</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

    } catch (e) {
        console.error("Failed to load history", e);
    }
}

// Modal Logic
async function viewResults(id) {
    const modal = document.getElementById('resultsModal');
    const viewer = document.getElementById('jsonViewer');
    const title = document.getElementById('modalTitle');

    title.innerText = `Scan #${id} Results`;
    viewer.innerHTML = '<div style="text-align:center; padding:2rem;">Loading...</div>';
    modal.style.display = 'block';

    try {
        const res = await fetch(`${API_BASE}/scans/${id}`);
        const data = await res.json();

        if (data.results && data.results.vulnerabilities) {
            renderFormattedReport(data.results.vulnerabilities, viewer);
        } else {
            // Fallback to JSON
            viewer.innerHTML = `<pre>${JSON.stringify(data.results, null, 2)}</pre>`;
        }

    } catch (e) {
        viewer.textContent = "Error loading results.";
    }
}

function renderFormattedReport(vulns, container) {
    if (!vulns || vulns.length === 0) {
        container.innerHTML = '<div style="padding:2rem; text-align:center; color:#888;">No vulnerabilities found. System secure (or we just missed them).</div>';
        return;
    }

    let html = '<div class="vuln-grid">';

    vulns.forEach(v => {
        const severityClass = v.severity ? v.severity.toLowerCase() : 'info';
        const source = v.source ? `<span class="source-tag">${v.source}</span>` : '';

        html += `
            <div class="vuln-card ${severityClass}">
                <div class="vuln-header">
                    <span class="vuln-type">${v.type || 'Unknown Issue'}</span>
                    <span class="vuln-sev ${severityClass}">${v.severity || 'Info'}</span>
                    ${source}
                </div>
                <div class="vuln-desc">${v.description || v.details || 'No description provided.'}</div>
                ${v.evidence ? `<div class="vuln-evidence"><code>${v.evidence}</code></div>` : ''}
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

function closeModal() {
    document.getElementById('resultsModal').style.display = 'none';
}

function refreshHistory() {
    loadHistory();
}

// Settings Logic
function saveSettings(e) {
    e.preventDefault();
    localStorage.setItem('vortex_username', document.getElementById('setting_username').value);
    localStorage.setItem('vortex_dd_url', document.getElementById('setting_dd_url').value);
    localStorage.setItem('vortex_dd_key', document.getElementById('setting_dd_key').value);
    alert('Settings Saved!');
    loadSettings(); // refresh form defaults
}

function loadSettings() {
    const user = localStorage.getItem('vortex_username');
    const ddUrl = localStorage.getItem('vortex_dd_url');
    const ddKey = localStorage.getItem('vortex_dd_key');

    if (document.getElementById('setting_username')) document.getElementById('setting_username').value = user || '';
    if (document.getElementById('setting_dd_url')) document.getElementById('setting_dd_url').value = ddUrl || '';
    if (document.getElementById('setting_dd_key')) document.getElementById('setting_dd_key').value = ddKey || '';

    // Auto-fill New Scan Form
    if (document.querySelector('input[name="defect_dojo_url"]')) {
        if (ddUrl) document.querySelector('input[name="defect_dojo_url"]').value = ddUrl;
        if (ddKey) document.querySelector('input[name="defect_dojo_key"]').value = ddKey;
    }

    // Update Sidebar User if exists
    // (Optional: Add user profile display in sidebar later)
}

// Init
window.onclick = function (event) {
    if (event.target == document.getElementById('resultsModal')) {
        closeModal();
    }
}

// Run on load
document.addEventListener('DOMContentLoaded', () => {
    loadSettings();
    loadHistory();
});
