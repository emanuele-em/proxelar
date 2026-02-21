(function() {
    const tbody = document.getElementById('requests-body');
    const detailPanel = document.getElementById('detail-panel');
    const detailContent = document.getElementById('detail-content');
    const statusEl = document.getElementById('status');
    const methodFilter = document.getElementById('method-filter');
    const searchInput = document.getElementById('search');
    const clearBtn = document.getElementById('clear-btn');
    const tabs = document.querySelectorAll('.tab');

    const MAX_REQUESTS = 10000;
    let requests = [];
    let selectedIdx = null;
    let activeTab = 'request';

    function connect() {
        const ws = new WebSocket('ws://' + location.host + '/ws?token=__WS_TOKEN__');

        ws.onopen = function() {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status connected';
        };

        ws.onclose = function() {
            statusEl.textContent = 'Disconnected';
            statusEl.className = 'status disconnected';
            setTimeout(connect, 2000);
        };

        ws.onmessage = function(e) {
            try {
                const event = JSON.parse(e.data);
                if (event.RequestComplete) {
                    requests.push(event.RequestComplete);
                    if (requests.length > MAX_REQUESTS) {
                        var toRemove = requests.length - MAX_REQUESTS;
                        requests = requests.slice(toRemove);
                        if (selectedIdx !== null) {
                            selectedIdx = Math.max(0, selectedIdx - toRemove);
                        }
                    }
                    renderTable();
                }
            } catch(err) {
                console.error('Parse error:', err);
            }
        };
    }

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + 'B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
        return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
    }

    function getMethodClass(method) {
        return 'method-' + method.toLowerCase();
    }

    function getStatusClass(status) {
        if (status >= 200 && status < 300) return 'status-2xx';
        if (status >= 300 && status < 400) return 'status-3xx';
        if (status >= 400 && status < 500) return 'status-4xx';
        if (status >= 500) return 'status-5xx';
        return '';
    }

    function parseUri(uriStr) {
        try {
            const url = new URL(uriStr);
            return { host: url.host, path: url.pathname + url.search };
        } catch(e) {
            return { host: '-', path: uriStr };
        }
    }

    function getFiltered() {
        const method = methodFilter.value;
        const search = searchInput.value.toLowerCase();
        return requests.filter(function(r) {
            if (method && r.request.method !== method) return false;
            if (search && !r.request.uri.toLowerCase().includes(search)) return false;
            return true;
        });
    }

    function renderTable() {
        const filtered = getFiltered();
        tbody.innerHTML = '';

        filtered.forEach(function(r, i) {
            const tr = document.createElement('tr');
            if (i === selectedIdx) tr.className = 'selected';

            const uri = parseUri(r.request.uri);
            const bodyBytes = bodySize(r.response.body);

            tr.innerHTML =
                '<td>' + r.id + '</td>' +
                '<td class="' + getMethodClass(r.request.method) + '">' + r.request.method + '</td>' +
                '<td class="' + getStatusClass(r.response.status) + '">' + r.response.status + '</td>' +
                '<td>' + escapeHtml(uri.host) + '</td>' +
                '<td>' + escapeHtml(uri.path) + '</td>' +
                '<td>' + formatSize(bodyBytes) + '</td>';

            tr.onclick = function() {
                selectedIdx = i;
                showDetail(r);
                renderTable();
            };

            tbody.appendChild(tr);
        });
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function showDetail(r) {
        detailPanel.classList.remove('hidden');
        renderDetail(r);
    }

    function renderDetail(r) {
        const filtered = getFiltered();
        if (selectedIdx === null || !filtered[selectedIdx]) return;

        r = filtered[selectedIdx];
        let content = '';

        if (activeTab === 'request') {
            content = r.request.method + ' ' + r.request.uri + '\n\n';
            if (r.request.headers) {
                for (const [key, val] of Object.entries(r.request.headers)) {
                    content += key + ': ' + val + '\n';
                }
            }
            if (r.request.body) {
                content += '\n' + tryDecodeBody(r.request.body);
            }
        } else {
            content = r.response.status + '\n\n';
            if (r.response.headers) {
                for (const [key, val] of Object.entries(r.response.headers)) {
                    content += key + ': ' + val + '\n';
                }
            }
            if (r.response.body) {
                content += '\n' + tryDecodeBody(r.response.body);
            }
        }

        detailContent.textContent = content;
    }

    function bodySize(body) {
        if (!body) return 0;
        if (Array.isArray(body)) return body.length;
        if (typeof body === 'string') {
            try { return atob(body).length; } catch(e) { return body.length; }
        }
        return 0;
    }

    function bodyToString(body) {
        if (!body) return '';
        if (Array.isArray(body)) {
            return new TextDecoder().decode(new Uint8Array(body));
        }
        if (typeof body === 'string') {
            try { return atob(body); } catch(e) { return body; }
        }
        return String(body);
    }

    function tryDecodeBody(body) {
        const decoded = bodyToString(body);
        if (!decoded) return '';
        try { return JSON.stringify(JSON.parse(decoded), null, 2); }
        catch(e) { return decoded; }
    }

    // Event listeners
    tabs.forEach(function(tab) {
        tab.onclick = function() {
            tabs.forEach(function(t) { t.classList.remove('active'); });
            tab.classList.add('active');
            activeTab = tab.dataset.tab;
            if (selectedIdx !== null) {
                renderDetail(getFiltered()[selectedIdx]);
            }
        };
    });

    document.getElementById('close-detail').onclick = function() {
        detailPanel.classList.add('hidden');
        selectedIdx = null;
        renderTable();
    };

    clearBtn.onclick = function() {
        requests = [];
        selectedIdx = null;
        detailPanel.classList.add('hidden');
        renderTable();
    };

    methodFilter.onchange = renderTable;
    searchInput.oninput = renderTable;

    connect();
})();
