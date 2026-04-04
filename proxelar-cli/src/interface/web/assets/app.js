(function() {
    const tbody = document.getElementById('requests-body');
    const detailPanel = document.getElementById('detail-panel');
    const detailContent = document.getElementById('detail-content');
    const statusEl = document.getElementById('status');
    const methodFilter = document.getElementById('method-filter');
    const searchInput = document.getElementById('search');
    const clearBtn = document.getElementById('clear-btn');
    const tabs = document.querySelectorAll('.tab');
    const interceptBtn = document.getElementById('intercept-btn');
    const interceptLabel = document.getElementById('intercept-label');
    const interceptPanel = document.getElementById('intercept-panel');
    const interceptTitle = document.getElementById('intercept-title');
    const closeInterceptBtn = document.getElementById('close-intercept');
    const editMethod = document.getElementById('edit-method');
    const editUri = document.getElementById('edit-uri');
    const headersBody = document.getElementById('headers-body');
    const addHeaderBtn = document.getElementById('add-header-btn');
    const editBody = document.getElementById('edit-body');
    const forwardBtn = document.getElementById('forward-btn');
    const dropBtn = document.getElementById('drop-btn');

    const MAX_REQUESTS = 10000;

    // completed flows: array of { id, request, response }
    let requests = [];
    // pending flows: Map<id, request>
    let pendingRequests = new Map();

    let selectedIdx = null;
    let activeTab = 'request';
    let interceptEnabled = false;
    let currentInterceptId = null;
    let ws = null;

    // ─── WebSocket ───────────────────────────────────────────────────────────

    function connect() {
        ws = new WebSocket('ws://' + location.host + '/ws?token=__WS_TOKEN__');

        ws.onopen = function() {
            statusEl.textContent = 'Connected';
            statusEl.className = 'status connected';
        };

        ws.onclose = function() {
            statusEl.textContent = 'Disconnected';
            statusEl.className = 'status disconnected';
            ws = null;
            setTimeout(connect, 2000);
        };

        ws.onmessage = function(e) {
            try {
                const event = JSON.parse(e.data);
                if (event.RequestComplete) {
                    const r = event.RequestComplete;
                    // If this was pending, promote it; otherwise append.
                    pendingRequests.delete(r.id);
                    requests.push(r);
                    if (requests.length > MAX_REQUESTS) {
                        const toRemove = requests.length - MAX_REQUESTS;
                        requests = requests.slice(toRemove);
                        if (selectedIdx !== null) {
                            selectedIdx = Math.max(0, selectedIdx - toRemove);
                        }
                    }
                    renderTable();
                } else if (event.RequestIntercepted) {
                    const r = event.RequestIntercepted;
                    pendingRequests.set(r.id, r.request);
                    renderTable();
                    updateInterceptBtn();
                } else if (event.InterceptStatus) {
                    interceptEnabled = event.InterceptStatus.enabled;
                    updateInterceptBtn();
                }
            } catch(err) {
                console.error('Parse error:', err);
            }
        };
    }

    function sendWs(msg) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(msg));
        }
    }

    // ─── Intercept UI ────────────────────────────────────────────────────────

    function updateInterceptBtn() {
        if (interceptEnabled) {
            interceptBtn.classList.add('active');
            const n = pendingRequests.size;
            interceptLabel.textContent = n > 0 ? 'ON · ' + n + ' pending' : 'ON';
        } else {
            interceptBtn.classList.remove('active');
            interceptLabel.textContent = 'OFF';
        }
    }

    interceptBtn.onclick = function() {
        const newState = !interceptEnabled;
        sendWs({ type: 'SetIntercept', enabled: newState });
        // Optimistic UI update (server will confirm via InterceptStatus)
        interceptEnabled = newState;
        updateInterceptBtn();
    };

    function openInterceptEditor(id, request) {
        currentInterceptId = id;

        const parsed = parseUri(request.uri || '');
        interceptTitle.textContent = '\u23f8 ' + (request.method || '') + ' ' + parsed.path;

        // Populate method
        editMethod.value = request.method || 'GET';

        // Populate URI
        editUri.value = request.uri || '';

        // Populate headers
        headersBody.innerHTML = '';
        if (request.headers) {
            for (const [k, v] of Object.entries(request.headers)) {
                addHeaderRow(k, v);
            }
        }

        // Populate body
        editBody.value = tryDecodeBody(request.body) || '';

        interceptPanel.classList.remove('hidden');
        detailPanel.classList.add('hidden');
        editUri.focus();
    }

    function addHeaderRow(name, value) {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        const inputName = document.createElement('input');
        inputName.className = 'header-name';
        inputName.value = name;
        tdName.appendChild(inputName);

        const tdValue = document.createElement('td');
        const inputValue = document.createElement('input');
        inputValue.className = 'header-value';
        inputValue.value = value;
        tdValue.appendChild(inputValue);

        const tdBtn = document.createElement('td');
        const btn = document.createElement('button');
        btn.className = 'btn-icon remove-header';
        btn.title = 'Remove';
        btn.textContent = '\u00d7';
        btn.onclick = function() { tr.remove(); };
        tdBtn.appendChild(btn);

        tr.appendChild(tdName);
        tr.appendChild(tdValue);
        tr.appendChild(tdBtn);
        headersBody.appendChild(tr);
    }

    addHeaderBtn.onclick = function() { addHeaderRow('', ''); };

    function collectEdits() {
        const headers = {};
        headersBody.querySelectorAll('tr').forEach(function(tr) {
            const k = tr.querySelector('.header-name').value.trim();
            const v = tr.querySelector('.header-value').value;
            if (k) headers[k] = v;
        });
        return {
            id: currentInterceptId,
            method: editMethod.value,
            uri: editUri.value.trim(),
            headers: headers,
            body: editBody.value,
        };
    }

    forwardBtn.onclick = function() {
        if (currentInterceptId === null) return;
        const edits = collectEdits();
        sendWs({ type: 'Modified', ...edits });
        pendingRequests.delete(currentInterceptId);
        currentInterceptId = null;
        interceptPanel.classList.add('hidden');
        updateInterceptBtn();
        renderTable();
    };

    dropBtn.onclick = function() {
        if (currentInterceptId === null) return;
        sendWs({ type: 'Drop', id: currentInterceptId });
        pendingRequests.delete(currentInterceptId);
        currentInterceptId = null;
        interceptPanel.classList.add('hidden');
        updateInterceptBtn();
        renderTable();
    };

    closeInterceptBtn.onclick = function() {
        // Close without action: request stays pending
        currentInterceptId = null;
        interceptPanel.classList.add('hidden');
    };

    // Ctrl+Enter anywhere in the intercept panel → Forward as edited
    interceptPanel.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            forwardBtn.click();
        }
        if (e.key === 'Escape') {
            closeInterceptBtn.click();
        }
    });

    // ─── Table rendering ─────────────────────────────────────────────────────

    function getFiltered() {
        const method = methodFilter.value;
        const search = searchInput.value.toLowerCase();

        // Build a merged list: pending first (ordered by Map insertion), then completed
        const rows = [];

        pendingRequests.forEach(function(request, id) {
            rows.push({ pending: true, id: id, request: request });
        });

        requests.forEach(function(r) {
            rows.push({ pending: false, id: r.id, request: r.request, response: r.response });
        });

        return rows.filter(function(r) {
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

            if (r.pending) {
                tr.className = 'pending';
                const uri = parseUri(r.request.uri || '');
                tr.innerHTML =
                    '<td>\u23f8 ' + r.id + '</td>' +
                    '<td class="' + getMethodClass(r.request.method) + '">' + escapeHtml(r.request.method) + '</td>' +
                    '<td class="status-pending">\u00b7\u00b7\u00b7</td>' +
                    '<td>' + escapeHtml(uri.host) + '</td>' +
                    '<td>' + escapeHtml(uri.path) + '</td>' +
                    '<td>-</td>';
                tr.onclick = function() {
                    openInterceptEditor(r.id, r.request);
                };
            } else {
                if (i === selectedIdx) tr.className = 'selected';
                const uri = parseUri(r.request.uri || '');
                const bodyBytes = bodySize(r.response.body);
                tr.innerHTML =
                    '<td>' + r.id + '</td>' +
                    '<td class="' + getMethodClass(r.request.method) + '">' + escapeHtml(r.request.method) + '</td>' +
                    '<td class="' + getStatusClass(r.response.status) + '">' + r.response.status + '</td>' +
                    '<td>' + escapeHtml(uri.host) + '</td>' +
                    '<td>' + escapeHtml(uri.path) + '</td>' +
                    '<td class="td-with-action">' + formatSize(bodyBytes) +
                        '<button class="btn-row-replay" title="Replay">&#8635; Replay</button>' +
                    '</td>';
                tr.querySelector('.btn-row-replay').onclick = (function(row) {
                    return function(e) {
                        e.stopPropagation();
                        sendWs({
                            type: 'Replay',
                            method: row.request.method || 'GET',
                            uri: row.request.uri || '',
                            headers: row.request.headers || {},
                            body: bodyToString(row.request.body),
                        });
                    };
                })(r);
                tr.onclick = (function(idx, row) {
                    return function() {
                        selectedIdx = idx;
                        showDetail(row);
                        renderTable();
                    };
                })(i, r);
            }

            tbody.appendChild(tr);
        });
    }

    // ─── Detail panel ────────────────────────────────────────────────────────

    function showDetail(r) {
        detailPanel.classList.remove('hidden');
        interceptPanel.classList.add('hidden');
        renderDetail(r);
    }

    function renderDetail(r) {
        let content = '';
        if (activeTab === 'request') {
            content = (r.request.method || '') + ' ' + (r.request.uri || '') + '\n\n';
            if (r.request.headers) {
                for (const [key, val] of Object.entries(r.request.headers)) {
                    content += key + ': ' + val + '\n';
                }
            }
            if (r.request.body) {
                content += '\n' + tryDecodeBody(r.request.body);
            }
        } else {
            content = (r.response.status || '') + '\n\n';
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

    // ─── Helpers ─────────────────────────────────────────────────────────────

    function formatSize(bytes) {
        if (bytes < 1024) return bytes + 'B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
        return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
    }

    function getMethodClass(method) {
        return 'method-' + (method || '').toLowerCase();
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
            return { host: '-', path: uriStr || '-' };
        }
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    function escapeAttr(str) {
        return (str || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
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

    // ─── Event listeners ─────────────────────────────────────────────────────

    tabs.forEach(function(tab) {
        tab.onclick = function() {
            tabs.forEach(function(t) { t.classList.remove('active'); });
            tab.classList.add('active');
            activeTab = tab.dataset.tab;
            const filtered = getFiltered().filter(function(r) { return !r.pending; });
            if (selectedIdx !== null && filtered[selectedIdx]) {
                renderDetail(filtered[selectedIdx]);
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
        pendingRequests.clear();
        selectedIdx = null;
        currentInterceptId = null;
        detailPanel.classList.add('hidden');
        interceptPanel.classList.add('hidden');
        updateInterceptBtn();
        renderTable();
    };

    methodFilter.onchange = renderTable;
    searchInput.oninput = renderTable;

    connect();
})();
