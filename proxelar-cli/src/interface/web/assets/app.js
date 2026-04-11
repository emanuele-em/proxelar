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

    const helpBtn = document.getElementById('help-btn');
    const helpModal = document.getElementById('help-modal');
    const helpBackdrop = document.getElementById('help-backdrop');
    const closeHelpBtn = document.getElementById('close-help');

    function openHelp() {
        helpModal.classList.remove('hidden');
        helpBackdrop.classList.remove('hidden');
    }

    function closeHelp() {
        helpModal.classList.add('hidden');
        helpBackdrop.classList.add('hidden');
    }

    helpBtn.onclick = function() {
        if (helpModal.classList.contains('hidden')) {
            openHelp();
        } else {
            closeHelp();
        }
    };

    closeHelpBtn.onclick = closeHelp;
    helpBackdrop.onclick = closeHelp;

    document.addEventListener('keydown', function(e) {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;
        if (e.key === '?') {
            e.preventDefault();
            if (helpModal.classList.contains('hidden')) {
                openHelp();
            } else {
                closeHelp();
            }
        }
        if (e.key === 'Escape') {
            closeHelp();
        }
    });

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

    // WebSocket inspection state
    // Map<conn_id, { request, response, frames: [], closed }>
    let wsFlows = new Map();
    let selectedWsConnId = null;

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
                } else if (event.WebSocketConnected) {
                    const r = event.WebSocketConnected;
                    wsFlows.set(r.id, { request: r.request, response: r.response, frames: [], closed: false });
                    renderTable();
                } else if (event.WebSocketFrame) {
                    const r = event.WebSocketFrame;
                    const flow = wsFlows.get(r.conn_id);
                    if (flow) {
                        flow.frames.push(r.frame);
                        if (flow.frames.length > 10000) { flow.frames.shift(); }
                        // Incremental append if this connection is selected and Frames tab is active
                        if (selectedWsConnId === r.conn_id && activeTab === 'frames') {
                            appendWsFrame(r.frame);
                        }
                    }
                } else if (event.WebSocketClosed) {
                    const flow = wsFlows.get(event.WebSocketClosed.conn_id);
                    if (flow) {
                        flow.closed = true;
                        if (selectedWsConnId === event.WebSocketClosed.conn_id) {
                            updateWsClosedBadge();
                        }
                        renderTable();
                    }
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

        wsFlows.forEach(function(flow, id) {
            rows.push({ ws: true, id: id, request: flow.request, wsFlow: flow });
        });

        return rows.filter(function(r) {
            if (r.ws) {
                // WS flows are always GET; skip method filter mismatch only if non-GET selected
                if (method && method !== 'GET') return false;
                if (search && !r.request.uri.toLowerCase().includes(search)) return false;
                return true;
            }
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

            if (r.ws) {
                const flow = r.wsFlow;
                const uri = parseUri(r.request.uri || '');
                const statusStr = flow.closed
                    ? '<span class="status-ws-closed">WS \u2713</span>'
                    : '<span class="status-ws-live">WS \u21c4</span>';
                if (selectedWsConnId === r.id) tr.className = 'selected';
                tr.innerHTML =
                    '<td>' + r.id + '</td>' +
                    '<td class="method-get">GET</td>' +
                    '<td>' + statusStr + '</td>' +
                    '<td>' + escapeHtml(uri.host) + '</td>' +
                    '<td>' + escapeHtml(uri.path) + '</td>' +
                    '<td class="status-ws-live">' + flow.frames.length + ' fr</td>';
                tr.onclick = (function(connId, flowRef) {
                    return function() {
                        selectedIdx = null;
                        selectedWsConnId = connId;
                        openWsDetail(flowRef);
                        renderTable();
                    };
                })(r.id, flow);
            } else if (r.pending) {
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
                        selectedWsConnId = null;
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

    // ─── WebSocket detail ────────────────────────────────────────────────────

    function openWsDetail(flow) {
        // Show the Frames tab, hide the Response tab (not meaningful for WS)
        document.getElementById('frames-tab').classList.remove('hidden');
        document.querySelector('[data-tab="response"]').classList.add('hidden');

        // Activate Frames tab
        tabs.forEach(function(t) { t.classList.remove('active'); });
        document.getElementById('frames-tab').classList.add('active');
        activeTab = 'frames';

        detailPanel.classList.remove('hidden');
        interceptPanel.classList.add('hidden');
        renderWsFrameList(flow);
    }

    function renderWsFrameList(flow) {
        let html = '';
        if (flow.closed) {
            html += '<div class="ws-status-badge ws-closed-badge">Connection closed</div>';
        } else {
            html += '<div class="ws-status-badge ws-live-badge">Connection live</div>';
        }
        flow.frames.forEach(function(frame) {
            html += buildWsFrameRow(frame);
        });
        detailContent.innerHTML = html;
        // Auto-scroll to bottom
        detailContent.scrollTop = detailContent.scrollHeight;
    }

    function appendWsFrame(frame) {
        const atBottom = detailContent.scrollTop + detailContent.clientHeight >= detailContent.scrollHeight - 10;
        const div = document.createElement('div');
        div.innerHTML = buildWsFrameRow(frame);
        // buildWsFrameRow returns a single <div> string; append its first child
        while (div.firstChild) {
            detailContent.appendChild(div.firstChild);
        }
        if (atBottom) {
            detailContent.scrollTop = detailContent.scrollHeight;
        }
    }

    function updateWsClosedBadge() {
        const badge = detailContent.querySelector('.ws-status-badge');
        if (badge) {
            badge.className = 'ws-status-badge ws-closed-badge';
            badge.textContent = 'Connection closed';
        }
    }

    function buildWsFrameRow(frame) {
        const isClient = frame.direction === 'ClientToServer';
        const dirSym = isClient ? '\u2191' : '\u2193'; // ↑ ↓
        const dirClass = isClient ? 'ws-frame-row client' : 'ws-frame-row server';
        const opcode = frame.opcode || 'Unknown';
        const payloadBytes = Array.isArray(frame.payload) ? frame.payload.length : 0;
        const truncated = frame.truncated ? ' <span class="ws-truncated">[trunc]</span>' : '';
        let preview = '';
        if (frame.opcode === 'Text') {
            const text = Array.isArray(frame.payload)
                ? new TextDecoder().decode(new Uint8Array(frame.payload))
                : '';
            preview = escapeHtml(text.slice(0, 200));
        } else if (Array.isArray(frame.payload)) {
            preview = frame.payload.slice(0, 32).map(function(b) {
                return b.toString(16).padStart(2, '0');
            }).join(' ');
        }
        return '<div class="' + dirClass + '">' +
            '<span class="ws-dir">' + dirSym + '</span>' +
            '<span class="ws-op">' + escapeHtml(opcode.toLowerCase().slice(0, 4)) + '</span>' +
            '<span class="ws-size">' + payloadBytes + 'B' + truncated + '</span>' +
            '<span class="ws-payload">' + preview + '</span>' +
            '</div>';
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
            if (activeTab === 'frames' && selectedWsConnId !== null) {
                const flow = wsFlows.get(selectedWsConnId);
                if (flow) renderWsFrameList(flow);
            } else {
                const filtered = getFiltered().filter(function(r) { return !r.pending && !r.ws; });
                if (selectedIdx !== null && filtered[selectedIdx]) {
                    renderDetail(filtered[selectedIdx]);
                }
            }
        };
    });

    document.getElementById('close-detail').onclick = function() {
        detailPanel.classList.add('hidden');
        selectedIdx = null;
        selectedWsConnId = null;
        // Restore standard Request/Response tabs
        document.getElementById('frames-tab').classList.add('hidden');
        document.querySelector('[data-tab="response"]').classList.remove('hidden');
        renderTable();
    };

    clearBtn.onclick = function() {
        requests = [];
        pendingRequests.clear();
        wsFlows.clear();
        selectedIdx = null;
        selectedWsConnId = null;
        currentInterceptId = null;
        detailPanel.classList.add('hidden');
        interceptPanel.classList.add('hidden');
        // Restore standard tabs
        document.getElementById('frames-tab').classList.add('hidden');
        document.querySelector('[data-tab="response"]').classList.remove('hidden');
        updateInterceptBtn();
        renderTable();
    };

    methodFilter.onchange = renderTable;
    searchInput.oninput = renderTable;

    connect();
})();
