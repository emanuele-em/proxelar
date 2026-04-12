(function() {
    const tbody = document.getElementById('requests-body');
    const detailPanel = document.getElementById('detail-panel');
    const detailContent = document.getElementById('detail-content');
    const statusEl = document.getElementById('status');
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

    const FILTER_COLUMNS = ['time', 'proto', 'method', 'host', 'path', 'status', 'type', 'size', 'duration'];

    function parseSearch(search) {
        const colonIdx = search.indexOf(':');
        if (colonIdx > 0) {
            const col = search.slice(0, colonIdx).trim().toLowerCase();
            const val = search.slice(colonIdx + 1).toLowerCase();
            if (FILTER_COLUMNS.includes(col)) {
                return { col: col, val: val };
            }
        }
        return { col: null, val: search };
    }

    function rowMatchesSearch(r, col, val) {
        if (!val) return true;
        const isWs = !!r.ws;
        const uri = parseUri(r.request.uri || '');
        const response = isWs ? r.wsFlow.response : r.response;

        if (!col) {
            return (r.request.uri || '').toLowerCase().includes(val)
                || (r.request.method || '').toLowerCase().includes(val);
        }
        switch (col) {
            case 'time':
                return formatTime(r.request.time).includes(val);
            case 'proto':
                return getProto(r.request.uri || '', isWs).toLowerCase().includes(val);
            case 'method':
                return (isWs ? 'get' : (r.request.method || '').toLowerCase()).includes(val);
            case 'host':
                return uri.host.toLowerCase().includes(val);
            case 'path':
                return uri.path.toLowerCase().includes(val);
            case 'status':
                return response ? String(response.status).includes(val) : false;
            case 'type':
                return response ? getContentType(response.headers).toLowerCase().includes(val) : false;
            case 'size':
                return response ? formatSize(bodySize(response.body)).toLowerCase().includes(val) : false;
            case 'duration':
                return response ? formatDuration(r.request.time, response.time).includes(val) : false;
            default:
                return true;
        }
    }

    function getFiltered() {
        const rawSearch = searchInput.value.toLowerCase().trim();
        const { col, val } = parseSearch(rawSearch);

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
            return rowMatchesSearch(r, col, val);
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
                const proto = getProto(r.request.uri || '', true).toLowerCase();
                const resp = flow.response;
                const status = resp ? resp.status : 101;
                const ct = getContentType(resp ? resp.headers : null);
                const frameSuffix = flow.closed ? ' \u2713' : ' \u21c4';
                const frameStr = flow.frames.length + 'fr' + frameSuffix;
                const duration = formatDuration(r.request.time, resp ? resp.time : null);
                if (selectedWsConnId === r.id) tr.className = 'selected';
                tr.innerHTML =
                    '<td class="col-time">' + formatTime(r.request.time) + '</td>' +
                    '<td data-proto="' + proto + '">' + proto.toUpperCase() + '</td>' +
                    '<td data-method="get">GET</td>' +
                    '<td>' + escapeHtml(uri.host) + '</td>' +
                    '<td class="col-path">' + escapeHtml(uri.path) + '</td>' +
                    '<td data-status="' + statusCategory(status) + '">' + status + '</td>' +
                    '<td class="col-type" data-type="' + typeCategory(ct) + '">' + escapeHtml(ct) + '</td>' +
                    '<td data-proto="' + proto + '">' + frameStr + '</td>' +
                    '<td data-dur="' + durationCategory(r.request.time, resp ? resp.time : null) + '">' + duration + '</td>';
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
                const proto = getProto(r.request.uri || '', false).toLowerCase();
                const method = (r.request.method || '').toLowerCase();
                tr.innerHTML =
                    '<td class="col-time">' + formatTime(r.request.time) + '</td>' +
                    '<td data-proto="' + proto + '">' + proto.toUpperCase() + '</td>' +
                    '<td data-method="' + method + '">' + escapeHtml(r.request.method) + '</td>' +
                    '<td>' + escapeHtml(uri.host) + '</td>' +
                    '<td class="col-path">' + escapeHtml(uri.path) + '</td>' +
                    '<td data-status="pending">\u00b7\u00b7\u00b7</td>' +
                    '<td data-type="none">-</td>' +
                    '<td data-size="zero">-</td>' +
                    '<td data-dur="none">-</td>';
                tr.onclick = function() {
                    openInterceptEditor(r.id, r.request);
                };
            } else {
                if (i === selectedIdx) tr.className = 'selected';
                const uri = parseUri(r.request.uri || '');
                const proto = getProto(r.request.uri || '', false).toLowerCase();
                const method = (r.request.method || '').toLowerCase();
                const bodyBytes = bodySize(r.response.body);
                const ct = getContentType(r.response.headers);
                const duration = formatDuration(r.request.time, r.response.time);
                tr.innerHTML =
                    '<td class="col-time">' + formatTime(r.request.time) + '</td>' +
                    '<td data-proto="' + proto + '">' + proto.toUpperCase() + '</td>' +
                    '<td data-method="' + method + '">' + escapeHtml(r.request.method) + '</td>' +
                    '<td>' + escapeHtml(uri.host) + '</td>' +
                    '<td class="col-path">' + escapeHtml(uri.path) + '</td>' +
                    '<td data-status="' + statusCategory(r.response.status) + '">' + r.response.status + '</td>' +
                    '<td class="col-type" data-type="' + typeCategory(ct) + '">' + escapeHtml(ct) + '</td>' +
                    '<td class="td-with-action" data-size="' + sizeCategory(bodyBytes) + '">' + formatSize(bodyBytes) +
                        '<button class="btn-row-replay" title="Replay">&#8635; Replay</button>' +
                    '</td>' +
                    '<td data-dur="' + durationCategory(r.request.time, r.response.time) + '">' + duration + '</td>';
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

    function formatTime(ms) {
        if (!ms) return '-';
        const d = new Date(ms);
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        const ss = String(d.getSeconds()).padStart(2, '0');
        return hh + ':' + mm + ':' + ss;
    }

    function formatDuration(requestTime, responseTime) {
        if (!requestTime || !responseTime) return '-';
        const ms = responseTime - requestTime;
        if (ms < 0) return '-';
        if (ms >= 1000) return (ms / 1000).toFixed(1) + 's';
        return ms + 'ms';
    }

    function getProto(uriStr, isWs) {
        try {
            const url = new URL(uriStr);
            const tls = (url.protocol === 'https:' || url.protocol === 'wss:');
            if (isWs) return tls ? 'WSS' : 'WS';
            return tls ? 'HTTPS' : 'HTTP';
        } catch(e) {
            return isWs ? 'WSS' : 'HTTPS';
        }
    }

    function getProtoClass(proto) {
        return 'proto-' + proto.toLowerCase();
    }

    function getContentType(headers) {
        if (!headers) return '[no content]';
        const ct = headers['content-type'];
        if (!ct) return '[no content]';
        return ct.split(';')[0].trim();
    }

    // ── Semantic category helpers ─────────────────────────────────────────
    // Return plain tokens used as data-* attribute values; CSS rules live in
    // attribute selectors — no dynamic class strings built here.

    function statusCategory(status) {
        if (status < 200) return '1xx';
        if (status < 300) return '2xx';
        if (status < 400) return '3xx';
        if (status < 500) return '4xx';
        if (status < 600) return '5xx';
        return 'other';
    }

    function typeCategory(ct) {
        if (!ct || ct === '[no content]') return 'none';
        const base = ct.split(';')[0].trim();
        if (base.includes('json'))                                      return 'json';
        if (base.startsWith('text/html'))                               return 'html';
        if (base.includes('javascript') || base.includes('ecmascript')) return 'js';
        if (base.startsWith('text/css'))                                return 'css';
        if (base.startsWith('text/'))                                   return 'text';
        if (base.startsWith('image/'))                                  return 'image';
        if (base.startsWith('font/'))                                   return 'font';
        if (base.includes('xml'))                                       return 'xml';
        if (base.startsWith('multipart/'))                              return 'multi';
        if (base.startsWith('application/octet-stream'))                return 'bin';
        return 'other';
    }

    function sizeCategory(bytes) {
        if (bytes === 0)         return 'zero';
        if (bytes < 1024)        return 'tiny';
        if (bytes < 10 * 1024)   return 'small';
        if (bytes < 100 * 1024)  return 'medium';
        if (bytes < 1024 * 1024) return 'large';
        return 'huge';
    }

    function durationCategory(requestTime, responseTime) {
        if (!requestTime || !responseTime) return 'none';
        const ms = responseTime - requestTime;
        if (ms < 0)    return 'none';
        if (ms < 100)  return 'fast';
        if (ms < 300)  return 'ok';
        if (ms < 700)  return 'slow';
        if (ms < 2000) return 'vslow';
        return 'dead';
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

    searchInput.oninput = renderTable;

    connect();
})();
