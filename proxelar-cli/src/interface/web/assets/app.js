(function() {
    const fragment = new URLSearchParams(location.hash.slice(1));
    let bootstrapToken = fragment.get('token');
    if (location.hash) {
        history.replaceState(null, '', location.pathname + location.search);
    }

    async function authenticateBrowser() {
        if (!bootstrapToken) return;
        const token = bootstrapToken;
        bootstrapToken = null;
        const response = await fetch('/api/v1/auth', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Authorization': 'Bearer ' + token },
        });
        if (!response.ok) throw new Error('Browser authentication failed');
    }

    function apiFetch(path, options) {
        return fetch(path, Object.assign({ credentials: 'same-origin' }, options || {}));
    }
    const tbody = document.getElementById('requests-body');
    const requestsTable = document.getElementById('requests-table');
    const wireguardSetup = document.getElementById('wireguard-setup');
    const wireguardQr = document.getElementById('wireguard-qr');
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
    const editBodyMode = document.getElementById('edit-body-mode');
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

    let selectedFlowId = null;
    let activeTab = 'request';
    let interceptEnabled = false;
    let currentInterceptId = null;
    let editorOriginalBytes = [];
    let editorStructured = null;
    let ws = null;

    // WebSocket inspection state
    // Map<conn_id, { request, response, frames: [], closed }>
    let wsFlows = new Map();
    let selectedWsConnId = null;
    let tcpStreams = new Map();
    let dnsExchanges = new Map();
    let udpExchanges = new Map();
    let selectedAuxKey = null;
    let filterMatches = null;
    let filterGeneration = 0;
    let filterTimer = null;
    let wireguardAvailable = false;

    async function loadWireGuardSetup() {
        const response = await apiFetch('/api/v1/wireguard.svg');
        if (response.status === 404) return;
        if (!response.ok) throw new Error('WireGuard setup request failed with status ' + response.status);
        const image = await response.blob();
        wireguardQr.src = URL.createObjectURL(image);
        wireguardAvailable = true;
        updateWireGuardSetup();
    }

    function hasCapturedTraffic() {
        return requests.length > 0
            || pendingRequests.size > 0
            || wsFlows.size > 0
            || tcpStreams.size > 0
            || dnsExchanges.size > 0
            || udpExchanges.size > 0;
    }

    function updateWireGuardSetup() {
        const visible = wireguardAvailable && !hasCapturedTraffic();
        wireguardSetup.classList.toggle('hidden', !visible);
        requestsTable.classList.toggle('hidden', visible);
    }

    // ─── WebSocket ───────────────────────────────────────────────────────────

    async function loadSession() {
        try {
            const response = await apiFetch('/api/v1/session');
            if (!response.ok) throw new Error('Session request failed with status ' + response.status);
            const session = await response.json();
            requests = (session.flows || []).slice(-MAX_REQUESTS);
            wsFlows.clear();
            (session.websockets || []).forEach(function(flow) {
                wsFlows.set(flow.id, {
                    request: flow.request,
                    response: flow.response,
                    frames: flow.frames || [],
                    closed: !!flow.closed,
                });
            });
            tcpStreams.clear();
            (session.tcp_streams || []).forEach(function(stream) {
                tcpStreams.set(stream.id, stream);
            });
            dnsExchanges.clear();
            (session.dns_exchanges || []).forEach(function(exchange) {
                dnsExchanges.set(exchange.id, exchange);
            });
            udpExchanges.clear();
            (session.udp_exchanges || []).forEach(function(exchange) {
                udpExchanges.set(exchange.id, exchange);
            });
            scheduleTableUpdate();
        } catch (error) {
            console.warn('Could not load capture history:', error);
            throw error;
        }
    }

    function connect() {
        ws = new WebSocket('ws://' + location.host + '/ws');

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
                    if (currentInterceptId === r.id) {
                        currentInterceptId = null;
                        interceptPanel.classList.add('hidden');
                        forwardBtn.disabled = false;
                    }
                    requests.push(r);
                    if (requests.length > MAX_REQUESTS) {
                        const toRemove = requests.length - MAX_REQUESTS;
                        requests = requests.slice(toRemove);
                        if (selectedFlowId !== null && !requests.some(function(flow) { return flow.id === selectedFlowId; })) {
                            selectedFlowId = null;
                        }
                    }
                    scheduleTableUpdate();
                } else if (event.RequestIntercepted) {
                    const r = event.RequestIntercepted;
                    r.request._editor = r.editor || null;
                    pendingRequests.set(r.id, r.request);
                    scheduleTableUpdate();
                    updateInterceptBtn();
                } else if (event.InterceptStatus) {
                    interceptEnabled = event.InterceptStatus.enabled;
                    updateInterceptBtn();
                } else if (event.EditorError) {
                    if (currentInterceptId === event.EditorError.id) {
                        forwardBtn.disabled = false;
                        editBody.setCustomValidity(event.EditorError.message || 'Invalid structured body');
                        editBody.reportValidity();
                        editBody.focus();
                    }
                } else if (event.WebSocketConnected) {
                    const r = event.WebSocketConnected;
                    wsFlows.set(r.id, { request: r.request, response: r.response, frames: [], closed: false });
                    scheduleTableUpdate();
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
                        scheduleTableUpdate();
                    }
                } else if (event.WebSocketClosed) {
                    const flow = wsFlows.get(event.WebSocketClosed.conn_id);
                    if (flow) {
                        flow.closed = true;
                        if (selectedWsConnId === event.WebSocketClosed.conn_id) {
                            updateWsClosedBadge();
                        }
                        scheduleTableUpdate();
                    }
                } else if (event.TcpConnected) {
                    const r = event.TcpConnected;
                    tcpStreams.set(r.id, {
                        id: r.id,
                        target: r.target,
                        opened_at: r.opened_at,
                        chunks: [],
                        closed: false,
                    });
                    scheduleTableUpdate();
                } else if (event.TcpData) {
                    const r = event.TcpData;
                    const stream = tcpStreams.get(r.stream_id);
                    if (stream && stream.chunks.length < 10000) {
                        stream.chunks.push(r.chunk);
                        if (selectedAuxKey === 'tcp:' + r.stream_id) openAuxDetail('tcp', stream);
                        scheduleTableUpdate();
                    }
                } else if (event.TcpClosed) {
                    const stream = tcpStreams.get(event.TcpClosed.stream_id);
                    if (stream) {
                        stream.closed = true;
                        scheduleTableUpdate();
                    }
                } else if (event.DnsQuery) {
                    const r = event.DnsQuery;
                    dnsExchanges.set(r.id, {
                        id: r.id,
                        name: r.name,
                        query_type: r.query_type,
                        time: r.time,
                        answers: [],
                        overridden: false,
                        completed: false,
                    });
                    scheduleTableUpdate();
                } else if (event.DnsResponse) {
                    const r = event.DnsResponse;
                    const exchange = dnsExchanges.get(r.id);
                    if (exchange) {
                        exchange.answers = r.answers || [];
                        exchange.overridden = !!r.overridden;
                        exchange.completed = true;
                        if (selectedAuxKey === 'dns:' + r.id) openAuxDetail('dns', exchange);
                        scheduleTableUpdate();
                    }
                } else if (event.UdpExchange) {
                    const exchange = event.UdpExchange.exchange;
                    udpExchanges.set(exchange.id, exchange);
                    if (selectedAuxKey === 'udp:' + exchange.id) openAuxDetail('udp', exchange);
                    scheduleTableUpdate();
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

    function emptyFilterMatches() {
        return {
            flowIds: new Set(),
            websocketIds: new Set(),
            tcpStreamIds: new Set(),
            dnsExchangeIds: new Set(),
            udpExchangeIds: new Set(),
        };
    }

    async function refreshFilter() {
        const expression = searchInput.value.trim();
        const generation = ++filterGeneration;
        if (!expression) {
            filterMatches = null;
            renderTable();
            return;
        }
        filterMatches = emptyFilterMatches();
        try {
            const response = await apiFetch(
                '/api/v1/filter?filter=' + encodeURIComponent(expression)
            );
            if (!response.ok) throw new Error(await response.text());
            const result = await response.json();
            if (generation !== filterGeneration) return;
            filterMatches = {
                flowIds: new Set(result.flow_ids || []),
                websocketIds: new Set(result.websocket_ids || []),
                tcpStreamIds: new Set(result.tcp_stream_ids || []),
                dnsExchangeIds: new Set(result.dns_exchange_ids || []),
                udpExchangeIds: new Set(result.udp_exchange_ids || []),
            };
        } catch (error) {
            if (generation !== filterGeneration) return;
            console.warn('Invalid or unavailable flow filter:', error);
            filterMatches = emptyFilterMatches();
        }
        renderTable();
    }

    function scheduleTableUpdate() {
        if (!searchInput.value.trim()) {
            renderTable();
            return;
        }
        clearTimeout(filterTimer);
        filterTimer = setTimeout(refreshFilter, 100);
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
        headerEntries(request.headers).forEach(function(field) {
            addHeaderRow(field.name, field.value, field.value_base64);
        });

        // Populate body
        setBodyEditor(request.body, request._editor);

        interceptPanel.classList.remove('hidden');
        detailPanel.classList.add('hidden');
        editUri.focus();
    }

    function addHeaderRow(name, value, valueBase64) {
        const tr = document.createElement('tr');

        const tdName = document.createElement('td');
        const inputName = document.createElement('input');
        inputName.className = 'header-name';
        inputName.value = name;
        tdName.appendChild(inputName);

        const tdValue = document.createElement('td');
        const inputValue = document.createElement('input');
        inputValue.className = 'header-value';
        const binaryMarker = valueBase64 ? '<base64:' + valueBase64 + '>' : '';
        inputValue.value = valueBase64 ? binaryMarker : value;
        if (valueBase64) {
            inputValue.dataset.valueBase64 = valueBase64;
            inputValue.dataset.binaryMarker = binaryMarker;
            inputValue.addEventListener('input', function() {
                if (inputValue.value !== inputValue.dataset.binaryMarker) {
                    delete inputValue.dataset.valueBase64;
                    delete inputValue.dataset.binaryMarker;
                }
            });
        }
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

    function bytesFromBody(body) {
        if (Array.isArray(body)) return body.slice();
        if (typeof body === 'string') return Array.from(new TextEncoder().encode(bodyToString(body)));
        return [];
    }

    function formatHex(bytes) {
        return bytes.map(function(byte, index) {
            const prefix = index === 0 ? '' : (index % 16 === 0 ? '\n' : ' ');
            return prefix + byte.toString(16).padStart(2, '0');
        }).join('');
    }

    function parseHex(value) {
        const compact = value.replace(/\s/g, '');
        if (compact.length % 2 !== 0 || /[^0-9a-f]/i.test(compact)) return null;
        const bytes = [];
        for (let index = 0; index < compact.length; index += 2) {
            bytes.push(parseInt(compact.slice(index, index + 2), 16));
        }
        return bytes;
    }

    function setBodyEditor(body, structured) {
        const bytes = bytesFromBody(body);
        editorOriginalBytes = bytes;
        editorStructured = structured || null;
        editBody.setCustomValidity('');
        if (editorStructured) {
            editBody.value = editorStructured.text || '';
            editBodyMode.value = editorStructured.format;
            return;
        }
        try {
            editBody.value = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
            editBodyMode.value = 'text';
        } catch (error) {
            editBody.value = formatHex(bytes);
            editBodyMode.value = 'hex';
        }
    }

    editBodyMode.onchange = function() {
        editBody.setCustomValidity('');
        if (editBodyMode.value === 'protobuf' || editBodyMode.value === 'messagepack') {
            if (editorStructured && editorStructured.format === editBodyMode.value) {
                editBody.value = editorStructured.text || '';
                return;
            }
            editBodyMode.value = 'hex';
            editBody.value = formatHex(editorOriginalBytes);
            return;
        }
        if (editBodyMode.value === 'hex') {
            editBody.value = formatHex(editorOriginalBytes);
            return;
        }
        try {
            editBody.value = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(editorOriginalBytes));
        } catch (error) {
            editBodyMode.value = 'hex';
            editBody.value = formatHex(editorOriginalBytes);
            return;
        }
    };

    function editedBody() {
        if (editBodyMode.value === 'text') return editBody.value;
        if (editBodyMode.value === 'protobuf' || editBodyMode.value === 'messagepack') {
            try {
                JSON.parse(editBody.value);
            } catch (error) {
                editBody.focus();
                editBody.setCustomValidity('Structured bodies must be valid JSON: ' + error.message);
                editBody.reportValidity();
                return null;
            }
            editBody.setCustomValidity('');
            return { format: editBodyMode.value, text: editBody.value };
        }
        const bytes = parseHex(editBody.value);
        if (bytes === null) {
            editBody.focus();
            editBody.setCustomValidity('Hex bodies must contain pairs of hexadecimal digits');
            editBody.reportValidity();
            return null;
        }
        editBody.setCustomValidity('');
        return { bytes: bytes };
    }

    function collectEdits() {
        const headers = [];
        headersBody.querySelectorAll('tr').forEach(function(tr) {
            const k = tr.querySelector('.header-name').value.trim();
            const v = tr.querySelector('.header-value').value;
            if (k) {
                const valueBase64 = tr.querySelector('.header-value').dataset.valueBase64;
                headers.push(valueBase64
                    ? { name: k, value_base64: valueBase64 }
                    : { name: k, value: v });
            }
        });
        const body = editedBody();
        if (body === null) return null;
        return {
            id: currentInterceptId,
            method: editMethod.value,
            uri: editUri.value.trim(),
            headers: headers,
            body: body,
        };
    }

    forwardBtn.onclick = function() {
        if (currentInterceptId === null) return;
        const edits = collectEdits();
        if (!edits) return;
        forwardBtn.disabled = true;
        sendWs({ type: 'Modified', ...edits });
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

        tcpStreams.forEach(function(stream, id) {
            rows.push({ tcp: true, id: id, stream: stream });
        });

        dnsExchanges.forEach(function(exchange, id) {
            rows.push({ dns: true, id: id, exchange: exchange });
        });

        udpExchanges.forEach(function(exchange, id) {
            rows.push({ udp: true, id: id, exchange: exchange });
        });

        return rows.filter(function(r) {
            if (!rawSearch) return true;
            if (r.pending) return rowMatchesSearch(r, col, val);
            if (!filterMatches) return false;
            if (r.ws) return filterMatches.websocketIds.has(r.id);
            if (r.tcp) return filterMatches.tcpStreamIds.has(r.id);
            if (r.dns) return filterMatches.dnsExchangeIds.has(r.id);
            if (r.udp) return filterMatches.udpExchangeIds.has(r.id);
            return filterMatches.flowIds.has(r.id);
        });
    }

    function renderTable() {
        const filtered = getFiltered();
        tbody.innerHTML = '';
        updateWireGuardSetup();

        filtered.forEach(function(r, i) {
            const tr = document.createElement('tr');

            if (r.udp) {
                const exchange = r.exchange;
                const requestSize = bodySize(exchange.request);
                const responseSize = bodySize(exchange.response);
                const complete = !!exchange.response_received;
                if (selectedAuxKey === 'udp:' + r.id) tr.className = 'selected';
                tr.innerHTML =
                    '<td class="col-time">' + formatTime(exchange.time) + '</td>' +
                    '<td data-proto="udp">UDP</td>' +
                    '<td data-method="datagram">DGRAM</td>' +
                    '<td>' + escapeHtml(exchange.target) + '</td>' +
                    '<td class="col-path">' + escapeHtml(exchange.client) + '</td>' +
                    '<td data-status="' + (complete ? '2xx' : 'pending') + '">' + (complete ? 'complete' : 'no-resp') + '</td>' +
                    '<td class="col-type" data-type="bin">binary</td>' +
                    '<td data-size="' + sizeCategory(requestSize + responseSize) + '">' + formatSize(requestSize + responseSize) + '</td>' +
                    '<td>-</td>';
                tr.onclick = function() {
                    selectedFlowId = null;
                    selectedWsConnId = null;
                    selectedAuxKey = 'udp:' + r.id;
                    openAuxDetail('udp', exchange);
                    renderTable();
                };
            } else if (r.tcp) {
                const stream = r.stream;
                const bytes = stream.chunks.reduce(function(total, chunk) {
                    return total + bodySize(chunk.payload);
                }, 0);
                if (selectedAuxKey === 'tcp:' + r.id) tr.className = 'selected';
                tr.innerHTML =
                    '<td class="col-time">' + formatTime(stream.opened_at) + '</td>' +
                    '<td data-proto="tcp">TCP</td>' +
                    '<td data-method="stream">STREAM</td>' +
                    '<td>' + escapeHtml(stream.target) + '</td>' +
                    '<td class="col-path">-</td>' +
                    '<td data-status="' + (stream.closed ? 'other' : '2xx') + '">' + (stream.closed ? 'closed' : 'live') + '</td>' +
                    '<td class="col-type" data-type="bin">binary</td>' +
                    '<td data-size="' + sizeCategory(bytes) + '">' + formatSize(bytes) + '</td>' +
                    '<td>' + stream.chunks.length + 'ch</td>';
                tr.onclick = function() {
                    selectedFlowId = null;
                    selectedWsConnId = null;
                    selectedAuxKey = 'tcp:' + r.id;
                    openAuxDetail('tcp', stream);
                    renderTable();
                };
            } else if (r.dns) {
                const exchange = r.exchange;
                const state = !exchange.completed ? 'pending' : (exchange.overridden ? 'override' : 'upstream');
                if (selectedAuxKey === 'dns:' + r.id) tr.className = 'selected';
                tr.innerHTML =
                    '<td class="col-time">' + formatTime(exchange.time) + '</td>' +
                    '<td data-proto="dns">DNS</td>' +
                    '<td data-method="dns">' + dnsQueryType(exchange.query_type) + '</td>' +
                    '<td>' + escapeHtml(exchange.name) + '</td>' +
                    '<td class="col-path">-</td>' +
                    '<td data-status="' + (exchange.overridden ? '3xx' : '2xx') + '">' + state + '</td>' +
                    '<td class="col-type" data-type="other">dns</td>' +
                    '<td>' + (exchange.answers || []).length + 'ans</td>' +
                    '<td>-</td>';
                tr.onclick = function() {
                    selectedFlowId = null;
                    selectedWsConnId = null;
                    selectedAuxKey = 'dns:' + r.id;
                    openAuxDetail('dns', exchange);
                    renderTable();
                };
            } else if (r.ws) {
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
                        selectedFlowId = null;
                        selectedWsConnId = connId;
                        selectedAuxKey = null;
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
                if (selectedFlowId === r.id) tr.className = 'selected';
                const uri = parseUri(r.request.uri || '');
                const proto = getProto(r.request.uri || '', false).toLowerCase();
                const method = (r.request.method || '').toLowerCase();
                const bodyBytes = (r.response.body_metadata && r.response.body_metadata.total_seen)
                    || bodySize(r.response.body);
                const truncatedMark = r.response.body_metadata && r.response.body_metadata.truncated ? ' ⚠' : '';
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
                    '<td class="td-with-action" data-size="' + sizeCategory(bodyBytes) + '">' + formatSize(bodyBytes) + truncatedMark +
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
                            body: encodedWireBody(row.request.body),
                        });
                    };
                })(r);
                tr.onclick = (function(row) {
                    return function() {
                        selectedFlowId = row.id;
                        selectedWsConnId = null;
                        selectedAuxKey = null;
                        showDetail(row);
                        renderTable();
                    };
                })(r);
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
        let body = null;
        let side = activeTab === 'request' ? 'request' : 'response';
        if (activeTab === 'request') {
            content = (r.request.method || '') + ' ' + (r.request.uri || '') + '\n\n';
            headerEntries(r.request.headers).forEach(function(field) {
                content += field.name + ': ' + headerDisplayValue(field) + '\n';
            });
            body = r.request.body;
        } else {
            content = (r.response.status || '') + '\n\n';
            headerEntries(r.response.headers).forEach(function(field) {
                content += field.name + ': ' + headerDisplayValue(field) + '\n';
            });
            body = r.response.body;
        }
        detailContent.textContent = content;
        if (!body) return;

        const renderKey = r.id + ':' + side + ':' + Date.now();
        detailContent.dataset.renderKey = renderKey;
        apiFetch('/api/v1/flows/' + r.id + '/content/' + side)
            .then(function(response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.json();
            })
            .then(function(view) {
                if (detailContent.dataset.renderKey !== renderKey) return;
                let banner = '\n[' + view.kind + ' · ' + formatSize(view.decoded_len) + ']';
                if (view.truncated) {
                    banner += ' [truncated · observed ' + formatSize(view.total_seen) + ']';
                }
                renderContentView(content + banner + '\n', view);
            })
            .catch(function() {
                if (detailContent.dataset.renderKey === renderKey) {
                    detailContent.textContent = content + '\n' + tryDecodeBody(body);
                }
            });
    }

    function renderContentView(prefix, view) {
        detailContent.textContent = prefix;
        const text = view.text || '';
        if (view.kind === 'Image' && view.image_media_type && view.image_base64) {
            const image = document.createElement('img');
            image.className = 'content-image-preview';
            image.alt = view.image_media_type + ' response preview';
            image.src = 'data:' + view.image_media_type + ';base64,' + view.image_base64;
            detailContent.appendChild(image);
            return;
        }
        let pattern = null;
        const jsonLike = view.kind === 'JSON' || view.kind === 'Protobuf' || view.kind === 'MessagePack';
        if (jsonLike) {
            pattern = /("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|\b(true|false|null)\b|-?\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/gi;
        } else if (view.kind === 'XML' || view.kind === 'HTML') {
            pattern = /<\/?[^>]+>/g;
        } else if (view.kind === 'CSS' || view.kind === 'JavaScript') {
            pattern = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|\b(true|false|null|undefined)\b|-?\b\d+(?:\.\d+)?\b/g;
        }
        if (!pattern) {
            detailContent.appendChild(document.createTextNode(text));
            return;
        }

        let cursor = 0;
        let match;
        while ((match = pattern.exec(text)) !== null) {
            detailContent.appendChild(document.createTextNode(text.slice(cursor, match.index)));
            const token = document.createElement('span');
            const value = match[0];
            if (jsonLike && /^".*"\s*:$/.test(value)) token.className = 'syntax-key';
            else if (/^["']/.test(value)) token.className = 'syntax-string';
            else if (/^(true|false|null|undefined)$/i.test(value)) token.className = 'syntax-literal';
            else if (/^-?\d/.test(value)) token.className = 'syntax-number';
            else token.className = 'syntax-key';
            token.textContent = value;
            detailContent.appendChild(token);
            cursor = pattern.lastIndex;
        }
        detailContent.appendChild(document.createTextNode(text.slice(cursor)));
    }

    function openAuxDetail(kind, item) {
        document.getElementById('frames-tab').classList.add('hidden');
        document.querySelector('[data-tab="response"]').classList.add('hidden');
        tabs.forEach(function(tab) { tab.classList.remove('active'); });
        document.querySelector('[data-tab="request"]').classList.add('active');
        activeTab = 'request';
        detailPanel.classList.remove('hidden');
        interceptPanel.classList.add('hidden');

        if (kind === 'dns') {
            const source = item.overridden ? 'local override' : 'upstream resolver';
            const answers = (item.answers || []).length ? item.answers.join('\n') : 'No IP answers';
            detailContent.textContent = dnsQueryType(item.query_type) + ' ' + item.name + '\n' +
                'Source: ' + source + '\n' +
                'State: ' + (item.completed ? 'complete' : 'pending') + '\n\n' + answers;
            return;
        }

        if (kind === 'udp') {
            const request = Array.isArray(item.request) ? item.request : [];
            const response = Array.isArray(item.response) ? item.response : [];
            detailContent.textContent = 'Client: ' + item.client + '\n' +
                'Target: ' + item.target + '\n' +
                'Request: ' + request.length + 'B' + (item.request_truncated ? ' [capture limit]' : '') + '\n' +
                bytesPreview(request) + '\n\n' +
                'Response: ' + response.length + 'B' + (item.response_truncated ? ' [capture limit]' : '') + '\n' +
                bytesPreview(response);
            return;
        }

        let content = 'Target: ' + item.target + '\n' +
            'State: ' + (item.closed ? 'closed' : 'live') + ' · ' + item.chunks.length + ' chunks\n\n';
        item.chunks.forEach(function(chunk) {
            const direction = chunk.direction === 'ClientToServer' ? '↑' : '↓';
            const payload = Array.isArray(chunk.payload) ? chunk.payload : [];
            const decoded = new TextDecoder().decode(new Uint8Array(payload));
            const printable = !/[\u0000-\u0008\u000e-\u001f]/.test(decoded);
            const preview = printable ? decoded.slice(0, 160) : payload.slice(0, 48).map(function(byte) {
                return byte.toString(16).padStart(2, '0');
            }).join(' ');
            content += direction + ' ' + formatTime(chunk.time) + ' ' + payload.length + 'B' +
                (chunk.truncated ? ' [capture limit]' : '') + ' ' + preview + '\n';
        });
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

    function dnsQueryType(queryType) {
        const names = { 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS' };
        return names[queryType] || 'TYPE' + queryType;
    }

    function getContentType(headers) {
        if (!headers) return '[no content]';
        const field = headerEntries(headers).find(function(candidate) {
            return candidate.name.toLowerCase() === 'content-type';
        });
        const ct = field ? field.value : null;
        if (!ct) return '[no content]';
        return ct.split(';')[0].trim();
    }

    function headerEntries(headers) {
        if (!headers) return [];
        if (Array.isArray(headers)) {
            return headers.map(function(field) {
                return {
                    name: String(field.name || ''),
                    value: typeof field.value === 'string' ? field.value : '',
                    value_base64: typeof field.value_base64 === 'string' ? field.value_base64 : null,
                };
            });
        }
        const fields = [];
        Object.entries(headers).forEach(function(entry) {
            const name = entry[0];
            const values = Array.isArray(entry[1]) ? entry[1] : [entry[1]];
            values.forEach(function(value) {
                fields.push({ name: name, value: String(value), value_base64: null });
            });
        });
        return fields;
    }

    function headerDisplayValue(field) {
        return field.value_base64 ? '<base64:' + field.value_base64 + '>' : field.value;
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

    function bytesPreview(bytes) {
        if (!bytes.length) return '[no payload]';
        const decoder = new TextDecoder('utf-8', { fatal: true });
        try {
            const text = decoder.decode(new Uint8Array(bytes));
            if (!/[\u0000-\u0008\u000e-\u001f]/.test(text)) return text.slice(0, 512);
        } catch (error) {
            // Fall through to an exact hexadecimal preview.
        }
        return bytes.slice(0, 512).map(function(byte) {
            return byte.toString(16).padStart(2, '0');
        }).join(' ');
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

    function encodedWireBody(body) {
        return Array.isArray(body) ? { bytes: body } : bodyToString(body);
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
                const selected = getFiltered().find(function(row) {
                    return !row.pending && !row.ws && !row.tcp && !row.dns && !row.udp && row.id === selectedFlowId;
                });
                if (selected) {
                    renderDetail(selected);
                }
            }
        };
    });

    document.getElementById('close-detail').onclick = function() {
        detailPanel.classList.add('hidden');
        selectedFlowId = null;
        selectedWsConnId = null;
        selectedAuxKey = null;
        // Restore standard Request/Response tabs
        document.getElementById('frames-tab').classList.add('hidden');
        document.querySelector('[data-tab="response"]').classList.remove('hidden');
        renderTable();
    };

    clearBtn.onclick = function() {
        requests = [];
        pendingRequests.clear();
        wsFlows.clear();
        tcpStreams.clear();
        dnsExchanges.clear();
        udpExchanges.clear();
        selectedFlowId = null;
        selectedWsConnId = null;
        selectedAuxKey = null;
        currentInterceptId = null;
        detailPanel.classList.add('hidden');
        interceptPanel.classList.add('hidden');
        // Restore standard tabs
        document.getElementById('frames-tab').classList.add('hidden');
        document.querySelector('[data-tab="response"]').classList.remove('hidden');
        updateInterceptBtn();
        renderTable();
        apiFetch('/api/v1/flows', { method: 'DELETE' }).catch(function(error) {
            console.warn('Could not clear server-side history:', error);
        });
    };

    searchInput.oninput = scheduleTableUpdate;

    authenticateBrowser()
        .then(loadWireGuardSetup)
        .then(loadSession)
        .then(connect)
        .catch(function(error) {
            console.warn('Could not authenticate browser session:', error);
            statusEl.textContent = 'Authentication required';
            statusEl.className = 'status disconnected';
        });
})();
