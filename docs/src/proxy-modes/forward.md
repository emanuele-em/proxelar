# Forward Proxy

Forward proxy is the default mode. Clients send their traffic to Proxelar, which forwards it to the destination server. This is the standard setup for inspecting browser or application traffic.

## Usage

```bash
proxelar
```

Configure your client (browser, curl, application) to use `127.0.0.1:8080` as the HTTP/HTTPS proxy.

## How it works

1. The client sends a request to the proxy
2. For HTTPS, the client sends a `CONNECT` request. Proxelar upgrades the connection and detects the protocol:
   - **TLS ClientHello** — generates a leaf certificate for the target host, terminates TLS, and inspects the decrypted traffic
   - **Plain HTTP** (e.g., `GET` prefix) — serves the stream directly
   - **Unknown protocol** — tunnels the raw TCP connection without inspection
3. For plain HTTP, the request is forwarded directly
4. Lua `on_request` / `on_response` hooks run at each step (if a script is loaded)

## Examples

```bash
# Start forward proxy on default port
proxelar

# Custom port and bind address
proxelar -p 9090 -b 0.0.0.0

# With terminal output instead of TUI
proxelar -i terminal

# With a Lua script
proxelar --script block_ads.lua

# Test with curl
curl -x http://127.0.0.1:8080 http://httpbin.org/get
curl -x http://127.0.0.1:8080 https://httpbin.org/get
```
