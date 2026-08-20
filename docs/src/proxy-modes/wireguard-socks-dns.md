# WireGuard, SOCKS5, DNS, and raw UDP modes

## WireGuard capture

```bash
proxelar -m wireguard -b 0.0.0.0 -p 51820 \
  --wireguard-endpoint 192.168.1.10:51820
```

WireGuard mode accepts a mobile or IoT device without firewall rules or system-proxy configuration. On first start it creates owner-only server/client keys and `proxelar-wg.conf` in the state directory (`~/.proxelar` by default). The TUI and authenticated web GUI show the profile as a scannable QR code while the capture is empty; terminal mode prints the same QR at startup. You can also import the file directly. The short `proxelar-wg` profile name stays within Android's 15-character WireGuard interface-name limit.

The QR code contains the client private key. Display it only on a trusted screen. It disappears from the TUI and web GUI after the first captured event, although the configuration file remains available for later import.

TCP is reconstructed in a userspace network stack and follows the normal HTTP, TLS MITM, WebSocket, and raw-stream paths. UDP is relayed to its original destination, while port 53 uses `--dns-upstream` and repeatable `--dns-map` overrides.

The endpoint must be reachable by the device. When binding to a concrete address it is derived automatically; when binding to `0.0.0.0` or `::`, Proxelar probes the route to the configured DNS server. Set `--wireguard-endpoint` explicitly for NAT, containers, multiple network interfaces, or a public hostname. Deleting the three `wireguard-*` files in the CA directory rotates the generated single-client identity; this also requires re-importing the client config.

## SOCKS5

```bash
proxelar -m socks5 -p 1080
```

The SOCKS5 listener supports unauthenticated CONNECT requests with IPv4, IPv6, and domain targets. HTTP traffic is inspected, TLS traffic uses the normal local-CA MITM flow, and unknown protocols fall back to observed raw TCP tunneling. Bind it to loopback unless exposure is intentional; client authentication is not currently implemented.

## Upstream chaining

Any HTTP proxy mode can route outbound connections through another HTTP CONNECT or SOCKS5 proxy:

```bash
proxelar --upstream-proxy http://proxy.example:8080
proxelar --upstream-proxy socks5://127.0.0.1:9050
proxelar --upstream-proxy http://proxy.example:8080 \
  --upstream-proxy-auth 'user:password'
```

This applies consistently to ordinary forwarding, reverse proxy requests, and replay. Credentials are sensitive command-line values and may be visible to local process inspection; prefer a dedicated low-privilege account.

## DNS inspection and rewriting

```bash
proxelar -m dns -p 5353 --dns-upstream 1.1.1.1:53 \
  --dns-map api.example.test=127.0.0.1
```

DNS mode is a UDP DNS listener. It records queries and responses, forwards unmatched queries to the configured recursive resolver, and can synthesize A/AAAA answers. It is not a DNS-over-HTTPS resolver.

## Fixed-target raw UDP

UDP mode forwards each client datagram to one configured upstream and captures both directions losslessly:

```bash
proxelar --mode udp --port 9001 --target upstream.example:9000
```

This is useful for testing a known datagram service. It is intentionally not an arbitrary-destination router: each invocation has one target, receives at most one response per request, and reports `no-response` after five seconds.
