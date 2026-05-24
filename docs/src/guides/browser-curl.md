# Inspect browser and curl traffic

This guide gets a basic HTTP and HTTPS capture working with the default forward proxy mode.

## Start Proxelar

```bash
proxelar
```

The proxy listens on `127.0.0.1:8080` and opens the TUI.

## Test with curl

Plain HTTP works without a certificate:

```bash
curl -x http://127.0.0.1:8080 http://httpbin.org/get
```

For HTTPS, curl must trust the generated Proxelar CA:

```bash
curl --proxy http://127.0.0.1:8080 \
  --cacert ~/.proxelar/proxelar-ca.pem \
  https://httpbin.org/get
```

The request and response should appear in the TUI. Press `Enter` to open details, `Tab` to switch request/response tabs, and `/` to filter.

## Configure a browser

Set both HTTP and HTTPS proxy to:

```text
127.0.0.1:8080
```

Then browse to:

```text
http://proxel.ar
```

Download and trust the Proxelar CA using the instructions shown on that page. After the CA is trusted, HTTPS pages should appear in Proxelar.

Firefox uses its own certificate store unless configured to use the system store. Import `~/.proxelar/proxelar-ca.pem` in Firefox settings if HTTPS traffic still shows certificate warnings.

## Troubleshooting

- If HTTP works but HTTPS fails, the client does not trust the Proxelar CA.
- If nothing appears, confirm the client is actually using `127.0.0.1:8080` as both HTTP and HTTPS proxy.
- If an app uses certificate pinning, Proxelar cannot decrypt it without changing the app or test configuration.
- On Android 7+, user-installed CAs are trusted only by apps that opt in through network security configuration.
