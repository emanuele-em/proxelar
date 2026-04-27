# CA Certificate

Proxelar intercepts HTTPS traffic by generating a local Certificate Authority (CA) and minting per-host leaf certificates on the fly. For this to work, your system must trust the Proxelar CA.

## Automatic generation

On first run, Proxelar generates a 4096-bit RSA CA certificate and private key in `~/.proxelar/`:

- `~/.proxelar/proxelar-ca.pem` — CA certificate
- `~/.proxelar/proxelar-ca.key` — CA private key (mode 0600)

If these files already exist, they are reused.

## Certificate download server

The easiest way to install the CA is through the built-in download server. With the proxy running, visit:

```
http://proxel.ar
```

This page provides:

- Direct download links for PEM and DER formats
- Platform-specific installation instructions for macOS, Linux, Windows, iOS, and Android

## Manual installation

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.proxelar/proxelar-ca.pem
```

### Linux (Debian/Ubuntu)

```bash
sudo cp ~/.proxelar/proxelar-ca.pem /usr/local/share/ca-certificates/proxelar.crt
sudo update-ca-certificates
```

### Linux (Fedora/RHEL)

```bash
sudo cp ~/.proxelar/proxelar-ca.pem /etc/pki/ca-trust/source/anchors/proxelar.pem
sudo update-ca-trust
```

### Windows

```powershell
certutil -addstore -f "ROOT" %USERPROFILE%\.proxelar\proxelar-ca.pem
```

### Firefox

Firefox uses its own certificate store. Go to Settings > Privacy & Security > Certificates > View Certificates > Import, and select `~/.proxelar/proxelar-ca.pem`.

## Custom CA directory

Use `--ca-dir` to store the CA files in a different location:

```bash
proxelar --ca-dir /path/to/certs
```

## Per-host certificate caching

Leaf certificates are cached in memory (up to 1,000 hosts). Repeated connections to the same host reuse the cached certificate instead of generating a new one.
