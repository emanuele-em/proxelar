# CA trust and uninstall

Proxelar decrypts HTTPS by generating a local Certificate Authority and minting per-host certificates. Clients must trust that CA before HTTPS interception works.

## Generated files

By default, Proxelar stores the CA files in:

```text
~/.proxelar/proxelar-ca.pem
~/.proxelar/proxelar-ca.key
```

The private key stays on your machine. Anyone with the key can mint certificates trusted by clients where you installed the CA, so treat it as sensitive.

## Install through the built-in page

Start Proxelar, configure your browser or device to use `127.0.0.1:8080`, then visit:

```text
http://proxel.ar
```

The page provides PEM/DER downloads and platform notes.

## Uninstall notes

Remove trust from every place where you installed the CA:

- **macOS**: open Keychain Access, find the Proxelar certificate, and delete it from the trusted keychain.
- **Linux**: remove the certificate from `/usr/local/share/ca-certificates/` or `/etc/pki/ca-trust/source/anchors/`, then run the platform trust update command.
- **Windows**: open Certificate Manager or run `certmgr.msc`, find the Proxelar root under trusted root authorities, and delete it.
- **Firefox**: remove it from Settings > Privacy & Security > Certificates > View Certificates.
- **iOS/Android**: remove the installed profile or user CA from system settings.

After trust is removed, deleting `~/.proxelar/` removes Proxelar's local copy of the certificate and key.

## Limitations

- Certificate-pinned apps usually reject Proxelar's generated certificates.
- Android 7+ apps trust user-installed CAs only if the app opts in.
- Some corporate-managed devices block custom CA installation.
- If you bind Proxelar to a network interface, other devices can reach the proxy. Only do this on trusted networks and with a clear reason.
