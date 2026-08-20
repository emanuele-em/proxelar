# Threat model

Proxelar is a local debugging proxy for a single trusted operator. It is not a hardened shared interception service.

## Assets and trust boundaries

The highest-value assets are the root CA private key, captured authorization/cookie data, API token, upstream proxy credentials, and any code loaded by Lua. Traffic crosses client → Proxelar → upstream boundaries; the GUI/API and exported files create additional local boundaries.

## Local CA

The CA private key can mint certificates trusted by any client that installs the root. Keep the state directory (`~/.proxelar` by default) private, never share `proxelar-ca.key`, and remove the root from client trust stores when Proxelar is no longer used. Each generated leaf certificate has a distinct private key rather than reusing the CA key.

Certificate-pinned clients will reject interception. Android 7+ applications trust user-installed CAs only when their network security configuration opts in. See [CA trust and uninstall](../guides/ca-trust.md).

## GUI and API

The API requires a random runtime bearer token unless `--api-token` is supplied. The GUI uses a separate random bootstrap token in the URL fragment, exchanges it for an `HttpOnly`, `SameSite=Strict` session cookie, and removes the fragment before making network requests. These credentials authorize reading captured credentials, replaying requests, and resolving intercepts. Bind to loopback by default. The server does not provide TLS, users/roles, rate limiting, or multi-tenant isolation; use an authenticated TLS tunnel for intentional remote access.

Do not place API tokens in URLs when logs or browser history are untrusted. Prefer the `Authorization: Bearer` header.

## Scripts and rules

Lua scripts can read and change all proxied traffic. Lua is constrained by mlua's safe standard library, but it still has access to captured secrets supplied to hooks. Native C modules are not loadable: `proxyapi` preserves `#![forbid(unsafe_code)]`, and validated addon packages that declare a native-module requirement are rejected.

Scripts hot-reload after file changes. Invalid updates retain the last known-good script and log the error; hook runtime errors log and pass traffic through.

Map-local rules read files below explicitly configured directories and reject traversal. Rules can redirect, mock, or alter requests, so rule files are trusted configuration.

## Captures and exports

Native sessions preserve data exactly, including secrets, and are created with owner-only permissions on Unix. HAR, curl, and raw exports redact common credentials and secret query keys unless `--export-secrets` is used. Redaction is a safety baseline, not a data-loss-prevention system; application-specific secrets in bodies or custom headers may remain.

## Release artifacts

Release automation produces SHA-256 checksums, an SPDX SBOM, and GitHub artifact provenance attestations. Consumers should verify the artifact they install and still apply normal host/package-manager controls.
