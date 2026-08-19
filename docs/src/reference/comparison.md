# Comparison with other tools

This page is intentionally practical, not promotional. Proxelar overlaps with several proxy tools, but it is not the best choice for every workflow.

## Summary

Use Proxelar when you want a local, scriptable, Rust-native traffic workbench with a TUI, web GUI, Lua hooks, request intercept, replay, and WebSocket frame inspection.

If you need HTTP/3 and QUIC interception today, choose a tool that already provides it. Proxelar will add HTTP/3 and QUIC support later this year. Another tool may also be a better fit when you need a large pre-existing addon inventory, polished desktop UX, or professional security testing workflows.

## mitmproxy

mitmproxy is the category default for many developers and security testers. It has mature HTTP tooling, a large addon ecosystem, strong flow persistence/export workflows, local capture modes, and broad documentation.

Proxelar is smaller. Its strengths are a Rust-native implementation, one CLI with terminal/TUI/web/API interfaces, portable redacted exports, Lua/rule automation, and integrity-checked addon packages with a local catalog. It is not yet a mitmproxy replacement for protocol depth or the size of mitmproxy's community addon inventory.

Choose mitmproxy if you need the most mature general-purpose MITM proxy today. Choose Proxelar if you value a compact Rust-native tool with Lua transforms and are comfortable with a younger feature set.

## proxyfor

proxyfor is the closest Rust CLI neighbor: it provides forward/reverse proxy modes, TUI/WebUI, filtering, CA install help, export formats, and portable binaries.

Proxelar emphasizes interactive intercept/edit, replay, lossless native sessions, redacted HAR/curl/raw exports, Lua request/response/WebSocket hooks, declarative rules, and an embeddable `proxyapi` core.

Choose proxyfor if its simpler capture workflow and interface fit are the main requirement. Choose Proxelar if traffic transformation, automation, portable sessions, or library embedding are central.

## Burp Suite and Caido

Burp Suite and Caido are security testing platforms. They are built for manual web security testing, scanning, collaboration, history management, and security-oriented workflows.

Proxelar is not a security suite. It can help inspect and modify traffic, but it does not provide scanners, project collaboration, vulnerability workflows, or the same depth of manual testing tools.

Choose Burp or Caido for professional web security testing. Choose Proxelar for local development debugging and scriptable traffic transforms.

## Charles, Proxyman, and HTTP Toolkit

These tools focus on polished desktop inspection workflows. They are often easier for GUI-first app debugging, especially when users want a desktop product rather than a terminal tool.

Proxelar is CLI-first and open source. Its interface is practical rather than desktop-polished, and its strongest workflows are scriptability, terminal use, and local proxy automation.

Choose a desktop proxy when UI polish and app onboarding matter most. Choose Proxelar when you want a terminal-friendly tool you can script and run in development environments.
