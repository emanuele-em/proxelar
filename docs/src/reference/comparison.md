# Comparison with other tools

This page is intentionally practical, not promotional. Proxelar overlaps with several proxy tools, but it is not the best choice for every workflow.

## Summary

Use Proxelar when you want a local, scriptable, Rust-native traffic workbench with a TUI, web GUI, Lua hooks, request intercept, replay, and WebSocket frame inspection.

Choose another tool when you need mature export formats, transparent capture, a large addon ecosystem, polished desktop UX, or professional security testing workflows.

## mitmproxy

mitmproxy is the category default for many developers and security testers. It has mature HTTP tooling, a large addon ecosystem, strong flow persistence/export workflows, transparent/local capture modes, and broad documentation.

Proxelar is smaller. Its strengths are a Rust-native implementation, a single CLI with TUI/web/terminal modes, Lua scripting, and a focused development-debugging workflow. It is not yet a mitmproxy replacement for advanced capture modes, saved flow formats, or deep content views.

Choose mitmproxy if you need the most mature general-purpose MITM proxy today. Choose Proxelar if you value a compact Rust-native tool with Lua transforms and are comfortable with a younger feature set.

## proxyfor

proxyfor is the closest Rust CLI neighbor: it provides forward/reverse proxy modes, TUI/WebUI, filtering, CA install help, export formats, and portable binaries.

Proxelar currently emphasizes interactive intercept/edit, replay, Lua request/response hooks, WebSocket frame inspection, and an embeddable `proxyapi` core. proxyfor currently has stronger export-oriented ergonomics.

Choose proxyfor if export and a simpler capture workflow are the main requirement. Choose Proxelar if traffic transformation and scripting are central.

## Burp Suite and Caido

Burp Suite and Caido are security testing platforms. They are built for manual web security testing, scanning, collaboration, history management, and security-oriented workflows.

Proxelar is not a security suite. It can help inspect and modify traffic, but it does not provide scanners, project collaboration, vulnerability workflows, or the same depth of manual testing tools.

Choose Burp or Caido for professional web security testing. Choose Proxelar for local development debugging and scriptable traffic transforms.

## Charles, Proxyman, and HTTP Toolkit

These tools focus on polished desktop inspection workflows. They are often easier for GUI-first app debugging, especially when users want a desktop product rather than a terminal tool.

Proxelar is CLI-first and open source. Its interface is practical rather than desktop-polished, and its strongest workflows are scriptability, terminal use, and local proxy automation.

Choose a desktop proxy when UI polish and app onboarding matter most. Choose Proxelar when you want a terminal-friendly tool you can script and run in development environments.
