# Contributing to the MITM Proxy

We welcome contributions from the community to help improve this project. Whether you're interested in fixing bugs, adding new features, or improving documentation, there are many ways to get involved.

## How to Contribute
Here are some steps to get started with contributing to this project:

* Fork the repository and clone it to your local machine
* Create a new branch for your changes
* Make your changes and test them thoroughly
* Commit your changes with a descriptive commit message
* Push your changes to your fork and submit a pull request

We appreciate contributions of any size, from small bug fixes to major new features. If you're unsure about a change you'd like to make, feel free to open an issue first to discuss it with the maintainers.

### Contribute to UI with Tauri UI

- install required tools
```bash
cargo install tauri-cli wasm-bindgen-cli trunk
```

- start development
```bash
cargo tauri dev
```

- package and release
```bash
cargo tauri build
```


## Test request generation

* Install http server and client.
  ```bash
  cargo install echo-server xh
  ```
* Run http server.
  ```bash
  echo-server
  ```
* Run http client.
  ```bash
  xh --proxy http:http://127.0.0.1:8100 OPTIONS  http://127.0.0.1:8080
  xh --proxy http:http://127.0.0.1:8100 GET  http://127.0.0.1:8080
  xh --proxy http:http://127.0.0.1:8100 POST  http://127.0.0.1:8080
  xh --proxy http:http://127.0.0.1:8100 PUT  http://127.0.0.1:8080
  xh --proxy http:http://127.0.0.1:8100 DELETE  http://127.0.0.1:8080
  xh --proxy http:http://127.0.0.1:8100 HEAD  http://127.0.0.1:8080
  xh --proxy http:http://127.0.0.1:8100 TRACE  http://127.0.0.1:8080
  xh --proxy http:http://127.0.0.1:8100 CONNECT  http://127.0.0.1:8080
  xh --proxy http:http://127.0.0.1:8100 PATCH  http://127.0.0.1:8080
  ```
