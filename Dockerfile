FROM rust:1.97.1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    cmake \
    perl \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release --locked --workspace

# ---- runtime ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/proxelar /usr/local/bin/proxelar

# The container stores state at /root/.proxelar. Setting XDG_CONFIG_HOME or
# passing --ca-dir moves it elsewhere, in which case mount that path instead.
VOLUME /root/.proxelar

EXPOSE 8080 8081

ENTRYPOINT ["proxelar"]
CMD ["--interface", "gui", "--addr", "0.0.0.0"]
