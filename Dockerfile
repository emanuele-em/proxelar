FROM rust:1.94-slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    cmake \
    perl \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release --workspace

# ---- runtime ----
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/proxelar /usr/local/bin/proxelar

VOLUME /root/.proxelar

EXPOSE 8080 8081

ENTRYPOINT ["proxelar"]
CMD ["--interface", "gui", "--addr", "0.0.0.0"]
