# syntax=docker/dockerfile:1

FROM rust:bullseye

WORKDIR /seaside

ARG NETWORK_GATEWAY
ENV ARG_NETWORK_GATEWAY $NETWORK_GATEWAY

ENV RUST_BACKTRACE=1
ENV DEBIAN_FRONTEND=noninteractive

ENV PROTOC_VERSION=24.4
ENV PROTOC_ZIP=protoc-$PROTOC_VERSION-linux-x86_64.zip
RUN wget -qO $PROTOC_ZIP https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/$PROTOC_ZIP && unzip -o $PROTOC_ZIP -d /usr/local bin/protoc && unzip -o $PROTOC_ZIP -d /usr/local 'include/*' && rm -f $PROTOC_ZIP

RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir pytest
COPY viridian/algae/tests/conftest.py viridian/algae/tests/test_local.py viridian/algae/tests

COPY vessels vessels
COPY viridian/reef/Cargo.toml viridian/reef/Cargo.toml
COPY viridian/reef/build.rs viridian/reef/build.rs

WORKDIR /seaside/viridian/reef
RUN mkdir -p src/bindings && echo "fn main() {}" > src/bindings/standard.rs && cargo build
COPY viridian/reef/src src

ENTRYPOINT ip route replace default via $ARG_NETWORK_GATEWAY && cargo run --bin standard

HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s CMD ls /sys/class/net | grep tun0
