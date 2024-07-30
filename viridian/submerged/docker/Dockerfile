# syntax=docker/dockerfile:1

FROM rust:bullseye

WORKDIR /seaside

ENV RUST_BACKTRACE=1
ENV DEBIAN_FRONTEND=noninteractive

ENV PROTOC_VERSION=24.4
ENV PROTOC_ZIP=protoc-$PROTOC_VERSION-linux-x86_64.zip
RUN wget -qO $PROTOC_ZIP https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/$PROTOC_ZIP && unzip -o $PROTOC_ZIP -d /usr/local bin/protoc && unzip -o $PROTOC_ZIP -d /usr/local 'include/*' && rm -f $PROTOC_ZIP

RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
RUN echo "echo \"This is submerged execution sandbox! Run \\\"cargo run --bin standard\\\" to run submerged!\"" > ~/.bashrc

COPY vessels ./vessels
COPY viridian/submerged/Cargo.toml ./viridian/submerged/Cargo.toml
COPY viridian/submerged/build.rs ./viridian/submerged/build.rs

WORKDIR /seaside/viridian/submerged
RUN mkdir -p src/bindings && echo "fn main() {}" > src/bindings/standard.rs && cargo build
VOLUME /seaside/viridian/submerged/src

ENTRYPOINT ["/bin/bash"]
