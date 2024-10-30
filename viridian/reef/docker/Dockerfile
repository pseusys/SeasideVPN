# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS downloader

WORKDIR /seaside

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential wget unzip ca-certificates && rm -rf /var/lib/apt/lists/*
RUN wget -qO- https://sh.rustup.rs | sh -s -- --default-toolchain 1.81.0 -y
ENV PATH="/root/.cargo/bin:${PATH}"

ENV PROTOC_VERSION=24.4
ENV PROTOC_ZIP=protoc-$PROTOC_VERSION-linux-x86_64.zip
RUN wget -qO "$PROTOC_ZIP" https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/$PROTOC_ZIP && unzip -o "$PROTOC_ZIP" -d /usr/local bin/protoc && unzip -o "$PROTOC_ZIP" -d /usr/local 'include/*' && rm -f "$PROTOC_ZIP"

COPY vessels vessels
COPY viridian/reef/Cargo.toml viridian/reef/Cargo.toml
COPY viridian/reef/build.rs viridian/reef/build.rs
COPY viridian/reef/src viridian/reef/src


FROM downloader AS builder

RUN cargo build --features cli-exec --bin cli --manifest-path viridian/reef/Cargo.toml


FROM downloader AS test

RUN apt-get update && apt-get install -y --no-install-recommends net-tools uml-utilities iproute2 && rm -rf /var/lib/apt/lists/*

COPY viridian/reef/tests viridian/reef/tests
WORKDIR /seaside/viridian/reef


FROM ubuntu:22.04 AS integration

WORKDIR /seaside/viridian

ARG NETWORK_GATEWAY
ENV ARG_NETWORK_GATEWAY="$NETWORK_GATEWAY"

ENV RUST_BACKTRACE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 python3-pip && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir pytest pytest-timeout
COPY viridian/algae/tests/conftest.py viridian/algae/tests/test_local.py tests/
COPY --from=builder /seaside/viridian/reef/target/debug/cli CLI_executable

VOLUME /seaside/viridian/ca

ENV SEASIDE_PAYLOAD_VIRIDIAN=
ENV SEASIDE_ADDRESS=
ENV SEASIDE_CTRLPORT=

ENV TEST_COMMAND="pytest --log-cli-level=INFO tests/test_local.py"
ENTRYPOINT ip route replace default via "$ARG_NETWORK_GATEWAY" && \
    ./CLI_executable -a "$SEASIDE_ADDRESS" -c "$SEASIDE_CTRLPORT" -p "$SEASIDE_PAYLOAD_VIRIDIAN" -e "$TEST_COMMAND"

HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s CMD ls /sys/class/net | grep tun0
