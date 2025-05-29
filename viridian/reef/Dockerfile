# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS downloader

WORKDIR /seaside

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential wget ca-certificates && rm -rf /var/lib/apt/lists/*
RUN wget -qO- https://sh.rustup.rs | sh -s -- --default-toolchain 1.86.0 -y
ENV PATH="/root/.cargo/bin:${PATH}"

COPY vessels vessels
COPY viridian/reef/Cargo.toml viridian/reef/Cargo.toml
RUN cargo build --manifest-path viridian/reef/Cargo.toml --all-features --bin cli || true

COPY viridian/reef/src viridian/reef/src


FROM downloader AS builder

RUN cargo build --features cli-exec --bin cli --manifest-path viridian/reef/Cargo.toml


FROM downloader AS tester

ENV RUST_BACKTRACE=1
RUN apt-get update && apt-get install -y --no-install-recommends net-tools uml-utilities iptables iproute2 && rm -rf /var/lib/apt/lists/*

COPY viridian/reef/tests viridian/reef/tests
WORKDIR /seaside/viridian/reef


FROM ubuntu:22.04 AS default

WORKDIR /seaside/viridian

ARG NETWORK_GATEWAY
ENV ARG_NETWORK_GATEWAY="$NETWORK_GATEWAY"

ENV RUST_BACKTRACE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 python3-pip && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir pytest pytest-timeout
COPY viridian/algae/tests/conftest.py viridian/algae/tests/test_local.py tests/
COPY --from=builder /seaside/viridian/reef/target/debug/cli cli

VOLUME /seaside/viridian/ca

ENV SEASIDE_PAYLOAD_VIRIDIAN=
ENV SEASIDE_ADDRESS=
ENV SEASIDE_CTRLPORT=

ENV TEST_COMMAND="pytest --log-cli-level=INFO tests/test_local.py"
ENV RUN_COMMAND="./cli -a \$SEASIDE_ADDRESS -c \$SEASIDE_CTRLPORT -k ... -t ... -p \$SEASIDE_PAYLOAD_VIRIDIAN -e \"\$TEST_COMMAND\""
ENTRYPOINT ["sh", "-c", "ip route replace default via \"$ARG_NETWORK_GATEWAY\" && eval \"$RUN_COMMAND\""]

HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s CMD ls /sys/class/net | grep tun0
