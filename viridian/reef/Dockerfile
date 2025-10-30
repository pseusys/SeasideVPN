# syntax=docker/dockerfile:1

FROM ubuntu:22.04 AS downloader

WORKDIR /seaside

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential wget ca-certificates && rm -rf /var/lib/apt/lists/*
RUN wget -qO- https://sh.rustup.rs | sh -s -- --default-toolchain 1.86.0 -y
ENV PATH="/root/.cargo/bin:${PATH}"

COPY vessels vessels
COPY viridian/reef/Cargo.toml viridian/reef/
COPY viridian/reef/cli_executable/Cargo.toml viridian/reef/cli_executable/
COPY viridian/reef/rust_library/Cargo.toml viridian/reef/rust_library/
COPY viridian/reef/shared_library/Cargo.toml viridian/reef/shared_library/
COPY viridian/reef/test_library/Cargo.toml viridian/reef/test_library/
RUN cargo build --manifest-path viridian/reef/Cargo.toml --bin cli --lib || true

COPY viridian/reef/cli_executable/ viridian/reef/cli_executable/
COPY viridian/reef/rust_library/ viridian/reef/rust_library/
COPY viridian/reef/shared_library/ viridian/reef/shared_library/
COPY viridian/reef/test_library/ viridian/reef/test_library/


FROM downloader AS builder

RUN cargo build --manifest-path viridian/reef/Cargo.toml --bin cli --lib


FROM downloader AS tester

ENV RUST_BACKTRACE=full
RUN apt-get update && apt-get install -y --no-install-recommends net-tools uml-utilities iptables iproute2 && rm -rf /var/lib/apt/lists/*

WORKDIR /seaside/viridian/reef


FROM ubuntu:22.04 AS default

WORKDIR /seaside/viridian

ARG NETWORK_GATEWAY
ENV ARG_NETWORK_GATEWAY="$NETWORK_GATEWAY"

ENV RUST_BACKTRACE=full
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends iptables iproute2 python3-pip && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir pytest pytest-timeout
COPY viridian/algae/tests/conftest.py viridian/algae/tests/test_local.py tests/
COPY --from=builder /seaside/viridian/reef/target/debug/cli cli

VOLUME /seaside/viridian

ENV SEASIDE_PAYLOAD_VIRIDIAN=
ENV SEASIDE_ADDRESS=
ENV SEASIDE_API_PORT=

ENV TEST_COMMAND="pytest --log-cli-level=INFO tests/test_local.py"
ENV RUN_COMMAND="./cli -a \$SEASIDE_ADDRESS -c \$SEASIDE_API_PORT -k ... -t ... -p \$SEASIDE_PAYLOAD_VIRIDIAN -e \"\$TEST_COMMAND\""
ENTRYPOINT ["sh", "-c", "ip route replace default via \"$ARG_NETWORK_GATEWAY\" && eval \"$RUN_COMMAND\""]

HEALTHCHECK --interval=1m --timeout=1s --retries=3 --start-period=10s --start-interval=3s CMD ls /sys/class/net | grep tun0
