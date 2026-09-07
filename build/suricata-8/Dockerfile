# syntax=docker/dockerfile:1
# Suricata 8.0.6 for linux/amd64 (DSM x86_64 engine).
# Capture: AF_PACKET + NFQUEUE. Alerts: eve-log. No Synology synodb.

ARG SURICATA_VERSION=8.0.6
ARG PREFIX=/opt/tps-suricata

FROM --platform=linux/amd64 ubuntu:24.04 AS build
ARG SURICATA_VERSION
ARG PREFIX
ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/opt/cargo
ENV RUSTUP_HOME=/opt/rustup
ENV PATH="/opt/cargo/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libtool pkg-config \
        python3 python3-yaml python3-setuptools \
        libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev \
        zlib1g-dev libpcre2-dev libjansson-dev libmagic-dev \
        libcap-ng-dev liblz4-dev liblzma-dev \
        libnetfilter-queue-dev libnfnetlink-dev libmnl-dev \
        libnss3-dev libnspr4-dev \
        libhyperscan-dev \
        wget ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Suricata 8 needs a current Rust; distro rustc is often too old.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal

WORKDIR /src
RUN wget -q "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz" \
    && tar -xzf "suricata-${SURICATA_VERSION}.tar.gz"

WORKDIR /src/suricata-${SURICATA_VERSION}
# Bundled libhtp is in the tarball; Rust vendor dir is included in official releases.
RUN ./configure \
        --prefix="${PREFIX}" \
        --sysconfdir="${PREFIX}/etc" \
        --localstatedir="${PREFIX}/var" \
        --enable-nfqueue \
        --disable-gccmarch-native \
    && make -j"$(nproc)" \
    && make install

# Record runtime linkage and version for the DSM wrap step.
RUN "${PREFIX}/bin/suricata" -V \
    && (ldd "${PREFIX}/bin/suricata" || true) | tee "${PREFIX}/ldd.txt" \
    && "${PREFIX}/bin/suricata" --build-info | tee "${PREFIX}/build-info.txt"

FROM scratch AS export
COPY --from=build /opt/tps-suricata /tps-suricata
