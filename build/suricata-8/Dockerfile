# Suricata for DSM. SURICATA_VERSION from repo VERSION via --build-arg.
# GitHub Actions compiles natively (no Docker). This image is for local
# cross-build (e.g. Apple Silicon → x86_64). TARGETPLATFORM comes from buildx.

ARG SURICATA_VERSION=8.0.6
ARG PREFIX=/opt/tps-suricata
ARG TARGETPLATFORM=linux/amd64

FROM --platform=$TARGETPLATFORM debian:12 AS build
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
        patchelf \
        wget ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal

WORKDIR /src
RUN wget -q "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz" \
    && tar -xzf "suricata-${SURICATA_VERSION}.tar.gz"

WORKDIR /src/suricata-${SURICATA_VERSION}
# Echo distro so this layer cannot reuse an Ubuntu 24.04 (glibc 2.39) cache.
RUN cat /etc/os-release && ./configure \
        --prefix="${PREFIX}" \
        --sysconfdir="${PREFIX}/etc" \
        --localstatedir="${PREFIX}/var" \
        --enable-nfqueue \
        --disable-gccmarch-native \
    && make -j"$(nproc)" \
    && make install

# Vendor non-glibc shared libs so DSM does not need Ubuntu/Debian packages.
# Keep libc, libm, libgcc_s, libstdc++ from the NAS (glibc 2.36 / libstdc++ 6.0.31).
COPY collect-libs.sh /tmp/collect-libs.sh
RUN chmod +x /tmp/collect-libs.sh && /tmp/collect-libs.sh "${PREFIX}"

RUN "${PREFIX}/bin/suricata" -V \
    && (ldd "${PREFIX}/bin/suricata" || true) | tee "${PREFIX}/ldd.txt" \
    && "${PREFIX}/bin/suricata" --build-info | tee "${PREFIX}/build-info.txt" \
    && echo "=== vendored libs ===" | tee -a "${PREFIX}/ldd.txt" \
    && ls -l "${PREFIX}/lib" | tee -a "${PREFIX}/ldd.txt"

FROM scratch AS export
COPY --from=build /opt/tps-suricata /tps-suricata
