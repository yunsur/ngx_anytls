ARG DEBIAN_VERSION=12

FROM debian:${DEBIAN_VERSION} AS builder

ARG TARGETARCH
ARG NGINX_VERSION=1.30.3
ARG MODULE_VERSION=1.0.0

WORKDIR /usr/local/src/

COPY . /usr/local/src/ngx_anytls

RUN set -xe \
    && apt-get update -y \
    && apt-get --no-install-recommends --no-install-suggests -y install \
        build-essential ca-certificates git wget lsb-release \
        libpcre2-dev libpcre3-dev zlib1g-dev libssl-dev libxml2-utils \
        xsltproc mercurial devscripts fakeroot debhelper dpkg-dev quilt \
        libparse-recdescent-perl libjemalloc-dev \
    && rm -rf /var/lib/apt/lists/*

RUN set -xe \
    && wget https://github.com/nginx/pkg-oss/archive/refs/tags/${NGINX_VERSION}-1.tar.gz -O pkg-oss.tar.gz \
    && tar -xzf pkg-oss.tar.gz \
    && mv pkg-oss-${NGINX_VERSION}-1 pkg-oss \
    && rm pkg-oss.tar.gz

RUN set -xe \
    && case "${TARGETARCH}" in \
        amd64) \
            ANYTLS_CFLAGS='-O2 -march=x86-64 -mtune=generic'; \
            ;; \
        arm64) \
            ANYTLS_CFLAGS='-O2 -march=armv8-a'; \
            ;; \
        *) \
            echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; \
            exit 1; \
            ;; \
    esac \
    && export CFLAGS="${ANYTLS_CFLAGS}" CXXFLAGS="${ANYTLS_CFLAGS}" \
    && /usr/local/src/pkg-oss/build_module.sh \
         -s \
         -v ${NGINX_VERSION} \
         -V ${MODULE_VERSION} \
         -n anytls \
         /usr/local/src/ngx_anytls

FROM scratch

COPY --from=builder /usr/local/src/build-module-artifacts/ /
