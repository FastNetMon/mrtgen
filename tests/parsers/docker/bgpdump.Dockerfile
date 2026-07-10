FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_HTTP_PROXY=

RUN if [ -n "$APT_HTTP_PROXY" ]; then \
        printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "DIRECT";\n' "$APT_HTTP_PROXY" > /etc/apt/apt.conf.d/01proxy; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends bgpdump ca-certificates coreutils jq \
    && rm -rf /var/lib/apt/lists/*

COPY tests/parsers/runners/bgpdump_check.sh /usr/local/bin/bgpdump_check
COPY tests/parsers/parser-baseline.json /usr/local/share/mrtgen/parser-baseline.json
RUN chmod +x /usr/local/bin/bgpdump_check

ENTRYPOINT ["/usr/local/bin/bgpdump_check"]
