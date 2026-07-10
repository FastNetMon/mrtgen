FROM rust:1-slim-trixie

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_HTTP_PROXY=

RUN if [ -n "$APT_HTTP_PROXY" ]; then \
        printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "DIRECT";\n' "$APT_HTTP_PROXY" > /etc/apt/apt.conf.d/01proxy; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates pkg-config libssl-dev jq \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install bgpkit-parser --features cli

COPY tests/parsers/runners/bgpkit_parser_check.sh /usr/local/bin/bgpkit_parser_check
COPY tests/parsers/parser-baseline.json /usr/local/share/mrtgen/parser-baseline.json
RUN chmod +x /usr/local/bin/bgpkit_parser_check

ENTRYPOINT ["/usr/local/bin/bgpkit_parser_check"]
