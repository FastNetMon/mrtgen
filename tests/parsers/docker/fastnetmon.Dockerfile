FROM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive
ARG APT_HTTP_PROXY=

RUN if [ -n "$APT_HTTP_PROXY" ]; then \
        printf 'Acquire::http::Proxy "%s";\nAcquire::https::Proxy "DIRECT";\n' "$APT_HTTP_PROXY" > /etc/apt/apt.conf.d/01proxy; \
    fi \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git g++ python3 \
        liblog4cpp5-dev libboost-dev libboost-thread-dev libboost-serialization-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# The known-gap model in fastnetmon_flowspec_check.py was written against this
# exact revision of bgp_protocol_flow_spec.cpp (byte-identical to master as of
# 2026-07). Bump deliberately: a newer decoder may turn KNOWN-FAIL cases into
# UNEXPECTED-PASS, which is the signal to update the model.
ARG FASTNETMON_COMMIT=09bab48c84fbb6b8accec0170ca752e4e32b728e

RUN git init -q /opt/fastnetmon \
    && git -C /opt/fastnetmon fetch -q --depth 1 https://github.com/pavel-odintsov/fastnetmon.git "$FASTNETMON_COMMIT" \
    && git -C /opt/fastnetmon checkout -q FETCH_HEAD

# Compile FastNetMon's FlowSpec decoder plus the few translation units it
# links against (no CMake: the daemon build drags in gRPC/gobgp/capture
# plugins that the decoder itself never touches). -w: the pinned sources
# use C++20 bit-field initializers and are not warning-clean.
COPY tests/parsers/runners/fastnetmon_flowspec_shim.cpp /opt/
RUN g++ -O1 -std=c++20 -w -I/opt/fastnetmon/src \
        /opt/fastnetmon_flowspec_shim.cpp \
        /opt/fastnetmon/src/bgp_protocol_flow_spec.cpp \
        /opt/fastnetmon/src/bgp_protocol.cpp \
        /opt/fastnetmon/src/fast_library.cpp \
        /opt/fastnetmon/src/iana_ip_protocols.cpp \
        /opt/fastnetmon/src/libpatricia/patricia.cpp \
        -llog4cpp -lboost_thread -lboost_system -lssl -lcrypto -lpthread \
        -o /usr/local/bin/fastnetmon_flowspec_shim

COPY tests/parsers/runners/fastnetmon_flowspec_check.py /usr/local/bin/fastnetmon_flowspec_check
RUN chmod +x /usr/local/bin/fastnetmon_flowspec_check

ENTRYPOINT ["/usr/local/bin/fastnetmon_flowspec_check"]
