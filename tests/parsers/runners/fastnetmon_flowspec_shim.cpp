// Cross-validation shim: feed one BGP FlowSpec NLRI *value* (hex on argv[1],
// without the RFC 8955 length octet(s)) to FastNetMon's decoder and print the
// decoded rule as JSON on stdout.
//
// Compiled inside tests/parsers/docker/fastnetmon.Dockerfile against a pinned
// FastNetMon checkout; see fastnetmon_flowspec_check.py for the driver that
// compares the output with mrtgen's manifest.
//
// Output (single line):
//   {"decoded": true, "flow": {...encode_flow_spec_to_json...}}
//   {"decoded": false}
// Exit code: 0 decoded, 1 decoder refused, 2 usage/input error.
// FastNetMon's own diagnostics (log4cpp WARN lines) go to stderr.

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <log4cpp/Category.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/Priority.hh>

#include "bgp_protocol_flow_spec.hpp"

// FastNetMon sources link against a logger owned by the main daemon.
log4cpp::Category& logger = log4cpp::Category::getRoot();

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <nlri-value-hex>" << std::endl;
        return 2;
    }

    std::string hex = argv[1];
    if (hex.size() % 2 != 0) {
        std::cerr << "error: odd-length hex string" << std::endl;
        return 2;
    }

    std::vector<uint8_t> nlri;
    nlri.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            std::cerr << "error: invalid hex at offset " << i << std::endl;
            return 2;
        }
        nlri.push_back(static_cast<uint8_t>(hi << 4 | lo));
    }

    log4cpp::PatternLayout* layout = new log4cpp::PatternLayout();
    layout->setConversionPattern("fastnetmon %p: %m%n");
    log4cpp::OstreamAppender* appender = new log4cpp::OstreamAppender("stderr", &std::cerr);
    appender->setLayout(layout);
    logger.addAppender(appender);
    logger.setPriority(log4cpp::Priority::DEBUG);

    flow_spec_rule_t rule;
    bool decoded = flow_spec_decode_nlri_value(nlri.data(), static_cast<uint32_t>(nlri.size()), rule);

    if (!decoded) {
        std::cout << "{\"decoded\": false}" << std::endl;
        return 1;
    }

    std::string flow_json;
    if (!encode_flow_spec_to_json(rule, flow_json, false)) {
        std::cerr << "error: decode succeeded but JSON serialization failed" << std::endl;
        return 2;
    }

    std::cout << "{\"decoded\": true, \"flow\": " << flow_json << "}" << std::endl;
    return 0;
}
