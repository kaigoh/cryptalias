#pragma once

#include <string>

// Minimal Cryptalias HTTP resolver (no JWS verification).
// Dependencies: libcurl, nlohmann/json

namespace cryptalias {
std::string resolve_address(const std::string& ticker, const std::string& alias);
std::string verify_jws_payload(const std::string& jws, const std::string& jwk_json);
}
