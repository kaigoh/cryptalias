#include "cryptalias_client.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <cctype>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
size_t write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
  size_t total = size * nmemb;
  auto* buffer = static_cast<std::string*>(userp);
  buffer->append(static_cast<char*>(contents), total);
  return total;
}

std::string http_get(const std::string& url, const std::string& accept) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    throw std::runtime_error("failed to init curl");
  }

  std::string response;
  struct curl_slist* headers = nullptr;
  std::string accept_header = "Accept: " + accept;
  headers = curl_slist_append(headers, accept_header.c_str());

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

  CURLcode res = curl_easy_perform(curl);
  long code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res != CURLE_OK) {
    throw std::runtime_error(curl_easy_strerror(res));
  }
  if (code < 200 || code >= 300) {
    throw std::runtime_error("request failed " + std::to_string(code) + ": " + response);
  }
  return response;
}

std::string parse_domain(const std::string& alias) {
  auto pos = alias.rfind('$');
  if (pos == std::string::npos || pos == alias.size() - 1) {
    throw std::runtime_error("alias must be in the format [ticker:]alias$domain");
  }
  return alias.substr(pos + 1);
}

std::string normalize_ticker(const std::string& value) {
  std::string out;
  out.reserve(value.size());
  for (unsigned char c : value) {
    if (!std::isspace(c)) {
      out.push_back(static_cast<char>(std::tolower(c)));
    }
  }
  return out;
}

std::string parse_ticker_prefix(const std::string& alias) {
  auto pos = alias.rfind('$');
  if (pos == std::string::npos || pos == alias.size() - 1) {
    throw std::runtime_error("alias must be in the format [ticker:]alias$domain");
  }
  const std::string left = alias.substr(0, pos);
  auto colon = left.find(':');
  if (colon == std::string::npos) {
    return "";
  }
  if (colon == 0 || colon == left.size() - 1 || left.find(':', colon + 1) != std::string::npos) {
    throw std::runtime_error("invalid format (expected [ticker:]alias[+tag]$domain)");
  }
  return normalize_ticker(left.substr(0, colon));
}

std::string url_encode(const std::string& value) {
  static const char hex[] = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 0x0F]);
    }
  }
  return out;
}

std::vector<unsigned char> base64url_decode(const std::string& input) {
  std::string b64 = input;
  for (char& c : b64) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (b64.size() % 4 != 0) {
    b64.push_back('=');
  }

  static const int kDecTable[256] = {
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
      52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
      -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
      15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
      -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
      41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
      -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };

  std::vector<unsigned char> out;
  int val = 0, valb = -8;
  for (unsigned char c : b64) {
    int d = kDecTable[c];
    if (d == -1) continue;
    if (d == -2) break;
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      out.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return out;
}

void enforce_expires(const std::string& value) {
  if (value.empty()) {
    throw std::runtime_error("missing expires in JWS payload");
  }
  std::tm tm = {};
  std::istringstream ss(value);
  ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  if (ss.fail()) {
    throw std::runtime_error("invalid expires in JWS payload");
  }
  time_t exp = timegm(&tm);
  if (exp <= time(nullptr)) {
    throw std::runtime_error("resolved address has expired");
  }
}

} // namespace

namespace cryptalias {
std::string resolve_address(const std::string& ticker, const std::string& alias) {
  if (ticker.empty() || alias.empty()) {
    throw std::runtime_error("ticker and alias are required");
  }

  const std::string ticker_clean = normalize_ticker(ticker);
  const std::string prefix = parse_ticker_prefix(alias);
  if (!prefix.empty() && prefix != ticker_clean) {
    throw std::runtime_error("ticker prefix \"" + prefix + "\" does not match \"" + ticker_clean + "\"");
  }
  const std::string domain = parse_domain(alias);
  const std::string cfg_url = "https://" + domain + "/.well-known/cryptalias/configuration";

  const std::string cfg_body = http_get(cfg_url, "application/json");
  auto cfg = nlohmann::json::parse(cfg_body);

  std::string resolver = cfg["resolver"]["resolver_endpoint"].get<std::string>();
  while (!resolver.empty() && resolver.back() == '/') {
    resolver.pop_back();
  }
  if (resolver.empty()) {
    throw std::runtime_error("missing resolver_endpoint in configuration");
  }
  if (!cfg.contains("key")) {
    throw std::runtime_error("missing key in configuration");
  }

  const std::string resolve_url = resolver + "/_cryptalias/resolve/" + url_encode(ticker_clean) + "/" + url_encode(alias);
  const std::string jws = http_get(resolve_url, "application/jose");
  const std::string payload_json = verify_jws_payload(jws, cfg["key"].dump());
  auto payload = nlohmann::json::parse(payload_json);

  if (!payload.contains("address") || payload["address"].get<std::string>().empty()) {
    throw std::runtime_error("missing address in JWS payload");
  }
  if (!payload.contains("expires") || payload["expires"].get<std::string>().empty()) {
    throw std::runtime_error("missing expires in JWS payload");
  }
  enforce_expires(payload["expires"].get<std::string>());
  return payload["address"].get<std::string>();
}

std::string verify_jws_payload(const std::string& jws, const std::string& jwk_json) {
  auto jwk = nlohmann::json::parse(jwk_json);
  if (!jwk.contains("x")) {
    throw std::runtime_error("missing jwk x");
  }
  auto parts_pos1 = jws.find('.');
  auto parts_pos2 = jws.find('.', parts_pos1 + 1);
  if (parts_pos1 == std::string::npos || parts_pos2 == std::string::npos) {
    throw std::runtime_error("invalid JWS format");
  }

  std::string header_b64 = jws.substr(0, parts_pos1);
  std::string payload_b64 = jws.substr(parts_pos1 + 1, parts_pos2 - parts_pos1 - 1);
  std::string sig_b64 = jws.substr(parts_pos2 + 1);
  std::string signing_input = header_b64 + "." + payload_b64;

  auto pub_bytes = base64url_decode(jwk["x"].get<std::string>());
  auto sig_bytes = base64url_decode(sig_b64);

  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub_bytes.data(), pub_bytes.size());
  if (!pkey) {
    throw std::runtime_error("failed to create public key");
  }

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("failed to create md ctx");
  }

  int ok = EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey);
  if (ok != 1) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("verify init failed");
  }
  ok = EVP_DigestVerify(ctx, sig_bytes.data(), sig_bytes.size(),
                        reinterpret_cast<const unsigned char*>(signing_input.data()), signing_input.size());
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);

  if (ok != 1) {
    throw std::runtime_error("signature verification failed");
  }

  auto decoded = base64url_decode(payload_b64);
  return std::string(decoded.begin(), decoded.end());
}

} // namespace cryptalias
